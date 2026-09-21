"""Deterministic command parsing for the single conversational analyst."""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Any

from app.soc_assistant.catalog import COMMAND_BY_SLASH
from app.soc_assistant.schemas import AssistantCommandName, AssistantIntent


OPTION_NAMES = {
    "--hours": "hours",
    "--min-level": "min_level",
    "--limit": "limit",
    "--agent": "agent_id",
    "--type": "indicator_type",
    "--since": "since",
    "--severity": "severity",
}
INTEGER_OPTIONS = {"hours", "min_level", "limit"}
FLAG_OPTIONS = {
    "--new": "new_only",
    "--open": "open_only",
    "--all": "all_results",
}

INVALID_ALERT_REFERENCES = {
    "alert",
    "alerts",
    "it",
    "this",
    "that",
    "these",
    "those",
    "investigation",
}

# Bare, targetless imperatives ("analyze them", "check these", "what do you
# think", a lone "investigate") name nothing concrete to filter on. Routing
# these into the tool-calling chat agent invites it to chain several broad
# searches (each a real LLM call) before finding anything to say. Short-
# circuit to one deterministic, zero-LLM alert summary instead and let the
# user name a specific alert/agent/IP/time range for anything deeper.
VAGUE_NO_TARGET_PATTERN = re.compile(
    r"(?:analyze|analyse|check|review|look at|look into)\s+"
    r"(?:them|these|those|it)"
    r"|investigate"
    r"|what do you think"
    r"|any\s*(?:thing)?\s*suspicious"
)

# "new", "recent" and "changed" are three different questions that used to
# collapse into one broad alert listing. They are separated here so the
# executor can answer each against the right reference point: a recent time
# window, the user's previous successful check, or a state comparison.
CHANGE_SUBJECT_PATTERNS = (
    ("findings", re.compile(r"\bfindings?\b")),
    ("analysis", re.compile(r"\banalys[ei]s\b|\banalyses\b")),
    ("alerts", re.compile(r"\balerts?\b")),
)
NEW_PATTERN = re.compile(
    r"\bnew\b|\bsince (?:my |the |our |we )?last\b|\bsince i last\b"
)
CHANGED_PATTERN = re.compile(
    r"\b(?:changed|changes|different|updated|updates)\b"
)
RECENT_PATTERN = re.compile(r"\b(?:recent|latest|newest|current)\b")
# An explicit instruction to show rows, as opposed to a question about what
# moved. Anything else about alerts is a question for the analyst model.
LIST_PATTERN = re.compile(r"^(?:show|list|display|give me|get)\b")


class AssistantIntentRouter:
    def __init__(self, llm: Any | None = None) -> None:
        # Kept as an ignored compatibility argument for callers from before
        # the single-analyst refactor. Free-form language no longer incurs a
        # second model call merely to classify intent.
        self.llm = llm

    @staticmethod
    def _arguments(tokens: list[str]) -> tuple[list[str], dict[str, Any]]:
        positional: list[str] = []
        options: dict[str, Any] = {}
        index = 0
        while index < len(tokens):
            token = tokens[index]
            flag = FLAG_OPTIONS.get(token)
            if flag is not None:
                options[flag] = True
                index += 1
                continue
            key = OPTION_NAMES.get(token)
            if key is None:
                if token.startswith("--"):
                    raise ValueError(f"Unsupported option: {token}")
                positional.append(token)
                index += 1
                continue
            if index + 1 >= len(tokens):
                raise ValueError(f"{token} requires a value.")
            value: Any = tokens[index + 1]
            if key in INTEGER_OPTIONS:
                try:
                    value = int(value)
                except ValueError as exc:
                    raise ValueError(f"{token} requires an integer.") from exc
            options[key] = value
            index += 2
        return positional, options

    def parse_slash(self, message: str) -> AssistantIntent:
        try:
            tokens = shlex.split(message)
        except ValueError as exc:
            raise ValueError("The slash command contains an unclosed quote.") from exc
        if not tokens:
            return AssistantIntent(command=AssistantCommandName.HELP)
        command = COMMAND_BY_SLASH.get(tokens[0].lower())
        if command is None:
            raise ValueError(f"Unknown command: {tokens[0]}")
        positional, options = self._arguments(tokens[1:])
        if command.name == AssistantCommandName.ALERTS:
            if positional:
                options["text"] = " ".join(positional)
        elif command.name == AssistantCommandName.HUNT:
            if not positional:
                raise ValueError("/hunt requires an indicator.")
            options["indicator"] = positional[0]
        elif command.name == AssistantCommandName.INVESTIGATE:
            if not positional:
                raise ValueError("/investigate requires a Wazuh alert ID.")
            options["alert_id"] = positional[0]
        elif command.name in {
            AssistantCommandName.STATUS,
            AssistantCommandName.PLAN,
            AssistantCommandName.COLLECT,
            AssistantCommandName.CONTINUE,
        }:
            if not positional:
                raise ValueError(
                    f"{command.slash} requires an investigation ID."
                )
            options["investigation_id"] = positional[0]
        elif command.name == AssistantCommandName.CHAT:
            if not positional:
                raise ValueError("/ask requires a question.")
            options["question"] = " ".join(positional)
        elif positional:
            raise ValueError(f"{command.slash} does not accept positional arguments.")
        return AssistantIntent(command=command.name, arguments=options)

    @staticmethod
    def _alert_id(message: str) -> str | None:
        patterns = (
            # IDs commonly include the word "alert" as part of the token.
            r"\b(alert[-_][A-Za-z0-9][A-Za-z0-9_.-]{1,250})\b",
            # Explicit references: "alert 12345", "alert id ALERT-99".
            r"\balert(?:\s+id)?\s*(?:[:#]\s*)?([A-Za-z0-9][A-Za-z0-9_.-]{2,255})\b",
            # Compact formal forms such as "mapek 12345".
            r"\b(?:investigate|mapek)\s*[:#]?\s+([A-Za-z0-9][A-Za-z0-9_.-]{2,255})\b",
        )
        for pattern in patterns:
            match = re.search(pattern, message, re.I)
            if match and match.group(1).lower() not in INVALID_ALERT_REFERENCES:
                return match.group(1)
        return None

    @staticmethod
    def _alert_filters(message: str) -> dict[str, Any]:
        lower = message.lower()
        arguments: dict[str, Any] = {}
        duration = re.search(
            r"\blast\s+(?:(\d+)\s+)?(hour|hours|day|days)\b",
            lower,
        )
        if duration:
            quantity = int(duration.group(1) or 1)
            arguments["hours"] = quantity * (
                24 if duration.group(2).startswith("day") else 1
            )
        elif "overnight" in lower:
            arguments["hours"] = 12
        elif "today" in lower:
            arguments["hours"] = 24

        if "critical" in lower:
            arguments["severity"] = "critical"
        elif "high severity" in lower or "high-severity" in lower:
            arguments["severity"] = "high"

        agent = re.search(r"\bagent(?:\s+id)?\s*[:#]?\s*([A-Za-z0-9_.-]+)", message, re.I)
        if agent:
            arguments["agent_id"] = agent.group(1)
        return arguments

    @staticmethod
    def _change_query(lower: str, *, has_window: bool = False) -> dict[str, Any] | None:
        """Classify "what is new / recent / changed" questions.

        Returns None for everything else, so an ordinary alert question
        ("which IP is behind most of these?") reaches the analyst model
        instead of being answered with a structured listing.
        """

        subject = next(
            (
                name
                for name, pattern in CHANGE_SUBJECT_PATTERNS
                if pattern.search(lower)
            ),
            None,
        )
        asks_changed = bool(CHANGED_PATTERN.search(lower))
        asks_new = bool(NEW_PATTERN.search(lower))
        if subject is None:
            # "what changed?" / "anything new?" names no subject but still has
            # a well-defined answer: everything the cursor tracks.
            if asks_changed or (asks_new and re.search(r"\bany\b", lower)):
                return {
                    "change_subject": "all",
                    "change_mode": "changed" if asks_changed else "new",
                }
            return None
        if asks_new:
            return {"change_subject": subject, "change_mode": "new"}
        if asks_changed:
            return {"change_subject": subject, "change_mode": "changed"}
        # A plain "recent"/window/listing question used to be answered here
        # too, with a canned count that ignored any severity/agent filter in
        # the phrasing ("show me critical alerts" -> "there are 601 alerts").
        # "new" and "changed" still need this deterministic path - they name
        # a session cursor the model has no access to - but "recent" is an
        # ordinary time-windowed question the analyst model's own tools
        # (search_alerts/aggregate_alerts) can answer directly, filters and
        # all, so it no longer short-circuits here.
        return None

    @staticmethod
    def _indicator(message: str) -> tuple[str | None, str]:
        for token in re.findall(r"[A-Za-z0-9_./:@-]{2,256}", message):
            try:
                ipaddress.ip_address(token.strip("[],:"))
                return token.strip("[],:"), "ip"
            except ValueError:
                pass
            if re.fullmatch(r"[A-Fa-f0-9]{32,64}", token):
                return token, "hash"
            if "." in token and not token.lower().endswith((".log", ".txt")):
                return token, "domain"
        match = re.search(r"(?:hunt|search|find)(?:\s+(?:for|ioc))?\s+['\"]?([^\s'\"]+)", message, re.I)
        return (match.group(1), "other") if match else (None, "other")

    def deterministic(self, message: str) -> AssistantIntent | None:
        lower = message.lower()
        stripped = re.sub(r"[^\w\s]", "", lower).strip()
        normalized = re.sub(r"\bmape-?k\b", "mapek", lower)
        if VAGUE_NO_TARGET_PATTERN.fullmatch(stripped):
            return AssistantIntent(
                command=AssistantCommandName.SUMMARY,
                arguments={"vague_fallback": True},
            )
        investigation = re.search(r"\bINV-[A-Za-z0-9-]+\b", message, re.I)
        alert_id = self._alert_id(message)
        if stripped in {
            "hi",
            "hello",
            "hey",
            "yo",
            "good morning",
            "good afternoon",
            "good evening",
        }:
            return AssistantIntent(command=AssistantCommandName.CHAT)
        if investigation and re.search(
            r"\b(collect|gather|fetch)\b.*\b(evidence|telemetry|data)\b",
            lower,
        ):
            return AssistantIntent(
                command=AssistantCommandName.COLLECT,
                arguments={"investigation_id": investigation.group(0).upper()},
            )
        if investigation and re.search(r"\b(continue|resume)\b", lower):
            return AssistantIntent(
                command=AssistantCommandName.CONTINUE,
                arguments={"investigation_id": investigation.group(0).upper()},
            )
        if investigation and re.search(r"\b(plan|remediation)\b", lower):
            return AssistantIntent(
                command=AssistantCommandName.PLAN,
                arguments={"investigation_id": investigation.group(0).upper()},
            )
        if investigation and any(word in lower for word in ("status", "check", "show")):
            return AssistantIntent(
                command=AssistantCommandName.STATUS,
                arguments={"investigation_id": investigation.group(0).upper()},
            )
        if "investigation id" in lower and any(
            phrase in lower
            for phrase in ("this alert", "that alert", "previous alert")
        ):
            return AssistantIntent(command=AssistantCommandName.STATUS)
        if any(
            phrase in normalized
            for phrase in (
                "full mapek",
                "whole mapk",
                "whole mapek",
                "start formal investigation",
                "start response workflow",
                "run controlled response",
            )
        ):
            return AssistantIntent(
                command=AssistantCommandName.INVESTIGATE,
                arguments={"alert_id": alert_id} if alert_id else {},
            )
        if re.search(r"\b(isolate|contain|block|remediate)\b", lower):
            return AssistantIntent(
                command=AssistantCommandName.CHAT,
                arguments={"question": message},
            )
        if "investigate" in lower or re.search(
            r"\b(analyze|analyse|explain|review|correlate)\b", lower
        ):
            # Casual phrasing ("could u investigate him 1.2.3.4") that isn't
            # a formal /investigate <alert_id> request. The formal workflow
            # needs a specific Wazuh alert ID; anything looser is a search
            # and correlation question the chat tool agent can actually
            # answer (it can look up the indicator, related alerts, and
            # endpoint context on its own).
            return AssistantIntent(
                command=AssistantCommandName.CHAT,
                arguments={"question": message},
            )
        if any(phrase in lower for phrase in ("threat hunt", "hunt for", "search for ioc", "search telemetry")):
            indicator, indicator_type = self._indicator(message)
            return AssistantIntent(
                command=AssistantCommandName.HUNT,
                arguments={
                    **({"indicator": indicator} if indicator else {}),
                    "indicator_type": indicator_type,
                },
            )
        if any(
            phrase in lower
            for phrase in ("triage findings", "triage alerts", "show findings")
        ):
            return AssistantIntent(command=AssistantCommandName.TRIAGE)
        # Only "what's new / changed since my last check" is answered here -
        # that names a session cursor the analyst model has no access to.
        # A plain/recent alert listing ("show me critical alerts") used to be
        # captured here too and answered with a canned count that ignored
        # any severity/time filter in the phrasing; it now falls through to
        # CHAT, which has search_alerts/aggregate_alerts and can actually
        # apply those filters.
        filters = self._alert_filters(message)
        change = self._change_query(lower, has_window="hours" in filters)
        if change is not None and alert_id is None:
            # A named alert ID means this is about one specific alert, not a
            # fleet-wide count - let the analyst model look it up instead.
            return AssistantIntent(
                command=AssistantCommandName.ALERTS,
                arguments={**filters, **change},
            )
        if any(phrase in lower for phrase in ("alert summary", "alert overview", "how many alerts")):
            return AssistantIntent(command=AssistantCommandName.SUMMARY)
        if any(
            phrase in lower
            for phrase in (
                "wazuh health",
                "service health",
                "connections",
                "connection status",
                "are we connected",
            )
        ):
            return AssistantIntent(command=AssistantCommandName.HEALTH)
        if lower.strip() in {"help", "what can you do", "options", "commands"}:
            return AssistantIntent(command=AssistantCommandName.HELP)
        if (
            "?" in message
            or re.match(
                r"^\s*(what|why|how|explain|describe|should|can|could|does|"
                r"is|are|tell me)\b",
                lower,
            )
        ):
            return AssistantIntent(
                command=AssistantCommandName.CHAT,
                arguments={"question": message},
            )
        return None

    def route(self, message: str) -> tuple[AssistantIntent, dict[str, int]]:
        message = message.strip()
        if not message:
            raise ValueError("A message is required.")
        if message.startswith("/"):
            return self.parse_slash(message), {"input_tokens": 0, "output_tokens": 0}
        deterministic = self.deterministic(message)
        if deterministic is not None:
            return deterministic, {"input_tokens": 0, "output_tokens": 0}

        return (
            AssistantIntent(
                command=AssistantCommandName.CHAT,
                arguments={"question": message},
                confidence=1.0,
                source="deterministic",
            ),
            {"input_tokens": 0, "output_tokens": 0},
        )
