"""Deterministic command parsing with one bounded Oxy intent fallback."""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Any

from app.mape_k.llm import LLMProvider, LLMTier, get_llm_provider
from app.soc_assistant.catalog import COMMANDS, COMMAND_BY_SLASH
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

COMMAND_ARGUMENTS = {
    AssistantCommandName.CHAT: {"question"},
    AssistantCommandName.HELP: set(),
    AssistantCommandName.ALERTS: {
        "hours",
        "min_level",
        "limit",
        "agent_id",
        "text",
        "since",
        "severity",
        "new_only",
        "open_only",
        "all_results",
    },
    AssistantCommandName.SUMMARY: {"hours"},
    AssistantCommandName.HUNT: {
        "indicator",
        "indicator_type",
        "hours",
        "limit",
        "agent_id",
    },
    AssistantCommandName.TRIAGE: {"hours", "min_level", "limit"},
    AssistantCommandName.INVESTIGATE: {"alert_id", "agent_id"},
    AssistantCommandName.STATUS: {"investigation_id"},
    AssistantCommandName.PLAN: {"investigation_id"},
    AssistantCommandName.COLLECT: {"investigation_id"},
    AssistantCommandName.CONTINUE: {"investigation_id"},
    AssistantCommandName.HEALTH: set(),
    AssistantCommandName.EXPLAIN: {"command"},
}

ARGUMENT_ALIASES = {
    "agent": "agent_id",
    "alert": "alert_id",
    "investigation": "investigation_id",
    "query": "text",
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


class AssistantIntentRouter:
    def __init__(self, llm: LLMProvider | None = None) -> None:
        # Intent classification is a small structured pick, not reasoning -
        # keeping it on the cheap tier leaves the reasoning budget for
        # diagnosis and the analyst chat loop.
        self.llm = llm or get_llm_provider(LLMTier.ROUTER)

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
        elif command.name == AssistantCommandName.EXPLAIN:
            if not positional:
                raise ValueError("/explain requires a command line.")
            options["command"] = " ".join(positional)
        elif positional:
            raise ValueError(f"{command.slash} does not accept positional arguments.")
        return AssistantIntent(command=command.name, arguments=options)

    @staticmethod
    def _canonical_argument_name(name: str) -> str:
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", name).replace("-", "_").lower()
        return ARGUMENT_ALIASES.get(snake, snake)

    @classmethod
    def _normalize_arguments(
        cls,
        command: AssistantCommandName,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        allowed = COMMAND_ARGUMENTS[command]
        normalized: dict[str, Any] = {}
        unsupported: list[str] = []
        for name, value in arguments.items():
            canonical = cls._canonical_argument_name(str(name))
            if canonical not in allowed:
                unsupported.append(str(name))
                continue
            normalized[canonical] = value
        if unsupported:
            rendered = ", ".join(sorted(unsupported))
            raise ValueError(
                f"Unsupported arguments for {command.value}: {rendered}"
            )
        return normalized

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
        explain = re.search(
            r"\b(?:explain(?:\s+this|\s+the)?\s+command|"
            r"what\s+does\s+(?:this|the)\s+command\s+do)\s*[:\-]?\s*(.+)$",
            message,
            re.I,
        )
        if explain and explain.group(1).strip():
            return AssistantIntent(
                command=AssistantCommandName.EXPLAIN,
                arguments={"command": explain.group(1).strip()},
            )
        if any(
            phrase in normalized
            for phrase in (
                "full mapek",
                "whole mapk",
                "whole mapek",
                "start investigation",
                "investigate alert",
                "investigate it",
                "investigate this",
                "investigate that",
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
        if "investigate" in lower:
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
        alert_query = bool(re.search(r"\balerts?\b", lower)) and bool(
            re.search(
                r"\b(show|list|get|find|any|which|what|recent|latest|newest|came)\b",
                lower,
            )
        )
        if alert_query or any(
            phrase in lower
            for phrase in (
                "get only alerts",
                "show alerts",
                "recent alerts",
                "latest alerts",
                "newest alerts",
                "wazuh alerts",
            )
        ):
            return AssistantIntent(
                command=AssistantCommandName.ALERTS,
                arguments=self._alert_filters(message),
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

        catalog = [
            {
                "command": command.name,
                "description": command.description,
                "usage": command.usage,
            }
            for command in COMMANDS
        ]
        try:
            intent, usage = self.llm.invoke_structured(
                AssistantIntent,
                [
                    {
                        "role": "system",
                        "content": (
                            "Select exactly one SOC capability. Return only arguments "
                            "explicitly present in the message. Use chat for explanatory "
                            "questions or requests for defensive guidance. Use help only "
                            "when the user asks about available capabilities."
                        ),
                    },
                    {
                        "role": "user",
                        "content": f"Capabilities: {catalog}\nMessage: {message[:2000]}",
                    },
                ],
            )
            routed = AssistantIntent.model_validate(intent)
            routed = routed.model_copy(
                update={
                    "arguments": self._normalize_arguments(
                        routed.command,
                        routed.arguments,
                    ),
                    "source": "oxy",
                }
            )
            if routed.confidence < 0.65:
                # An uncertain classification is not a reason to dead-end the
                # user at a menu message - hand the raw message to the
                # general-purpose (read-only) chat capability instead, which
                # can actually search and answer it.
                routed = AssistantIntent(
                    command=AssistantCommandName.CHAT,
                    arguments={"question": message},
                    confidence=routed.confidence,
                    source="oxy",
                )
            return routed, usage
        except Exception:
            # Slash commands and deterministic natural-language routes must stay
            # available when the optional intent-classification call is down.
            # Route to chat rather than a dead-end HELP message: the chat path
            # has its own graceful "model unavailable" fallback, so the user
            # gets an honest answer either way instead of a non-sequitur menu.
            return (
                AssistantIntent(
                    command=AssistantCommandName.CHAT,
                    arguments={"question": message},
                    confidence=0,
                    source="fallback",
                ),
                {"input_tokens": 0, "output_tokens": 0},
            )
