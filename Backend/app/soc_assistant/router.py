"""Deterministic command parsing with one bounded Oxy intent fallback."""

from __future__ import annotations

import ipaddress
import re
import shlex
from typing import Any

from app.mape_k.llm import LLMProvider, get_llm_provider
from app.soc_assistant.catalog import COMMANDS, COMMAND_BY_SLASH
from app.soc_assistant.schemas import AssistantCommandName, AssistantIntent


OPTION_NAMES = {
    "--hours": "hours",
    "--min-level": "min_level",
    "--limit": "limit",
    "--agent": "agent_id",
    "--type": "indicator_type",
}
INTEGER_OPTIONS = {"hours", "min_level", "limit"}


class AssistantIntentRouter:
    def __init__(self, llm: LLMProvider | None = None) -> None:
        self.llm = llm or get_llm_provider()

    @staticmethod
    def _arguments(tokens: list[str]) -> tuple[list[str], dict[str, Any]]:
        positional: list[str] = []
        options: dict[str, Any] = {}
        index = 0
        while index < len(tokens):
            token = tokens[index]
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
        elif command.name == AssistantCommandName.STATUS:
            if not positional:
                raise ValueError("/status requires an investigation ID.")
            options["investigation_id"] = positional[0]
        elif positional:
            raise ValueError(f"{command.slash} does not accept positional arguments.")
        return AssistantIntent(command=command.name, arguments=options)

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
        normalized = re.sub(r"\bmape-?k\b", "mapek", lower)
        investigation = re.search(r"\bINV-[A-Za-z0-9-]+\b", message, re.I)
        alert = re.search(
            r"(?:alert(?:\s+id)?|mapek|investigate)\s*[:#]?\s+([A-Za-z0-9_.-]{3,256})",
            message,
            re.I,
        )
        if investigation and any(word in lower for word in ("status", "check", "show")):
            return AssistantIntent(
                command=AssistantCommandName.STATUS,
                arguments={"investigation_id": investigation.group(0).upper()},
            )
        if any(
            phrase in normalized
            for phrase in (
                "full mapek",
                "whole mapk",
                "whole mapek",
                "start investigation",
                "investigate alert",
            )
        ):
            return AssistantIntent(
                command=AssistantCommandName.INVESTIGATE,
                arguments={"alert_id": alert.group(1)} if alert else {},
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
        if any(phrase in lower for phrase in ("get only alerts", "show alerts", "recent alerts", "wazuh alerts")):
            return AssistantIntent(command=AssistantCommandName.ALERTS)
        if any(phrase in lower for phrase in ("alert summary", "alert overview", "how many alerts")):
            return AssistantIntent(command=AssistantCommandName.SUMMARY)
        if any(phrase in lower for phrase in ("wazuh health", "service health", "connections")):
            return AssistantIntent(command=AssistantCommandName.HEALTH)
        if lower.strip() in {"help", "what can you do", "options", "commands"}:
            return AssistantIntent(command=AssistantCommandName.HELP)
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
                            "explicitly present in the message. Use help when uncertain."
                        ),
                    },
                    {
                        "role": "user",
                        "content": f"Capabilities: {catalog}\nMessage: {message[:2000]}",
                    },
                ],
            )
            routed = AssistantIntent.model_validate(intent).model_copy(
                update={"source": "oxy"}
            )
            if routed.confidence < 0.65:
                routed = AssistantIntent(command=AssistantCommandName.HELP)
            return routed, usage
        except Exception:
            # Slash commands and deterministic natural-language routes must stay
            # available when the optional intent-classification call is down.
            return (
                AssistantIntent(
                    command=AssistantCommandName.HELP,
                    confidence=0,
                    source="fallback",
                ),
                {"input_tokens": 0, "output_tokens": 0},
            )
