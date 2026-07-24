"""Two deeper read-only context tools for SOC L3."""

from langchain_core.tools import StructuredTool

from app.coreAgents.tools.wazuh._common import run
from app.coreAgents.tools.wazuh.schemas import DetectionEvidenceInput, RuleMitreContextInput
from app.services.wazuh.dependencies import get_wazuh_gateway
from app.services.wazuh.gateway import WazuhGateway


def build_l3_tools(gateway: WazuhGateway | None = None) -> list[StructuredTool]:
    def current_gateway() -> WazuhGateway:
        return gateway or get_wazuh_gateway()

    def get_rule_and_mitre_context(rule_id: str) -> dict:
        def fetch() -> dict:
            context = current_gateway().get_rule_and_mitre_context(rule_id)
            return {
                "found": context is not None,
                "context": context.model_dump(mode="json") if context else None,
            }

        return run(fetch)

    def get_detection_evidence(agent_id: str, limit: int = 100) -> dict:
        return run(lambda: current_gateway().get_detection_evidence(
            agent_id=agent_id, limit=limit
        ).model_dump(mode="json"))

    return [
        StructuredTool.from_function(
            func=get_rule_and_mitre_context,
            name="get_rule_and_mitre_context",
            description=(
                "Read-only Wazuh rule and MITRE context for one numeric rule ID already seen "
                "in evidence. Use to validate, not force, an ATT&CK mapping."
            ),
            args_schema=RuleMitreContextInput,
        ),
        StructuredTool.from_function(
            func=get_detection_evidence,
            name="get_detection_evidence",
            description=(
                "Read-only bounded FIM, SCA, and rootcheck evidence for one numeric agent "
                "ID. Use when validating endpoint findings or detection gaps; results may "
                "be truncated."
            ),
            args_schema=DetectionEvidenceInput,
        ),
    ]
