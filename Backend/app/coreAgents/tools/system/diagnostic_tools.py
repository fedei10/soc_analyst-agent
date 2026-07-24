"""One bounded read-only tool for API-host diagnostics."""

from langchain_core.tools import StructuredTool

from app.coreAgents.tools.system.schemas import SystemDiagnosticInput
from app.coreAgents.tools.wazuh._common import run
from app.services.system.diagnostics import get_system_diagnostic_service


def build_system_diagnostic_tools(service=None) -> list[StructuredTool]:
    def collect_host_diagnostic(diagnostic: str) -> dict:
        current = service or get_system_diagnostic_service()
        return run(lambda: current.collect(diagnostic))

    return [
        StructuredTool.from_function(
            func=collect_host_diagnostic,
            name="collect_host_diagnostic",
            description=(
                "Run one fixed read-only diagnostic on the host running TSAGE: "
                "listening ports, network connections, routes, firewall status, "
                "failed services, or a process snapshot. This tool accepts no "
                "command text or arguments and never modifies the host. For a "
                "remote Wazuh endpoint, use Wazuh inventory tools instead."
            ),
            args_schema=SystemDiagnosticInput,
        )
    ]
