"""Cumulative, read-only Wazuh toolsets for each SOC tier."""

from app.coreAgents.tools.wazuh.soc_l1_tools import build_l1_tools
from app.coreAgents.tools.wazuh.soc_l2_tools import build_l2_tools
from app.coreAgents.tools.wazuh.soc_l3_tools import build_l3_tools
from app.coreAgents.tools.system.diagnostic_tools import (
    build_system_diagnostic_tools,
)
from app.services.wazuh.gateway import WazuhGateway


def get_soc_l1_tools(gateway: WazuhGateway | None = None) -> list:
    return build_l1_tools(gateway)


def get_soc_l2_tools(gateway: WazuhGateway | None = None) -> list:
    return (
        build_l1_tools(gateway)
        + build_l2_tools(gateway)
        + build_system_diagnostic_tools()
    )


def get_soc_l3_tools(gateway: WazuhGateway | None = None) -> list:
    return get_soc_l2_tools(gateway) + build_l3_tools(gateway)


def get_all_read_only_tools(gateway: WazuhGateway | None = None) -> list:
    return get_soc_l3_tools(gateway)
