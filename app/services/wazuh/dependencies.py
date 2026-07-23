"""Lazy dependency providers for Wazuh infrastructure."""

from functools import lru_cache

from app.services.wazuh.gateway import WazuhGateway
from app.services.wazuh.responder_client import WazuhResponderClient


@lru_cache(maxsize=1)
def get_wazuh_gateway() -> WazuhGateway:
    return WazuhGateway()


@lru_cache(maxsize=1)
def get_wazuh_responder() -> WazuhResponderClient:
    return WazuhResponderClient()


def close_wazuh_dependencies() -> None:
    if get_wazuh_gateway.cache_info().currsize:
        get_wazuh_gateway().close()
        get_wazuh_gateway.cache_clear()
    if get_wazuh_responder.cache_info().currsize:
        get_wazuh_responder().close()
        get_wazuh_responder.cache_clear()
