from types import SimpleNamespace

import pytest

from app.services.system.diagnostics import (
    SystemDiagnosticService,
    SystemDiagnosticsDisabledError,
)
from app.services.system.remediation import (
    SystemRemediationError,
    SystemRemediationService,
)


def test_diagnostics_are_disabled_by_default():
    service = SystemDiagnosticService(enabled=False)

    with pytest.raises(SystemDiagnosticsDisabledError):
        service.collect("listening_ports")


def test_diagnostic_executes_only_the_fixed_argument_vector(monkeypatch):
    calls = []

    monkeypatch.setattr(
        "app.services.system.diagnostics.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="port evidence", stderr="")

    monkeypatch.setattr(
        "app.services.system.diagnostics.subprocess.run",
        fake_run,
    )
    result = SystemDiagnosticService(enabled=True).collect("listening_ports")

    assert calls[0][0] == ["/usr/bin/ss", "-lntup"]
    assert calls[0][1]["shell"] is False
    assert result["scope"] == "tsage_api_host"
    assert result["status"] == "completed"


def test_service_restart_requires_exact_allowlist_match(monkeypatch):
    service = SystemRemediationService(
        enabled=True,
        service_allowlist={"wazuh-agent.service"},
    )
    monkeypatch.setattr(
        "app.services.system.remediation.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )

    with pytest.raises(SystemRemediationError):
        service.validate_service("postgresql.service")
    with pytest.raises(SystemRemediationError):
        service.validate_service("wazuh-agent.service; reboot")


def test_service_restart_never_uses_a_shell(monkeypatch):
    calls = []
    service = SystemRemediationService(
        enabled=True,
        service_allowlist={"wazuh-agent.service"},
    )
    monkeypatch.setattr(
        "app.services.system.remediation.shutil.which",
        lambda name: f"/usr/bin/{name}",
    )

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "app.services.system.remediation.subprocess.run",
        fake_run,
    )
    result = service.restart_service("wazuh-agent.service")

    assert calls[0][0] == [
        "systemctl",
        "restart",
        "wazuh-agent.service",
    ]
    assert calls[0][1]["shell"] is False
    assert result["status"] == "completed"
