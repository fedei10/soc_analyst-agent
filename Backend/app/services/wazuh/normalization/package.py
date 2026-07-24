"""Package installation and state-change normalization."""

from typing import Any

from app.services.wazuh.normalization.base import AlertNormalizer
from app.services.wazuh.normalization.field_extractors import combined_text, text
from app.services.wazuh.normalization.schemas import PackageChangeDetails


class PackageNormalizer(AlertNormalizer):
    priority = 40
    category = "configuration_change"
    attack_family = "software_change"

    def matches(self, raw: dict[str, Any]) -> bool:
        value = combined_text(raw)
        return any(marker in value for marker in ("dpkg", "package installed", "package removed"))

    def normalize(self, raw: dict[str, Any]):
        value = combined_text(raw)
        if any(marker in value for marker in (" remove ", "removed", "uninstall")):
            operation, event_type = "removed", "package_removed"
        elif any(marker in value for marker in ("install", "upgrade")):
            operation, event_type = "installed", "package_installed"
        else:
            operation, event_type = "state_changed", "package_state_changed"
        package = text(raw, "data.package", "data.name", "package.name", "package_name")
        details = PackageChangeDetails(
            package=package,
            version=text(raw, "data.version", "package.version"),
            operation=operation,
            package_status=text(raw, "data.status", "data.dpkg_status"),
        ).model_dump(mode="json", exclude_none=True)
        return self.build(
            raw,
            event_type=event_type,
            summary=f"Package {package or 'unknown'} was {operation}.",
            attack_details=details,
            package_name=package,
        )
