"""Compact, source-backed evidence for read-only analyst tools."""

import re
import shlex
from typing import Any


def technique_id(value: str) -> str:
    value = value.strip().upper()
    if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", value):
        raise ValueError("Use an ATT&CK technique ID such as T1040 or T1059.004.")
    return value


def compact_mitre(item: dict[str, Any]) -> dict[str, Any]:
    fields = ("id", "external_id", "name", "url", "description", "mitre_detection",
              "tactics", "mitigations", "deprecated", "modified_time")
    result = {key: item[key] for key in fields if key in item}
    omitted = []
    for key in ("description", "mitre_detection"):
        if isinstance(result.get(key), str) and len(result[key]) > 1200:
            result[key] = result[key][:1200]
            omitted.append(key)
    if omitted:
        result["truncated_fields"] = omitted
    return result


def process_evidence(source: dict[str, Any]) -> dict[str, Any] | None:
    """Decode audit EXECVE argv, not the syscall's pointer-valued a0/a1.

    An executable in a failed execve describes the calling process, not proof
    the attempted target launched. PROCTITLE alone may describe that caller.
    """
    data = source.get("data") or {}
    audit = data.get("audit") or {}
    if not audit:
        windows = (data.get("win") or {}).get("eventdata") or {}
        if not windows.get("image"):
            return None
        return {
            "executable": windows.get("image"),
            "command_line": windows.get("commandLine"),
            "pid": windows.get("processId"), "ppid": windows.get("parentProcessId"),
            "parent_executable": windows.get("parentImage"),
            "parent_command_line": windows.get("parentCommandLine"),
            "user": windows.get("user"), "command_source": "windows_eventdata",
        }
    result = {key: audit.get(field) for key, field in {
        "executable": "exe", "pid": "pid", "ppid": "ppid", "uid": "uid",
        "effective_uid": "euid", "login_uid": "auid", "session": "session",
        "execve_success": "success", "execve_return": "exit",
    }.items()}
    log = str(source.get("full_log") or "")
    is_execve = bool(audit.get("execve") or "type=EXECVE" in log
                     or "SYSCALL=execve" in log or "SYSCALL=execveat" in log)
    if not is_execve:
        # Other audit syscalls describe an existing process, not its launch.
        result["execve_success"] = None
        result["execve_return"] = None
    for key, label in (("user", "UID"), ("effective_user", "EUID")):
        match = re.search(rf'\b{label}="([^"]*)"', log)
        result[key] = match.group(1) if match else None
    section = re.search(r"\btype=EXECVE\b.*?(?= type=[A-Z_]+\b|$)", log, re.S)
    argv: dict[int, str] = {}
    expected = None
    if section:
        count = re.search(r"\bargc=(\d+)", section.group())
        expected = int(count.group(1)) if count else None
        for arg in re.finditer(r'\ba(\d+)=(?:"([^"]*)"|([0-9A-Fa-f]+))(?=\s|$)', section.group()):
            try:
                argv[int(arg.group(1))] = arg.group(2) if arg.group(2) is not None else bytes.fromhex(arg.group(3)).decode("utf-8", errors="replace")
            except ValueError:
                continue
    # Decoder fields are a fallback only when the complete raw argv is absent.
    if not argv and audit.get("execve"):
        decoded = audit["execve"]
        expected = int(decoded["argc"]) if str(decoded.get("argc", "")).isdigit() else None
        argv = {int(key[1:]): str(value) for key, value in decoded.items() if re.fullmatch(r"a\d+", key)}
    complete = expected is not None and 0 < expected <= 256 and set(argv) == set(range(expected))
    result.update({
        "command_line": shlex.join([argv[i] for i in range(expected)]) if complete else None,
        "argv_complete": complete,
        "command_source": "audit_execve" if complete else "unavailable_or_incomplete",
    })
    if audit.get("success") == "no":
        target = re.search(r'\btype=PATH\b.*?\bname="([^"]*)"', log)
        result["attempted_path"] = target.group(1) if target else None
    return result


def compact_alert(hit: dict[str, Any]) -> dict[str, Any]:
    source = hit.get("_source") or {}
    agent, rule = source.get("agent") or {}, source.get("rule") or {}
    result = {
        "alert_id": hit.get("_id"), "index_name": hit.get("_index"),
        "evidence_ref": f"wazuh:alert:{hit.get('_id')}",
        "timestamp": source.get("@timestamp") or source.get("timestamp"),
        "agent_id": agent.get("id"), "agent_name": agent.get("name"),
        "rule_id": rule.get("id"), "rule_level": rule.get("level"),
        "description": rule.get("description"),
        "mitre_techniques": (rule.get("mitre") or {}).get("id", []),
    }
    process = process_evidence(source)
    if process is not None:
        result["process"] = process
    data = source.get("data") or {}
    result["source_ip"] = data.get("srcip")
    result["target_user"] = data.get("dstuser")
    # SCA provides observed failed checks and explicit remediation guidance.
    sca = data.get("sca") or {}
    check = sca.get("check") or {}
    if check:
        result["configuration_check"] = {k: check[k] for k in (
            "id", "title", "result", "rationale", "remediation", "compliance"
        ) if k in check}
    return result


def compact_vulnerability(hit: dict[str, Any]) -> dict[str, Any]:
    source = hit.get("_source") or {}
    vulnerability = source.get("vulnerability") or {}
    return {
        "evidence_ref": f"wazuh:vulnerability:{hit.get('_index')}:{hit.get('_id')}",
        "document_id": hit.get("_id"), "index_name": hit.get("_index"),
        "agent": source.get("agent", {}), "os": (source.get("host") or {}).get("os", {}),
        "package": {k: v for k, v in (source.get("package") or {}).items() if k in (
            "name", "version", "architecture", "type", "installed", "condition"
        )},
        "vulnerability": {k: v for k, v in vulnerability.items() if k in (
            "id", "severity", "score", "description", "detected_at", "published_at",
            "reference", "scanner", "status", "under_evaluation"
        )},
        "assessment_limit": "Detected vulnerable inventory, not proof of exploitation. Do not invent a fixed version when no vendor condition/advisory is present.",
    }
