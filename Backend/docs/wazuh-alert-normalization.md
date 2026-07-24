# Wazuh Alert Normalization and Context Compaction

## Architecture

TSAGE keeps raw evidence in Wazuh/OpenSearch and sends compact, deterministic
security findings to SOC agents:

```text
Wazuh document
  -> prioritized normalizer registry
  -> NormalizedAlert + attack_details
  -> time-window grouping and deduplication
  -> SecurityFinding
  -> agent/trace serializer
```

Existing FastAPI Wazuh endpoints retain their response contracts. The compact
path is the default for conversational and tier-specific agent list tools.
Exact alert lookup remains available, while complete raw documents require the
explicit raw-evidence operation.

## Canonical Schema

`NormalizedAlert` contains stable identifiers, UTC timestamps, agent and rule
data, category, attack family, event type, outcome, network/user/process fields,
MITRE techniques, a deterministic summary, and a resolvable evidence reference.
It never contains the complete raw document.

`AlertEnvelope` adds family-specific `attack_details`, normalization quality,
missing fields, and evidence references. Command-line content is represented by
a SHA-256 digest.

## Normalizer Registry

Normalizers run in explicit priority order:

1. SSH and authentication
2. Auditd execution
3. Sysmon
4. Vulnerability detector
5. SCA/compliance
6. Package changes
7. File integrity/syscheck
8. Network/firewall
9. Generic fallback

Each class implements `matches(raw)` and `normalize(raw)`. Field extractors
handle nested aliases and malformed values without failing the entire result.
Invalid timestamps use the Unix epoch sentinel and add `timestamp` to
`missing_fields`; malformed IP addresses become `null`.

To support a new decoder, add a small normalizer, give it a priority before the
generic fallback, register it in `registry.py`, and add representative fixtures.

## Aggregation and Findings

Default grouping includes the attack family, event type, relevant source and
target fields, rule identity, and a configured time bucket. Family-specific
keys prevent unrelated alerts from merging:

- Authentication: event, source, target host/user, protocol
- Vulnerability: agent, CVE, package
- Compliance: agent, benchmark, control
- Package: agent, package, operation
- File integrity: agent, path, operation

Findings preserve the highest Wazuh level and map it deterministically:

| Rule level | Finding severity |
| --- | --- |
| 0-3 | informational |
| 4-6 | low |
| 7-9 | medium |
| 10-12 | high |
| 13+ | critical |

High and critical findings recommend investigation. This is not a confirmed
compromise decision.

## Compact, Normalized, and Raw

- `compact`: counts, grouped findings, time windows, severity, and evidence refs
- `normalized`: bounded canonical alert envelopes
- `raw`: explicit restricted retrieval of one original Wazuh document

Conversation `ToolMessage` payloads use compact results. Formal investigation
payloads retain only identifiers, stages, result summaries, errors, and action
counts. Storage, API, agent, and trace serializers are intentionally separate.

Evidence references use `wazuh:alert:<alert_id>`. The resolver validates this
format before retrieving the unchanged document from the Wazuh indexer.

## LangGraph and LangSmith

Agent state retains findings, counts, identifiers, and evidence references, not
complete alert arrays. Trace serialization removes raw documents, `full_log`,
credentials, cookies, authorization, reasoning, and provider signature fields.
LangSmith remains enabled when configured, with content hidden by default.

Run metadata includes request/conversation/investigation identifiers where
available, scope, environment, service version, revision, role, provider, and
model.

## Example: Repeated SSH Alerts

Twenty raw SSH events containing duplicated rule, decoder, agent, and
`full_log` data become one finding:

```json
{
  "finding_id": "FND-...",
  "title": "Repeated SSH authentication failures",
  "event_type": "ssh_brute_force",
  "severity": "high",
  "alert_count": 20,
  "source_ips": ["192.168.100.9"],
  "affected_assets": ["servervb"],
  "representative_alert_id": "alert-19",
  "evidence_refs": ["wazuh:alert:alert-0", "wazuh:alert:alert-1"]
}
```

Evidence references are bounded in the agent payload; the group records whether
the reference list was truncated.

## Other Compact Examples

Vulnerability:

```json
{"event_type":"vulnerable_package","severity":"high","affected_assets":["servervb"],"alert_count":1,"representative_alert_id":"vuln-1","evidence_refs":["wazuh:alert:vuln-1"]}
```

SCA:

```json
{"event_type":"compliance_control_failed","severity":"medium","affected_assets":["servervb"],"alert_count":1,"representative_alert_id":"sca-1","evidence_refs":["wazuh:alert:sca-1"]}
```

Package change:

```json
{"event_type":"package_installed","severity":"medium","affected_assets":["servervb"],"alert_count":1,"representative_alert_id":"pkg-1","evidence_refs":["wazuh:alert:pkg-1"]}
```

## Configuration

```dotenv
WAZUH_AGENT_RESPONSE_MODE=compact
WAZUH_NORMALIZATION_ENABLED=true
WAZUH_RAW_EVIDENCE_ENABLED=true
ALERT_AGGREGATION_WINDOW_SECONDS=300
AUTH_AGGREGATION_WINDOW_SECONDS=600
VULNERABILITY_AGGREGATION_WINDOW_SECONDS=86400
COMPLIANCE_AGGREGATION_WINDOW_SECONDS=86400
MAX_FINDINGS_PER_AGENT_RESPONSE=10
MAX_EVIDENCE_REFS_PER_FINDING=20
MAX_NORMALIZED_ALERTS_PER_RESPONSE=50
LANGSMITH_INCLUDE_RAW_ALERTS=false
LANGSMITH_INCLUDE_FULL_LOG=false
REVISION_ID=development
```

## Limitations

- Wazuh decoder fields vary across versions and custom rules. Unknown layouts
  use the generic fallback and expose missing fields explicitly.
- `new_since_last_check` is `null` until a Redis cursor exists for the caller.
- A timestamp sentinel marks malformed source data and must not be interpreted
  as the event time.
- Normalization does not enrich external threat intelligence or prove actor
  identity.
- No database migration is required; raw evidence remains in Wazuh and current
  normalized evidence/report tables remain authoritative.
