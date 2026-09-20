# Single AI SOC Analyst

TSAGE has one conversational AI SOC analyst for ordinary investigation. It is
not an L1/L2/L3 simulation and it does not use a second model to classify an
analyst's message.

```text
analyst message
  -> deterministic slash-command parser
  -> one bounded LangGraph tool-calling analyst
  -> allowlisted, tenant-bound evidence tools
  -> deterministic Wazuh counts/correlation/timelines/coverage
  -> grounded conversational answer with evidence references

explicit /investigate <alert-id>
  -> durable MAPE-K response workflow
  -> policy -> approval -> execution authorization
  -> execute -> verify -> rollback/audit
```

## Evidence tools

The model sees small tool schemas, not arbitrary Wazuh paths or OpenSearch DSL.
The organization ID and calling user are server-owned closure values and cannot
be supplied or overridden in a model tool call. The main operations are:

- bounded alert search and one-alert lookup;
- deterministic alert activity counts with deduplication and coverage;
- SSH/authentication timelines with account cardinality;
- exact success-after-failure matching on source IP, target account, and agent;
- bounded post-login activity on the same agent;
- endpoint context, inventory, detections, vulnerabilities, and health;
- read-only finding and investigation status lookup.

Tool results carry stable `wazuh:alert:<document-id>` references. Complete zero
results are represented differently from partial/truncated results. Exceptions
remain visible as tool failures, so the model cannot turn unavailable telemetry
into a confident answer.

### MITRE, threat hunting, and remediation

- `mitre_technique_context(technique_id="T1040")` queries the Wazuh server's
  `/mitre/techniques` with an exact `external_id` filter, then resolves related
  `/mitre/mitigations`. ATT&CK T/M identifiers are distinct from the STIX UUIDs
  used by these relation APIs. Catalog metadata is not evidence of an attack.
- `threat_hunt` searches only `wazuh-alerts-*`, combining exact agent, technique,
  executable, IP, and user filters. Historical ISO timestamp bounds must include
  a timezone and span at most seven days. Results include source document IDs,
  timestamps and audit/Sysmon process details. Linux argv is reconstructed from
  `EXECVE` (including hexadecimal arguments), not syscall pointer fields.
  Missing arguments and failed launches remain explicit. Generic audit events
  may not be MITRE-tagged: an empty T1040 query does not establish no sniffing.
- `hunt_ioc` correlates local alerts and archives for an indicator. This does not
  contact reputation services. Archive gaps remain visible; counts are source
  documents, not deduplicated events across the two indices.
- `vulnerability_overview` reads `wazuh-states-vulnerabilities-*` with exact
  agent/CVE/package/severity filters. It preserves installed versions, OS,
  CVSS, detection dates, scanner conditions and advisory references, plus
  `wazuh:vulnerability:<index>:<document-id>` evidence references. Inventory
  detection is not proof of exploitation; no fixed version is guessed.

Hunt/inventory results expose matched/returned/truncated coverage and bounded
`next_offset` pagination (offset <= 5000; not a snapshot of a changing index).
Timeouts or failed search shards are errors, not empty successful searches.
Output clipping updates coverage and pagination to the records actually shown.

The analyst connects recommendations to retrieved evidence, identifies required
privileges and disruption risks, and proposes how to verify the fix: package/CVE
inventory after the next scan, the same SCA check, or another bounded hunt.
Chat does not execute patches, isolation, blocking, shell commands or scripts.

### Adopted prototype capabilities

`sca_policy_summary` and `sca_failed_checks` expose native SCA scan scores,
check references, rationale and remediation. `mitre_search` resolves unknown
technique names; `mitre_metadata` reports the bundled catalog metadata.
`correlated_alerts` preserves distinct events and exact IDs around a scoped
timestamp, without merging different commands by rule description.
`alert_timeline`, `compare_alert_windows` and `mitre_attack_coverage` use
server-owned aggregations; comparison windows are disjoint and rate-normalized.
Top-bucket omissions/count errors and unmapped alerts remain explicit.
`hunt_ioc` additionally returns indexer-computed per-agent alert counts and
first/last-seen timestamps, separately from sampled alert/archive records.
These capabilities are selected by question rather than all exposed every turn.
The shortened prompt preserves evidence rules, remediation verification and
approval boundaries. No arbitrary indexer DSL or Flask prototype is imported.

Official references:

- [Wazuh server API: MITRE](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [Indexer API use cases](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html)
- [Threat hunting](https://documentation.wazuh.com/current/getting-started/use-cases/threat-hunting.html)
- [Vulnerability detection](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html)

## Boundaries and budgets

`SOC_ANALYST_MAX_TOOL_CALLS`, `SOC_ANALYST_MAX_HISTORY_MESSAGES`,
`SOC_ANALYST_MAX_EVIDENCE_REFS`, `SOC_ANALYST_MAX_TOOL_OUTPUT_CHARS`,
`SOC_ANALYST_MAX_QUERY_HOURS`, `SOC_ANALYST_MAX_QUERY_RESULTS`, and
`SOC_ANALYST_MAX_INPUT_CHARS` bound each turn. The hard tool-call counter also
covers parallel calls from one model response. Per-turn metrics include elapsed
time, tool counts, failed tools, evidence reference count, and provider token
usage.

Before each model request, the estimated input budget includes system prompt,
tool schemas, history and tool results, with the configured output reserve.
Old conversation turns are dropped when necessary, but current tool call/result
pairs are not silently removed. If current evidence alone exceeds the budget,
the response is `context_limit_exceeded`; provider HTTP 413 errors receive the
same classification, not the misleading `model_unavailable` fallback.

Wazuh fields and logs are untrusted evidence. Prompt text inside telemetry is
never an instruction. Suggested Ubuntu commands must be labeled as not executed
and include purpose, privilege requirements, side effects, and validation
signals. No shell or response-execution tool is bound to conversational chat.

## Local use

Start the API and worker in separate terminals:

```bash
cd Backend
venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
venv/bin/python -m app.workers.orchestration
```

Ask natural questions through `POST /api/v1/soc/orchestrator/chat`. Examples:

- `What happened on agent 001 in the last 24 hours?`
- `Were the SSH failures from 192.0.2.10 aimed at one account or many?`
- `Was there an exact successful login after those failures, and what happened next?`
- `Suggest Ubuntu commands to validate this, but do not run anything.`
- `Hunt T1040 on agent 001, inspect untagged tcpdump execution too, and suggest mitigations.`
- `Find critical vulnerabilities on agent 001. Explain the affected versions, vendor fix and verification steps.`
- `Check CVE-2025-4050 on agent 002 and show the installed package and patch condition.`

Use `/investigate <alert-id>` only when the analyst explicitly wants the formal
controlled-response workflow.
