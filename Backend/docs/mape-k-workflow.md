# Controlled MAPE-K Security Workflow

TSAGE formal investigations use one explicit state machine:

```text
Wazuh alert
  -> Monitor
  -> Analyze
  -> Plan
  -> Policy gate
  -> Human approval
  -> Execution authorization
  -> Execute
  -> Verify
  -> Knowledge

Verification failure -> Rollback -> Escalated
```

SOC L1, L2, and L3 are human RBAC roles. They are not autonomous agents.

## Migration map

| Previous component | Decision | Replacement |
| --- | --- | --- |
| L1/L2/L3 agent modules | Retired from runtime | `app/mape_k/graph.py` |
| Tier supervisors and subgraphs | Retired from runtime | Explicit conditional graph edges |
| Tier-agent conversation endpoint | Returns HTTP 410 | Formal investigation API |
| SOC assistant | Bounded command router | Allowlisted Wazuh reads and workflow operations |
| Groq/Cerebras/Gemini/Oxy model pool | Retired from runtime | One lazy Oxy `LLMProvider` |
| Per-tier prompts and tool loops | Retired from runtime | Deterministic stage implementations |
| Wazuh gateway and normalizers | Kept | `WazuhMonitor` |
| PostgreSQL repository/checkpointer | Kept | Durable workflow state and evidence |
| Redis facade | Kept | Ephemeral cache, lock, stream, idempotency |
| Approval and execution claim | Kept and tightened | RBAC approval plus separate execution |
| Existing response credentials | Kept isolated | `RestrictedExecutor` only |

Legacy agent, supervisor, provider-pool, prompt, and open-ended tool-loop
modules were removed. Shared historical schema and report models remain only
where the PostgreSQL compatibility layer still consumes them.

## SOC assistant

The assistant is a capability router, not another autonomous agent. Its
server-owned catalog drives both API validation and the frontend slash menu:

- `/alerts` returns compact, correlated Wazuh findings.
- `/summary` returns bounded alert distributions.
- `/hunt` searches local Wazuh alert and archive telemetry for one indicator.
- `/investigate` starts the formal MAPE-K workflow.
- `/status` loads a durable investigation snapshot.
- `/health` checks Wazuh manager and indexer connectivity.
- `/help` returns the current capability catalog.

Slash commands and common natural-language requests route deterministically.
Only ambiguous language uses Oxy for structured intent classification. An Oxy
outage falls back to help, so deterministic capabilities remain available.
The model only selects from the catalog and cannot invent tools, execute shell
commands, bypass approval, or access responder credentials.

## Oxy inference

Analyze and ambiguous assistant intent classification may call the centralized
provider. Plan selects the approved SSH playbook deterministically. Known
commands and SSH brute-force incidents therefore do not require model calls.

```env
LLM_PROVIDER=oxy
LLM_API_KEY=...
LLM_BASE_URL=https://api.oxyy.ai/v1
LLM_MODEL=gpt-oss-120b
```

The key is held in `SecretStr`, initialized lazily, and never included in
workflow state, prompts, logs, database records, or API responses.

## SSH brute-force playbook

`ssh-bruteforce-v1`:

1. Loads the selected Wazuh alert and related alerts.
2. Normalizes, deduplicates, aggregates, and creates immutable evidence IDs.
3. Maps the incident to `T1110.001` using deterministic rules.
4. Rejects missing source IPs, weak evidence, protected IPs, and approved
   administrative IPs.
5. Proposes a temporary `block_ip` paired with `unblock_ip`.
6. Requires SOC L2 or higher approval.
7. Requires a separate allowlisted executor user.
8. Executes in dry-run mode by default.
9. Verifies attack cessation, Wazuh connectivity, and legitimate SSH.
10. Rolls back and escalates if verification fails.

## Safety configuration

Real actions require all of:

```env
MAPEK_DRY_RUN=false
MAPEK_REAL_EXECUTION_ENABLED=true
WAZUH_READ_ONLY=false
WAZUH_ALLOW_DANGEROUS_TOOLS=true
```

Keep dry-run enabled until the Wazuh active-response timeout and automatic
unblock behavior are validated in the target environment.

Human roles are configured by Clerk user ID:

```env
CLERK_SOC_L2_USER_IDS=
CLERK_SOC_L3_USER_IDS=
CLERK_SECURITY_ADMIN_USER_IDS=
CLERK_AUDITOR_USER_IDS=
CLERK_EXECUTOR_USER_IDS=
```

Executor users are treated as SOC L3 for approval checks. Approval does not
grant execution permission.

## Persistence

PostgreSQL remains authoritative for snapshots, normalized evidence,
approvals, action claims, action results, reports, and audit events. The
existing JSON snapshot fields allow the MAPE-K state to be persisted without a
schema migration.

Redis is fail-soft and stores only correlation caches, analysis caches,
activity streams, locks, and short-lived idempotency records. A Redis outage
does not remove incident evidence or PostgreSQL action claims.

## Current boundary

Real execution is intentionally disabled by default. The dry-run result records
the intended expiry and rollback action. Before enabling production response,
deploy and test a durable expiry worker or confirm the Wazuh active-response
configuration automatically sends the delete action at the requested TTL.
