# TSAGE SOC Backend

FastAPI and LangGraph run locally. PostgreSQL 16 and Redis 7.4 run through
Docker Compose. PostgreSQL is authoritative; Redis is optional coordination.

## Configure

Copy the required values from `.env.example` into `.env.local`.

- `DATABASE_URL` points to the Compose PostgreSQL port.
- `REDIS_URL` includes the Compose Redis password.
- `CLERK_SECRET_KEY` is the claimed Clerk application's server key.
- `CLERK_AUTHORIZED_PARTIES` contains the frontend origin.
- `CLERK_EXECUTOR_USER_IDS` lists Clerk users allowed to execute approved
  responses. Empty denies execution.
- `CLERK_SOC_L2_USER_IDS` and `CLERK_SOC_L3_USER_IDS` grant human approval
  roles.
- `LLM_API_KEY` configures the single Oxy inference client used only when a
  deterministic diagnosis is unavailable.

Never expose `CLERK_SECRET_KEY` through a `NEXT_PUBLIC_*` variable.

## Run

```bash
make storage-up
make storage-init
source venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Run the checkpointed Wazuh ingestion and correlation worker in a second local
terminal:

```bash
make ingest-worker
```

Run queued investigations, delayed verification, and temporary-action recovery
in another terminal:

```bash
make orchestration-worker
```

`POST /api/v1/investigations` and the assistant's `/investigate` command return
a durable `queued` snapshot immediately. The orchestration worker claims it,
runs MAPE-K, pauses at approval or verification, and resumes verification when
the observation deadline is ready. Use `make orchestration-once` to test one
cycle.

To run the API, both workers, PostgreSQL, and Redis together:

```bash
make stack-up
```

Use `make ingest-once` for one bounded cycle during setup or troubleshooting.
The worker pages through `wazuh-alerts-*`, inserts raw alerts idempotently,
normalizes new rows, links correlated findings, and advances its PostgreSQL
checkpoint only with committed pages. Set `WAZUH_INGESTION_ORGANIZATION_ID` to
the Clerk user ID that owns this personal deployment's findings.

Only `GET /health` is public. Application requests require a verified Clerk
session token. Investigations and evidence are isolated by the verified Clerk
user ID.

Useful authenticated endpoints:

- `GET /api/v1/health/storage`
- `GET /api/v1/health/ingestion`
- `GET /api/v1/health/wazuh`
- `POST /api/v1/alerts/check`
- `GET /api/v1/soc/assistant/commands`
- `POST /api/v1/soc/orchestrator/chat`
- `POST /api/v1/soc/orchestrator/chat/stream`
- `POST /api/v1/investigations`
- `GET /api/v1/investigations`
- `GET /api/v1/investigations/{id}/events`
- `GET /api/v1/investigations/{id}/approvals`
- `POST /api/v1/investigations/{id}/approval`
- `POST /api/v1/investigations/{id}/execute`

`POST /api/v1/alerts/check` runs one bounded Monitor cycle and returns a
deterministic delta from the previous successful PostgreSQL checkpoint. It
uses a 60-second overlap and deduplicates by Wazuh index plus document ID, so
late indexing and equal timestamps do not invent or lose alerts. The Monitor
path never calls an LLM; provider outages do not prevent ingestion.

The formal workflow is a controlled MAPE-K state machine. SOC levels are human
RBAC roles, not autonomous agents. Approval only records a decision. A separate
executor operation atomically claims approved actions, runs a restricted
adapter, verifies security and health, and rolls back on failure. Keep
`MAPEK_DRY_RUN=true`, `WAZUH_READ_ONLY=true`, and dangerous tools disabled until
the response path has been validated in the lab.

The workflow is not limited to SSH brute force analysis. Any sufficiently
confident, evidence-backed attack diagnosis receives either a registered
executable remediation plan or a typed analyst advisory covering investigation,
containment, eradication, recovery, and detection improvement. Advisory plans
are always non-executable and require human review; only code-owned, reversible
playbooks can reach policy approval and execution.

Deterministic capability modules currently cover SSH authentication, privilege
escalation, persistence, suspicious process execution, file-integrity changes,
command and control, possible exfiltration, vulnerable packages, and software
changes. Unmatched attacks still use bounded evidence-only semantic analysis
and receive a non-executable advisory when no registered playbook fits.

The SOC assistant accepts deterministic slash commands and natural-language
requests. Its server-owned capability catalog is exposed to the frontend for
autocomplete. Ambiguous requests may use Oxy only for typed intent
classification; provider failure does not disable known commands.

Use `/ask <question>` or natural-language questions for read-only SOC
explanations. The Oxy question agent receives only bounded conversation history
and validated alert, finding, and investigation context. It cannot call write
tools, approve actions, execute commands, or change workflow state.

## LangSmith

Set `LANGSMITH_API_KEY`, `LANGSMITH_TRACING=true`, and
`LANGSMITH_PROJECT=tsage`, then restart FastAPI. The SOC assistant records
LangSmith runs for:

- `soc_assistant.respond`
- `soc_assistant.route`
- `soc_assistant.execute`
- `soc_assistant.tool_call`
- LangChain/Oxy structured-output calls

The traced tool calls show selected capability, tool name, bounded inputs,
sanitized outputs, activity status, and active investigation IDs. Keep
`LANGSMITH_HIDE_INPUTS=true` and `LANGSMITH_HIDE_OUTPUTS=true` for normal SOC
use. In a local lab, set both to `false` when you need to inspect full prompt
and response payloads.

See [`docs/mape-k-workflow.md`](docs/mape-k-workflow.md) for the migration map,
state machine, Oxy configuration, and current production boundary.

Apply the default retention schedule with `make retention-clean`. Reports,
approvals, actions, and curated memories are not automatically deleted.

## Tests

```bash
venv/bin/python -m pytest -q
```
