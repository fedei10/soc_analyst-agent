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

Only `GET /health` is public. Application requests require a verified Clerk
session token. Investigations and evidence are isolated by the verified Clerk
user ID.

Useful authenticated endpoints:

- `GET /api/v1/health/storage`
- `GET /api/v1/health/wazuh`
- `GET /api/v1/soc/assistant/commands`
- `POST /api/v1/soc/orchestrator/chat`
- `POST /api/v1/soc/orchestrator/chat/stream`
- `POST /api/v1/investigations`
- `GET /api/v1/investigations`
- `GET /api/v1/investigations/{id}/events`
- `GET /api/v1/investigations/{id}/approvals`
- `POST /api/v1/investigations/{id}/approval`
- `POST /api/v1/investigations/{id}/execute`

The formal workflow is a controlled MAPE-K state machine. SOC levels are human
RBAC roles, not autonomous agents. Approval only records a decision. A separate
executor operation atomically claims approved actions, runs a restricted
adapter, verifies security and health, and rolls back on failure. Keep
`MAPEK_DRY_RUN=true`, `WAZUH_READ_ONLY=true`, and dangerous tools disabled until
the response path has been validated in the lab.

The SOC assistant accepts deterministic slash commands and natural-language
requests. Its server-owned capability catalog is exposed to the frontend for
autocomplete. Ambiguous requests may use Oxy only for typed intent
classification; provider failure does not disable known commands.

See [`docs/mape-k-workflow.md`](docs/mape-k-workflow.md) for the migration map,
state machine, Oxy configuration, and current production boundary.

Apply the default retention schedule with `make retention-clean`. Reports,
approvals, actions, and curated memories are not automatically deleted.

## Tests

```bash
venv/bin/python -m pytest -q
```
