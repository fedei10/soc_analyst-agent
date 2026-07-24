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

Never expose `CLERK_SECRET_KEY` through a `NEXT_PUBLIC_*` variable.

## Run

```bash
make storage-up
make storage-init
source venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Only `GET /health` is public. Application requests require a verified Clerk
session token. Investigations, conversations, and memory are isolated by the
verified Clerk user ID.

Useful authenticated endpoints:

- `GET /api/v1/health/storage`
- `GET /api/v1/health/wazuh`
- `POST /api/v1/soc/orchestrator/chat/stream`
- `GET /api/v1/soc/conversations`
- `GET /api/v1/investigations`
- `GET /api/v1/investigations/{id}/events`
- `GET /api/v1/investigations/{id}/approvals`
- `POST /api/v1/investigations/{id}/approval`
- `POST /api/v1/investigations/{id}/execute`

The formal workflow uses fixed sequential L1, L2, and L3 teams. Each specialist
has an exact read-only tool allowlist and a four-call limit. L3 response
proposals pass server policy and a human approval checkpoint. Approval only
records a decision. A separate executor operation atomically claims the
approved actions, runs the allowlisted responder, and records post-action
verification. Keep `WAZUH_READ_ONLY=true` and dangerous tools disabled until
this path has been validated in the lab.

Apply the default retention schedule with `make retention-clean`. Reports,
approvals, actions, and curated memories are not automatically deleted.

## Tests

```bash
venv/bin/python -m pytest -q
```
