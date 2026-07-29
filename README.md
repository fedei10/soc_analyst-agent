# SOC Analyst Agent

SOC Analyst Agent is a full-stack security operations project with:

- **Backend**: FastAPI + LangGraph services for alert ingestion, investigation orchestration, and SOC assistant workflows.
- **Frontend**: Next.js SOC console for analyst interaction, investigation tracking, and approvals.
- **Dataset**: Wazuh-oriented datasets used for development and analysis.

## Repository structure

- `/Backend` – API, workers, orchestration logic, infrastructure, and backend tests.
- `/Frontend/agent-ui` – Next.js user interface for SOC analysts.
- `/dataset/wazuh-datasets` – dataset resources.

## Quick start

### 1) Backend

Follow the backend guide:

- `Backend/README.md`

Common local flow:

```bash
cd Backend
make storage-up
make storage-init
source venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 2) Frontend

Follow the frontend guide:

- `Frontend/agent-ui/README.md`

Common local flow:

```bash
cd Frontend/agent-ui
corepack pnpm install
corepack pnpm dev
```

## Validation

- Backend tests: `venv/bin/python -m pytest -q` (from `/Backend`)
- Frontend checks:
  - `corepack pnpm run typecheck`
  - `corepack pnpm run build`

## Documentation

- Backend details: `Backend/README.md`
- Frontend details: `Frontend/agent-ui/README.md`
