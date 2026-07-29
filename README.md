# TSAGE — SOC Analyst Agent

An AI-assisted Security Operations Center platform. It ingests Wazuh alerts,
correlates findings, and runs a controlled MAPE-K (Monitor-Analyze-Plan-Execute
+ Knowledge) workflow to produce evidence-backed diagnoses, executable
remediation playbooks, or human-reviewable advisories.

## Structure

- **`Backend/`** — FastAPI + LangGraph service. PostgreSQL (authoritative) and
  Redis (optional coordination) via Docker Compose. Handles alert ingestion,
  investigation orchestration, approvals, and execution. See
  [`Backend/README.md`](Backend/README.md) for setup, configuration, and the
  full API surface.
- **`Frontend/agent-ui/`** — Next.js SOC assistant UI (Clerk auth, Tailwind,
  shadcn/radix components). See
  [`Frontend/agent-ui/README.md`](Frontend/agent-ui/README.md) for dev setup.
- **`dataset/wazuh-datasets/`** — Sample Wazuh alert datasets used for local
  testing and evaluation.

## Quick start

```bash
# Backend
cd Backend
make storage-up
make storage-init
source venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000

# Frontend (separate terminal)
cd Frontend/agent-ui
pnpm install
pnpm dev
```

See each subdirectory's README for environment variables, workers, and test
commands.
