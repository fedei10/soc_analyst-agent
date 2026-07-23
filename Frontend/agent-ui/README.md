# TSAGE SOC Console

Next.js interface for the TSAGE FastAPI backend. It exposes:

- One orchestrator chat that routes requests to SOC L1, L2, or L3
- Visible specialist selection and routing reason
- Agent tool-call traces
- Wazuh health and 24-hour alert totals
- LangGraph investigation state
- L1/L2/L3 structured results and audit history
- Human approval for state-changing response actions

## Start the project

From the repository root, start the backend:

```bash
cd Backend
./venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Start the frontend in another terminal:

```bash
cd Frontend/agent-ui
npm run dev
```

Open `http://127.0.0.1:3000`.

The frontend proxies `/api/tsage/*` to `http://127.0.0.1:8000` through a
timeout-aware Next.js route handler. To use a different backend:

```bash
TSAGE_API_URL=http://127.0.0.1:8100 npm run dev
```

## Connect

1. Enter one configured `SOC_READ_API_KEYS` value in **Read token**.
2. Enter a `SOC_WRITE_API_KEYS` value only when testing human approval.
3. Save the session.
4. Start the Wazuh SSH tunnel with `make tunnel` from `Backend/`.
5. Refresh the environment indicator.
6. Describe the task to the orchestrator; it selects the minimum sufficient
   SOC tier automatically.

Tokens are stored in browser `sessionStorage`; they are not bundled into the
frontend.

## Validate

```bash
npm run typecheck
npm run build
```
