# TSAGE SOC Console

Local FastAPI console for testing the L1, L2, and L3 SOC agents, their
allowlisted Wazuh tools, and the LangGraph investigation workflow.

## Run

```bash
source venv/bin/activate
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/soc`.

1. Paste one value from `SOC_READ_API_KEYS` into **Read token**.
2. Paste one value from `SOC_WRITE_API_KEYS` into **Write token** only when
   testing a human approval.
3. Send the task to the conversational orchestrator; it calls the bounded
   Wazuh tools needed for the request and can start the formal L1/L2/L3 graph.
4. Check **Tool activity** to see which Wazuh tools the agent invoked.
5. Use **Investigations** with a real Wazuh alert document ID to run the full
   LangGraph workflow.

The tokens are kept in browser `sessionStorage` and are not written into the
frontend source.

## Connect Wazuh

The API expects the Wazuh indexer and manager API through the PC1 SSH tunnel:

```bash
make tunnel
make tunnel-status
```

Then use **Refresh** in the console. The Wazuh status indicator must be healthy
before running an investigation from a real alert.

The threat-hunting tool searches `WAZUH_ARCHIVE_INDEX` (default
`wazuh-archives-*`) so it can find logs that did not trigger rules. A zero
archive count means this API found no indexed archive events; it does not prove
that the activity never occurred. Enable Wazuh JSON archive collection and
archive indexing on the Wazuh host before relying on archive searches.

Conversational read tools include normalized and raw alert lookup, agent/time
correlation, authentication timelines, successful-login checks, bounded
archive-log search, log statistics, and deterministic alert attribution.

Useful endpoints:

- Console: `http://127.0.0.1:8000/soc`
- OpenAPI: `http://127.0.0.1:8000/docs`
- Liveness: `http://127.0.0.1:8000/health`
- Wazuh diagnostics: `http://127.0.0.1:8000/api/v1/health/wazuh`
- Orchestrator chat: `POST http://127.0.0.1:8000/api/v1/soc/orchestrator/chat`

## Tests

```bash
pytest -q
node --check app/static/soc/app.js
```
