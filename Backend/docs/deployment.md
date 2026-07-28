# Internship lab deployment

The local stack consists of the FastAPI service, alert-ingestion worker,
orchestration worker, PostgreSQL, and Redis.

The three application services use Linux host networking in this internship
lab. This lets them reach the Wazuh SSH forwards on `127.0.0.1` without
publishing Wazuh ports to the LAN. The existing PostgreSQL and Redis Compose
services remain unchanged and are reached through their published host ports.
Compose loads Wazuh credentials from `.env`, then overlays the local
PostgreSQL and Redis URLs from `.env.local`.
The Makefile targets Docker's `default` system engine unless
`DOCKER_CONTEXT` is explicitly overridden.

```bash
make tunnel
make stack-up
make storage-init
```

The SSH tunnel exposes the remote Wazuh indexer and manager on local ports
`9200` and `55000`. `make tunnel-status` must report `tunnel up` before live
Wazuh checks can succeed.

For separate local processes:

```bash
make storage-up
make storage-init
uvicorn app.main:app --host 127.0.0.1 --port 8000
make ingest-worker
make orchestration-worker
```

This internship deployment intentionally allows `WAZUH_VERIFY_SSL=false`.
Keep all response controls disabled until the read-only health endpoint and
one dry-run investigation succeed:

```dotenv
MAPEK_EXECUTION_MODE=disabled
MAPEK_DRY_RUN=true
MAPEK_REAL_EXECUTION_ENABLED=false
WAZUH_READ_ONLY=true
WAZUH_ALLOW_DANGEROUS_TOOLS=false
```
