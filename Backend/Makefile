WAZUH_SSH   := soclab@192.168.100.15
TUNNEL_SOCK := /tmp/wazuh-tunnel-$(USER).sock
DATABASE_ENV ?= .env.local

.PHONY: tunnel tunnel-stop tunnel-status storage-up storage-down storage-status storage-init retention-clean ingest-once ingest-worker database-up database-down database-init

tunnel: ## start SSH tunnel to Wazuh on PC1 (9200 indexer, 55000 API)
	@ssh -S $(TUNNEL_SOCK) -O check $(WAZUH_SSH) 2>/dev/null && echo "tunnel already running" || ( \
	ssh -M -S $(TUNNEL_SOCK) -fN \
		-o ExitOnForwardFailure=yes \
		-o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
		-L 9200:127.0.0.1:9200 \
		-L 55000:127.0.0.1:55000 \
		$(WAZUH_SSH) && echo "tunnel up (9200, 55000)" )

tunnel-stop:
	@ssh -S $(TUNNEL_SOCK) -O exit $(WAZUH_SSH) 2>/dev/null && echo "tunnel stopped" || echo "no tunnel running (started by make)"

tunnel-status:
	@ssh -S $(TUNNEL_SOCK) -O check $(WAZUH_SSH) 2>/dev/null && echo "tunnel up" || echo "tunnel down"

storage-up:
	docker compose --env-file $(DATABASE_ENV) up -d --wait postgres redis

storage-down:
	docker compose --env-file $(DATABASE_ENV) down

storage-status:
	docker compose --env-file $(DATABASE_ENV) ps

storage-init:
	venv/bin/python -m app.db.setup

retention-clean:
	venv/bin/python -m app.db.retention

ingest-once:
	venv/bin/python -m app.workers.alert_ingestion --once

ingest-worker:
	venv/bin/python -m app.workers.alert_ingestion

database-up: storage-up

database-down: storage-down

database-init: storage-init
