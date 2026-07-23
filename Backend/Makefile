WAZUH_SSH   := soclab@192.168.100.15
TUNNEL_SOCK := /tmp/wazuh-tunnel-$(USER).sock

.PHONY: tunnel tunnel-stop tunnel-status

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
