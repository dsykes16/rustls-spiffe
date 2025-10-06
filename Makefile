SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
MAKEFLAGS += --no-builtin-rules

SPIRE_VERSION ?= 1.13.1
SPIRE_DIR     ?= ./spire
TMPDIR        ?= /tmp
WORKLOAD_API  ?= $(TMPDIR)/spire-agent/public/api.sock
TIMEOUT       ?= 30

SERVER_BIN    := $(SPIRE_DIR)/bin/spire-server
AGENT_BIN     := $(SPIRE_DIR)/bin/spire-agent
CONFIG_DIR    := $(SPIRE_DIR)/conf
AGENT_CONFIG  := $(CONFIG_DIR)/agent.conf
SERVER_CONFIG := $(CONFIG_DIR)/server.conf
LOG_DIR       := $(SPIRE_DIR)/log
SERVER_PID    := $(SPIRE_DIR)/server.pid
AGENT_PID     := $(SPIRE_DIR)/agent.pid
JOIN_TOKEN    := $(SPIRE_DIR)/join.token

export TMPDIR := $(TMPDIR)

.PHONY: all deps clean up down test spire

all: test
deps: spire

spire:
	@$(MAKE) -C spire

clean: down
	@$(MAKE) -C spire clean
	@rm -rf $(LOG_DIR)


test: up
	@SPIFFE_ENDPOINT_SOCKET=unix://$(WORKLOAD_API) \
		cargo llvm-cov nextest --no-fail-fast || true
	$(MAKE) down

up: $(AGENT_PID)

$(SERVER_PID): | spire
	@install -d $(LOG_DIR)
	@$(SERVER_BIN) run -expandEnv -config $(SERVER_CONFIG) > $(LOG_DIR)/server.log 2>&1 & \
		echo $$! > $(SERVER_PID)
	@{ \
		s=1; \
		until curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/ready | grep -q 200; do \
			if [ $$s -gt $(TIMEOUT) ]; then \
				echo "timed out waiting for spire server"; \
				break; \
			fi; \
			echo "waiting for spire server..."; \
			((s++)); \
			sleep 1; \
		done; \
	}
	@$(SERVER_BIN) token generate \
		-socketPath $(TMPDIR)/spire-server/private/api.sock \
		-spiffeID spiffe://example.org/testagent \
		> $(SPIRE_DIR)/join.token
	@$(SERVER_BIN) entry create \
		-socketPath $(TMPDIR)/spire-server/private/api.sock \
		-selector "unix:uid:$$(id -u)" \
		-parentID spiffe://example.org/testagent \
		-spiffeID spiffe://example.org/testservice \
		-dns localhost \
		-dns 127.0.0.1
	@echo "SPIRE server started."

$(AGENT_PID): | $(SERVER_PID)
	@$(AGENT_BIN) run \
		-insecureBootstrap \
		-expandEnv \
		-config $(AGENT_CONFIG) \
		-joinToken $$(awk '{print $$2}' $(SPIRE_DIR)/join.token) \
		> $(LOG_DIR)/agent.log 2>&1 & \
		echo $$! > $(AGENT_PID)
	@{ \
		s=1; \
		until curl -s -o /dev/null -w "%{http_code}" http://localhost:8082/ready | grep -q 200; do \
			if [ $$s -gt $(TIMEOUT) ]; then \
				echo "timed out waiting for spire agent"; \
				break; \
			fi; \
			echo "waiting for spire agent..."; \
			((s++)); \
			sleep 1; \
		done; \
	}
	@{ \
		s=1; \
		until $(AGENT_BIN) api fetch -socketPath $(WORKLOAD_API) | grep -q testservice; do \
			if [ $$s -gt $(TIMEOUT) ]; then \
				echo "timed out waiting for spire agent"; \
				break; \
			fi; \
			echo "waiting for spire agent..."; \
			((s++)); \
			sleep 1; \
		done; \
	}
	@echo "SPIRE agent started."


down:
	@[ -f $(SPIRE_DIR)/agent.pid ] && kill $$(cat $(SPIRE_DIR)/agent.pid) || true
	@[ -f $(SPIRE_DIR)/server.pid ] && kill $$(cat $(SPIRE_DIR)/server.pid) || true
	@rm -f $(SPIRE_DIR)/*.pid $(SPIRE_DIR)/*.token
	@rm -rf $(TMPDIR)/spire-server
	@rm -rf $(TMPDIR)/spire-agent
	@echo "SPIRE server and agent stopped."
