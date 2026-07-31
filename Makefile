# =============================================================================
# UniSOC Sentinel — Makefile
# =============================================================================
# Usage:  make <target> [SERVICE=<service_name>]
# Run `make help` (or just `make`) to see all available targets.
# =============================================================================

# Detect operating system for colour support
ifeq ($(OS),Windows_NT)
    DETECTED_OS := Windows
    # Colour codes not universally supported on Windows cmd; use empty strings
    RED    :=
    GREEN  :=
    YELLOW :=
    CYAN   :=
    RESET  :=
else
    DETECTED_OS := $(shell uname -s)
    RED    := \033[0;31m
    GREEN  := \033[0;32m
    YELLOW := \033[1;33m
    CYAN   := \033[0;36m
    RESET  := \033[0m
endif

COMPOSE         := docker compose
COMPOSE_FILE    := docker-compose.yml
PROJECT_NAME    := unisoc-sentinel
BACKUP_DIR      := ./backups
SECRETS_DIR     := ./secrets

# Default service for `make logs` / `make shell` (override with SERVICE=)
SERVICE         ?=

.PHONY: help up down restart build pull logs ps shell \
        backup restore init-secrets generate-secrets \
        reset update-geoip lint

# ---------------------------------------------------------------------------
# Default target — show help
# ---------------------------------------------------------------------------
.DEFAULT_GOAL := help

## help: List all available make targets with descriptions
help:
	@printf "$(CYAN)UniSOC Sentinel — Available Targets$(RESET)\n"
	@printf "$(CYAN)=====================================$(RESET)\n"
	@grep -E '^## [a-zA-Z_-]+:' $(MAKEFILE_LIST) | \
	    awk 'BEGIN {FS = ": "}; {printf "  $(GREEN)%-22s$(RESET) %s\n", $$1, $$2}' | \
	    sed 's/## //'
	@printf "\n$(YELLOW)Examples:$(RESET)\n"
	@printf "  make up\n"
	@printf "  make logs SERVICE=siem-core\n"
	@printf "  make shell SERVICE=postgres\n"
	@printf "  make backup\n"

# ---------------------------------------------------------------------------
# Stack lifecycle
# ---------------------------------------------------------------------------

## up: Start all services in detached mode
up:
	@printf "$(GREEN)Starting UniSOC Sentinel...$(RESET)\n"
	$(COMPOSE) -p $(PROJECT_NAME) -f $(COMPOSE_FILE) up -d --remove-orphans
	@printf "$(GREEN)Stack is up. Run 'make ps' to check status.$(RESET)\n"

## down: Stop and remove all containers (preserves volumes)
down:
	@printf "$(YELLOW)Stopping UniSOC Sentinel...$(RESET)\n"
	$(COMPOSE) -p $(PROJECT_NAME) -f $(COMPOSE_FILE) down
	@printf "$(GREEN)Stack stopped.$(RESET)\n"

## restart: Restart all services (or a single SERVICE=<name>)
restart:
	@if [ -n "$(SERVICE)" ]; then \
	    printf "$(YELLOW)Restarting service: $(SERVICE)$(RESET)\n"; \
	    $(COMPOSE) -p $(PROJECT_NAME) -f $(COMPOSE_FILE) restart $(SERVICE); \
	else \
	    printf "$(YELLOW)Restarting all services...$(RESET)\n"; \
	    $(COMPOSE) -p $(PROJECT_NAME) -f $(COMPOSE_FILE) restart; \
	fi

## build: Build (or rebuild) all custom service images
build:
	@printf "$(GREEN)Building service images...$(RESET)\n"
	$(COMPOSE) -p $(PROJECT_NAME) -f $(COMPOSE_FILE) build --pull
	@printf "$(GREEN)Build complete.$(RESET)\n"

## pull: Pull latest upstream images (redis, postgres, opensearch, etc.)
pull:
	@printf "$(GREEN)Pulling upstream images...$(RESET)\n"
	$(COMPOSE) -p $(PROJECT_NAME) -f $(COMPOSE_FILE) pull --ignore-pull-failures
	@printf "$(GREEN)Pull complete.$(RESET)\n"

# ---------------------------------------------------------------------------
# Observability
# ---------------------------------------------------------------------------

## logs: Stream logs for all services, or SERVICE=<name> for one service
logs:
	@if [ -n "$(SERVICE)" ]; then \
	    $(COMPOSE) -p $(PROJECT_NAME) -f $(COMPOSE_FILE) logs -f --tail=200 $(SERVICE); \
	else \
	    $(COMPOSE) -p $(PROJECT_NAME) -f $(COMPOSE_FILE) logs -f --tail=50; \
	fi

## ps: Show running containers and their health status
ps:
	$(COMPOSE) -p $(PROJECT_NAME) -f $(COMPOSE_FILE) ps

# ---------------------------------------------------------------------------
# Debugging
# ---------------------------------------------------------------------------

## shell: Open a shell in a running container (requires SERVICE=<name>)
shell:
	@if [ -z "$(SERVICE)" ]; then \
	    printf "$(RED)Error: SERVICE is required. Usage: make shell SERVICE=<name>$(RESET)\n"; \
	    exit 1; \
	fi
	$(COMPOSE) -p $(PROJECT_NAME) -f $(COMPOSE_FILE) exec $(SERVICE) sh

# ---------------------------------------------------------------------------
# Backup and restore
# ---------------------------------------------------------------------------

## backup: Backup PostgreSQL, OpenSearch data, and Redis RDB to ./backups/
backup:
	@printf "$(GREEN)Running backup...$(RESET)\n"
	@bash ./scripts/backup.sh
	@printf "$(GREEN)Backup complete.$(RESET)\n"

## restore: Restore from a backup directory (prompts for confirmation)
restore:
	@if [ -z "$(BACKUP_DIR)" ]; then \
	    printf "$(RED)Error: Provide backup path via BACKUP_DIR=./backups/<timestamp>$(RESET)\n"; \
	    exit 1; \
	fi
	@bash ./scripts/restore.sh "$(BACKUP_DIR)"

# ---------------------------------------------------------------------------
# Secrets management
# ---------------------------------------------------------------------------

## init-secrets: Generate all secret files in ./secrets/ (idempotent)
init-secrets:
	@printf "$(GREEN)Initialising secrets...$(RESET)\n"
	@bash ./scripts/generate-secrets.sh
	@printf "$(GREEN)Secrets initialised.$(RESET)\n"

## generate-secrets: Alias for init-secrets
generate-secrets: init-secrets

# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------

## reset: DESTRUCTIVE — remove all containers AND volumes (data loss!)
reset:
	@printf "$(RED)WARNING: This will destroy ALL data including databases!$(RESET)\n"
	@printf "$(RED)Press Ctrl+C within 10 seconds to abort...$(RESET)\n"
	@sleep 10
	$(COMPOSE) -p $(PROJECT_NAME) -f $(COMPOSE_FILE) down -v --remove-orphans
	@printf "$(GREEN)Stack and volumes removed.$(RESET)\n"

## update-geoip: Download/update MaxMind GeoLite2-City database
update-geoip:
	@printf "$(GREEN)Updating GeoIP database...$(RESET)\n"
	@if [ -z "$${MAXMIND_LICENSE_KEY:-}" ] && [ -f .env ]; then \
	    export $$(grep -v '^#' .env | xargs); \
	fi; \
	if [ -z "$${MAXMIND_LICENSE_KEY:-}" ]; then \
	    printf "$(RED)Error: MAXMIND_LICENSE_KEY not set in .env$(RESET)\n"; \
	    exit 1; \
	fi; \
	$(COMPOSE) -p $(PROJECT_NAME) -f $(COMPOSE_FILE) \
	    run --rm parser-pipeline \
	    python -m geoip_updater
	@printf "$(GREEN)GeoIP update complete.$(RESET)\n"

## lint: Validate docker-compose.yml syntax and configuration
lint:
	@printf "$(GREEN)Linting docker-compose.yml...$(RESET)\n"
	$(COMPOSE) -f $(COMPOSE_FILE) config --quiet
	@printf "$(GREEN)docker-compose.yml is valid.$(RESET)\n"
	@if command -v yamllint >/dev/null 2>&1; then \
	    printf "$(GREEN)Running yamllint on config files...$(RESET)\n"; \
	    yamllint -d relaxed docker-compose.yml config/; \
	else \
	    printf "$(YELLOW)yamllint not installed — skipping YAML linting.$(RESET)\n"; \
	fi
