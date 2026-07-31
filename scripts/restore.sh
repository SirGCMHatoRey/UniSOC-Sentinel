#!/usr/bin/env bash
# =============================================================================
# UniSOC Sentinel — Restore Script
# =============================================================================
# Restores a backup created by scripts/backup.sh.
#
# Usage:  bash scripts/restore.sh <backup_directory>
#
# Example:
#   bash scripts/restore.sh ./backups/2026-05-21_02-00-00
#
# WARNING: This will OVERWRITE existing PostgreSQL, OpenSearch, and Redis data.
#          Stop the stack before restoring, or this script will do it for you.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

log_info()    { printf "${GREEN}[INFO]${RESET}  %s\n" "$*"; }
log_warn()    { printf "${YELLOW}[WARN]${RESET}  %s\n" "$*"; }
log_error()   { printf "${RED}[ERROR]${RESET} %s\n" "$*" >&2; }
log_section() { printf "\n${CYAN}--- %s ---${RESET}\n" "$*"; }

# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------
if [[ $# -lt 1 ]]; then
    log_error "Usage: $0 <backup_directory>"
    log_error "Example: $0 ./backups/2026-05-21_02-00-00"
    exit 1
fi

BACKUP_DIR="$(realpath "$1")"

if [[ ! -d "${BACKUP_DIR}" ]]; then
    log_error "Backup directory not found: ${BACKUP_DIR}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
PROJECT_NAME="unisoc-sentinel"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"
COMPOSE_CMD="docker compose -p ${PROJECT_NAME} -f ${COMPOSE_FILE}"

# ---------------------------------------------------------------------------
# Show backup contents and confirm
# ---------------------------------------------------------------------------
log_section "Backup to restore"

printf "\n"
printf "  ${CYAN}Backup directory:${RESET} %s\n" "${BACKUP_DIR}"
printf "\n"
printf "  Contents:\n"
for f in "${BACKUP_DIR}"/*; do
    if [[ -f "${f}" ]]; then
        printf "    %s  (%s)\n" "$(basename "${f}")" "$(du -sh "${f}" | cut -f1)"
    fi
done
printf "\n"

# Show manifest if it exists
if [[ -f "${BACKUP_DIR}/manifest.txt" ]]; then
    printf "  ${CYAN}Manifest:${RESET}\n"
    sed 's/^/    /' "${BACKUP_DIR}/manifest.txt"
    printf "\n"
fi

printf "${RED}WARNING: This will OVERWRITE existing data:${RESET}\n"
printf "  - PostgreSQL database 'siem'\n"
printf "  - OpenSearch data volume\n"
printf "  - Redis data volume\n"
printf "\n"
printf "${YELLOW}Are you sure you want to continue? Type 'yes' to proceed: ${RESET}"
read -r CONFIRM

if [[ "${CONFIRM}" != "yes" ]]; then
    log_info "Restore aborted."
    exit 0
fi

# ---------------------------------------------------------------------------
# Stop the stack (except data stores)
# ---------------------------------------------------------------------------
log_section "Stopping application services"

for svc in siem-core alerting-engine parser-pipeline syslog-ingestion \
           email-notifier dashboard-ui reverse-proxy prometheus grafana; do
    if ${COMPOSE_CMD} ps "${svc}" 2>/dev/null | grep -q "running\|Up"; then
        log_info "Stopping ${svc}..."
        ${COMPOSE_CMD} stop "${svc}" 2>/dev/null || true
    fi
done

# ---------------------------------------------------------------------------
# Restore PostgreSQL
# ---------------------------------------------------------------------------
log_section "Restoring PostgreSQL"

PG_BACKUP="${BACKUP_DIR}/postgres.dump.gz"

if [[ -f "${PG_BACKUP}" ]]; then
    log_info "Found PostgreSQL backup: ${PG_BACKUP}"

    # Ensure postgres is running
    if ! ${COMPOSE_CMD} ps postgres 2>/dev/null | grep -q "running\|Up"; then
        log_info "Starting postgres..."
        ${COMPOSE_CMD} up -d postgres
        log_info "Waiting for postgres to become healthy..."
        for i in $(seq 1 30); do
            if ${COMPOSE_CMD} exec -T postgres pg_isready -U siem -d siem > /dev/null 2>&1; then
                break
            fi
            sleep 2
        done
    fi

    log_info "Dropping and recreating database schema..."
    ${COMPOSE_CMD} exec -T postgres \
        psql --username=siem --dbname=postgres \
        -c "DROP DATABASE IF EXISTS siem;" \
        -c "CREATE DATABASE siem OWNER siem;" \
        > /dev/null 2>&1

    log_info "Restoring from dump..."
    zcat "${PG_BACKUP}" | ${COMPOSE_CMD} exec -T postgres \
        pg_restore \
        --username=siem \
        --dbname=siem \
        --no-owner \
        --no-privileges \
        --single-transaction \
        2>/dev/null || {
            log_warn "pg_restore exited with non-zero status — some objects may not have been restored cleanly"
        }

    log_info "PostgreSQL restore complete"
else
    log_warn "No PostgreSQL backup found at ${PG_BACKUP} — skipping"
fi

# ---------------------------------------------------------------------------
# Restore OpenSearch data volume
# ---------------------------------------------------------------------------
log_section "Restoring OpenSearch data"

OS_BACKUP="${BACKUP_DIR}/opensearch-data.tar.gz"

if [[ -f "${OS_BACKUP}" ]]; then
    log_info "Found OpenSearch backup: ${OS_BACKUP}"

    # Stop opensearch before restoring volume data
    log_info "Stopping opensearch..."
    ${COMPOSE_CMD} stop opensearch 2>/dev/null || true

    log_info "Clearing and restoring opensearch-data volume..."
    docker run --rm \
        --volume "${PROJECT_NAME}_opensearch-data:/opensearch-data" \
        --volume "${BACKUP_DIR}:/backup:ro" \
        alpine:3.19 \
        sh -c 'rm -rf /opensearch-data/* && tar xzf /backup/opensearch-data.tar.gz -C /opensearch-data'

    log_info "OpenSearch data restore complete"
    log_info "Starting opensearch..."
    ${COMPOSE_CMD} up -d opensearch
else
    log_warn "No OpenSearch backup found at ${OS_BACKUP} — skipping"
fi

# ---------------------------------------------------------------------------
# Restore Redis
# ---------------------------------------------------------------------------
log_section "Restoring Redis"

REDIS_BACKUP="${BACKUP_DIR}/redis-dump.rdb.gz"

if [[ -f "${REDIS_BACKUP}" ]]; then
    log_info "Found Redis backup: ${REDIS_BACKUP}"

    log_info "Stopping redis..."
    ${COMPOSE_CMD} stop redis 2>/dev/null || true

    log_info "Restoring redis-data volume..."
    docker run --rm \
        --volume "${PROJECT_NAME}_redis-data:/redis-data" \
        --volume "${BACKUP_DIR}:/backup:ro" \
        alpine:3.19 \
        sh -c 'zcat /backup/redis-dump.rdb.gz > /redis-data/dump.rdb && chmod 644 /redis-data/dump.rdb'

    log_info "Redis data restore complete"
    log_info "Starting redis..."
    ${COMPOSE_CMD} up -d redis
else
    log_warn "No Redis backup found at ${REDIS_BACKUP} — skipping"
fi

# ---------------------------------------------------------------------------
# Restart the full stack
# ---------------------------------------------------------------------------
log_section "Starting full stack"

log_info "Bringing up all services..."
${COMPOSE_CMD} up -d

printf "\n"
log_info "Waiting 30 seconds for services to stabilise..."
sleep 30

${COMPOSE_CMD} ps

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_section "Restore Complete"
printf "\n"
log_info "Restored from: ${BACKUP_DIR}"
log_info "Run 'make logs' to verify all services are healthy."
printf "\n"
