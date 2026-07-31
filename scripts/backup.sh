#!/usr/bin/env bash
# =============================================================================
# UniSOC Sentinel — Backup Script
# =============================================================================
# Creates a timestamped backup of all persistent data:
#   - PostgreSQL database  (pg_dump, gzip)
#   - OpenSearch data      (volume tar, gzip)
#   - Redis RDB snapshot   (BGSAVE + copy)
#
# Usage:  bash scripts/backup.sh
#         (or:  make backup)
#
# Retention: keeps the 7 most recent backup directories.
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
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
BACKUP_BASE="${PROJECT_ROOT}/backups"
TIMESTAMP="$(date +%Y-%m-%d_%H-%M-%S)"
BACKUP_DIR="${BACKUP_BASE}/${TIMESTAMP}"
RETAIN_COUNT=7

COMPOSE="docker compose"
PROJECT_NAME="unisoc-sentinel"
COMPOSE_FILE="${PROJECT_ROOT}/docker-compose.yml"
COMPOSE_CMD="${COMPOSE} -p ${PROJECT_NAME} -f ${COMPOSE_FILE}"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
log_section "Pre-flight checks"

if ! docker info > /dev/null 2>&1; then
    log_error "Docker daemon is not accessible. Is it running?"
    exit 1
fi

# Verify required containers are running
for svc in postgres redis opensearch; do
    status=$(${COMPOSE_CMD} ps --format json "${svc}" 2>/dev/null | \
             python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('State',''))" 2>/dev/null || true)
    if ! ${COMPOSE_CMD} ps "${svc}" 2>/dev/null | grep -q "running\|Up"; then
        log_warn "Service '${svc}' does not appear to be running — backup may be incomplete"
    else
        log_info "Service '${svc}' is running"
    fi
done

# ---------------------------------------------------------------------------
# Create backup directory
# ---------------------------------------------------------------------------
log_section "Creating backup directory"
mkdir -p "${BACKUP_DIR}"
log_info "Backup directory: ${BACKUP_DIR}"

# ---------------------------------------------------------------------------
# PostgreSQL backup
# ---------------------------------------------------------------------------
log_section "Backing up PostgreSQL"

PG_BACKUP="${BACKUP_DIR}/postgres.dump.gz"
log_info "Running pg_dump..."

if ${COMPOSE_CMD} exec -T postgres \
    pg_dump \
    --username=siem \
    --dbname=siem \
    --format=custom \
    --compress=0 \
    --no-password 2>/dev/null | gzip -9 > "${PG_BACKUP}"; then
    PG_SIZE=$(du -sh "${PG_BACKUP}" | cut -f1)
    log_info "PostgreSQL backup: ${PG_BACKUP} (${PG_SIZE})"
else
    log_error "PostgreSQL backup failed"
    rm -f "${PG_BACKUP}"
fi

# ---------------------------------------------------------------------------
# OpenSearch data volume backup
# ---------------------------------------------------------------------------
log_section "Backing up OpenSearch data volume"

OS_BACKUP="${BACKUP_DIR}/opensearch-data.tar.gz"
log_info "Snapshotting opensearch-data volume..."

# Run a temporary container to tar the volume contents
if docker run --rm \
    --volume "${PROJECT_NAME}_opensearch-data:/opensearch-data:ro" \
    --volume "${BACKUP_DIR}:/backup" \
    alpine:3.19 \
    tar czf /backup/opensearch-data.tar.gz -C /opensearch-data . 2>/dev/null; then
    OS_SIZE=$(du -sh "${OS_BACKUP}" | cut -f1)
    log_info "OpenSearch backup: ${OS_BACKUP} (${OS_SIZE})"
else
    log_warn "OpenSearch volume backup failed (volume may not exist yet)"
    rm -f "${OS_BACKUP}"
fi

# ---------------------------------------------------------------------------
# Redis RDB backup
# ---------------------------------------------------------------------------
log_section "Backing up Redis"

REDIS_BACKUP="${BACKUP_DIR}/redis-dump.rdb.gz"
log_info "Triggering Redis BGSAVE..."

# Read Redis password from secret file
REDIS_PASSWORD=""
if ${COMPOSE_CMD} exec -T redis test -f /run/secrets/redis_password 2>/dev/null; then
    REDIS_PASSWORD="$(${COMPOSE_CMD} exec -T redis cat /run/secrets/redis_password 2>/dev/null | tr -d '\n\r')"
fi

# Trigger background save and wait for completion
if [[ -n "${REDIS_PASSWORD}" ]]; then
    ${COMPOSE_CMD} exec -T redis redis-cli -a "${REDIS_PASSWORD}" BGSAVE > /dev/null 2>&1 || true
else
    ${COMPOSE_CMD} exec -T redis redis-cli BGSAVE > /dev/null 2>&1 || true
fi

# Wait up to 30s for BGSAVE to complete
MAX_WAIT=30
WAITED=0
while true; do
    if [[ -n "${REDIS_PASSWORD}" ]]; then
        LASTSAVE_STATUS=$(${COMPOSE_CMD} exec -T redis redis-cli -a "${REDIS_PASSWORD}" \
            LASTSAVE 2>/dev/null | tr -d '\n\r' || echo "0")
    else
        LASTSAVE_STATUS=$(${COMPOSE_CMD} exec -T redis redis-cli LASTSAVE 2>/dev/null | tr -d '\n\r' || echo "0")
    fi

    BGSAVE_STATUS=""
    if [[ -n "${REDIS_PASSWORD}" ]]; then
        BGSAVE_STATUS=$(${COMPOSE_CMD} exec -T redis redis-cli -a "${REDIS_PASSWORD}" \
            INFO persistence 2>/dev/null | grep "rdb_bgsave_in_progress" | cut -d: -f2 | tr -d '\r\n' || echo "0")
    else
        BGSAVE_STATUS=$(${COMPOSE_CMD} exec -T redis redis-cli INFO persistence 2>/dev/null | \
            grep "rdb_bgsave_in_progress" | cut -d: -f2 | tr -d '\r\n' || echo "0")
    fi

    if [[ "${BGSAVE_STATUS}" == "0" ]]; then
        log_info "Redis BGSAVE complete"
        break
    fi

    if [[ ${WAITED} -ge ${MAX_WAIT} ]]; then
        log_warn "Timed out waiting for Redis BGSAVE — proceeding with current RDB"
        break
    fi

    sleep 1
    WAITED=$((WAITED + 1))
done

# Copy the RDB file from the redis-data volume
if docker run --rm \
    --volume "${PROJECT_NAME}_redis-data:/redis-data:ro" \
    --volume "${BACKUP_DIR}:/backup" \
    alpine:3.19 \
    sh -c 'if [ -f /redis-data/dump.rdb ]; then gzip -c /redis-data/dump.rdb > /backup/redis-dump.rdb.gz; else echo "no rdb"; fi' \
    2>/dev/null; then
    if [[ -f "${REDIS_BACKUP}" ]]; then
        REDIS_SIZE=$(du -sh "${REDIS_BACKUP}" | cut -f1)
        log_info "Redis backup: ${REDIS_BACKUP} (${REDIS_SIZE})"
    else
        log_warn "Redis RDB file not found (Redis may not have written a snapshot yet)"
    fi
else
    log_warn "Redis volume backup failed"
fi

# ---------------------------------------------------------------------------
# Write backup manifest
# ---------------------------------------------------------------------------
log_section "Writing manifest"

MANIFEST="${BACKUP_DIR}/manifest.txt"
{
    echo "UniSOC Sentinel Backup Manifest"
    echo "================================"
    echo "Timestamp:    ${TIMESTAMP}"
    echo "Hostname:     $(hostname)"
    echo "Project:      ${PROJECT_NAME}"
    echo ""
    echo "Files:"
    for f in "${BACKUP_DIR}"/*; do
        if [[ -f "${f}" ]]; then
            fname=$(basename "${f}")
            fsize=$(du -sh "${f}" | cut -f1)
            echo "  ${fname}  (${fsize})"
        fi
    done
} > "${MANIFEST}"

log_info "Manifest written: ${MANIFEST}"

# ---------------------------------------------------------------------------
# Enforce retention policy (keep last N backups)
# ---------------------------------------------------------------------------
log_section "Enforcing retention policy (keep last ${RETAIN_COUNT})"

# List backup directories sorted oldest-first, skip the current one
BACKUP_DIRS=()
while IFS= read -r -d '' d; do
    [[ "${d}" != "${BACKUP_DIR}" ]] && BACKUP_DIRS+=("${d}")
done < <(find "${BACKUP_BASE}" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)

TOTAL=${#BACKUP_DIRS[@]}
DELETE_COUNT=$(( TOTAL - RETAIN_COUNT + 1 ))  # +1 because we just added a new one

if [[ ${DELETE_COUNT} -gt 0 ]]; then
    for (( i=0; i<DELETE_COUNT; i++ )); do
        old="${BACKUP_DIRS[$i]}"
        log_warn "Removing old backup: ${old}"
        rm -rf "${old}"
    done
else
    log_info "No old backups to remove (${TOTAL} backups retained)"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_section "Backup Summary"

TOTAL_SIZE=$(du -sh "${BACKUP_DIR}" | cut -f1)
printf "\n"
printf "  ${GREEN}Backup location:${RESET} %s\n" "${BACKUP_DIR}"
printf "  ${GREEN}Total size:${RESET}      %s\n" "${TOTAL_SIZE}"
printf "\n"
printf "  Contents:\n"
for f in "${BACKUP_DIR}"/*; do
    if [[ -f "${f}" ]]; then
        printf "    %s  (%s)\n" "$(basename "${f}")" "$(du -sh "${f}" | cut -f1)"
    fi
done
printf "\n"
log_info "Backup complete."
