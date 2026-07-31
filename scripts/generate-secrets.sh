#!/usr/bin/env bash
# =============================================================================
# UniSOC Sentinel — Secret Generation Script
# =============================================================================
# Generates cryptographically strong secrets for all services and stores them
# in ./secrets/ with restrictive file permissions.
#
# Usage:  bash scripts/generate-secrets.sh
#         (or:  make generate-secrets)
#
# Safe to re-run — existing secrets are preserved with a warning.
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
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
SECRETS_DIR="${PROJECT_ROOT}/secrets"
ENV_FILE="${PROJECT_ROOT}/.env"
ENV_EXAMPLE="${PROJECT_ROOT}/.env.example"

# ---------------------------------------------------------------------------
# Ensure secrets directory exists with tight permissions
# ---------------------------------------------------------------------------
log_section "Preparing secrets directory"

if [[ ! -d "${SECRETS_DIR}" ]]; then
    mkdir -p "${SECRETS_DIR}"
    chmod 700 "${SECRETS_DIR}"
    log_info "Created ${SECRETS_DIR} (chmod 700)"
else
    chmod 700 "${SECRETS_DIR}"
    log_info "Secrets directory already exists: ${SECRETS_DIR}"
fi

# ---------------------------------------------------------------------------
# Helper: write a secret file only if it does not already exist
# ---------------------------------------------------------------------------
write_secret() {
    local name="$1"
    local value="$2"
    local file="${SECRETS_DIR}/${name}"

    if [[ -f "${file}" ]]; then
        log_warn "Secret '${name}' already exists — skipping (delete the file to regenerate)"
        return 0
    fi

    printf '%s' "${value}" > "${file}"
    chmod 600 "${file}"
    log_info "Generated secret: ${name}"
}

# ---------------------------------------------------------------------------
# Generate secrets
# ---------------------------------------------------------------------------
log_section "Generating secrets"

# PostgreSQL password — 32 random bytes, base64 encoded (~43 printable chars)
write_secret "postgres_password" "$(openssl rand -base64 32)"

# Redis password — 32 random bytes, base64 encoded
write_secret "redis_password" "$(openssl rand -base64 32)"

# OpenSearch password — must meet complexity requirements:
#   at least 8 chars, one upper, one lower, one digit, one symbol.
#   Prefix "!Aa1" guarantees those character classes are present.
OPENSEARCH_RAW="$(openssl rand -base64 16)"
write_secret "opensearch_password" "!Aa1${OPENSEARCH_RAW}"

# SMTP password — placeholder (mail provider credentials must be supplied manually)
SMTP_SECRET_FILE="${SECRETS_DIR}/smtp_password"
if [[ -f "${SMTP_SECRET_FILE}" ]]; then
    log_warn "Secret 'smtp_password' already exists — skipping"
else
    printf 'REPLACE_WITH_SMTP_PASSWORD' > "${SMTP_SECRET_FILE}"
    chmod 600 "${SMTP_SECRET_FILE}"
    log_warn "smtp_password written as PLACEHOLDER — edit ${SMTP_SECRET_FILE} with your real SMTP password"
fi

# JWT signing secret — 64 random bytes, base64 encoded (~86 printable chars)
write_secret "jwt_secret" "$(openssl rand -base64 64)"

# ---------------------------------------------------------------------------
# Copy .env.example → .env if .env does not exist
# ---------------------------------------------------------------------------
log_section "Environment file"

if [[ -f "${ENV_FILE}" ]]; then
    log_warn ".env already exists — not overwriting. Review .env.example for any new variables."
else
    if [[ -f "${ENV_EXAMPLE}" ]]; then
        cp "${ENV_EXAMPLE}" "${ENV_FILE}"
        log_info "Copied .env.example → .env"
    else
        log_error ".env.example not found at ${ENV_EXAMPLE}"
        log_error "Please create .env manually from .env.example"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log_section "Summary"

printf "\n"
printf "  %-30s %s\n" "File" "Status"
printf "  %-30s %s\n" "----" "------"

for secret in postgres_password redis_password opensearch_password smtp_password jwt_secret; do
    file="${SECRETS_DIR}/${secret}"
    if [[ -f "${file}" ]]; then
        size=$(wc -c < "${file}")
        printf "  ${GREEN}%-30s${RESET} %s (%d bytes)\n" "${secret}" "OK" "${size}"
    else
        printf "  ${RED}%-30s${RESET} %s\n" "${secret}" "MISSING"
    fi
done

printf "\n"
log_info "Secrets directory: ${SECRETS_DIR}"
log_info "Permissions:       $(stat -c '%a' "${SECRETS_DIR}" 2>/dev/null || stat -f '%A' "${SECRETS_DIR}")"

printf "\n"
printf "${YELLOW}Next steps:${RESET}\n"
printf "  1. Edit ${ENV_FILE} and adjust DOMAIN, SMTP_*, ALERT_RECIPIENTS, etc.\n"
printf "  2. Edit ${SMTP_SECRET_FILE} and replace the placeholder with your SMTP password.\n"
printf "  3. Copy the OpenSearch password to .env:\n"
printf "       OPENSEARCH_INITIAL_ADMIN_PASSWORD=$(cat "${SECRETS_DIR}/opensearch_password")\n"
printf "  4. Run:  make build && make up\n"
printf "\n"
printf "${RED}IMPORTANT: Never commit the secrets/ directory or .env to version control!${RESET}\n"
printf "\n"
