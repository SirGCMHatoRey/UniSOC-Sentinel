# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Enterprise UniFi SIEM Platform — production-grade security information and event management system for UniFi Network and UDM/UDM Pro devices. Full specification lives in `prompt.txt` (XML format). Implementation does not yet exist; this repo is at the build phase.

Reference: https://github.com/Ward-Software-Defined-Systems/UniFI-Network-SIEM

## Commands

Once implemented, the primary interface is Docker Compose:

```bash
docker compose up -d          # Start full stack
docker compose down           # Stop all services
docker compose logs -f <svc>  # Tail service logs
docker compose ps             # Health status
```

No build/test commands exist yet — define them as services are implemented.

## Architecture

10 containerized services, all orchestrated via Docker Compose v3.9+:

| Service | Role |
|---|---|
| **siem-core** | Orchestration, correlation engine, event routing |
| **syslog-ingestion** | UDP 514 listener — async, buffered, backpressure-aware |
| **parser-pipeline** | Regex extraction, ECS normalization, GeoIP/TI/MAC enrichment |
| **search-engine** | Full-text indexing, time-series optimization, advanced filtering |
| **dashboard-ui** | WebSocket-driven SPA — dark mode, real-time, mobile-responsive |
| **alerting-engine** | Rule-based alerting with deduplication, throttling, escalation |
| **email-notifier** | SMTP with HTML templates for 7 predefined alert rules |
| **reverse-proxy** | API gateway + TLS termination (Let's Encrypt + self-signed) |
| **tls-manager** | Certificate lifecycle management |
| **monitoring** | Prometheus metrics, container health, pipeline visibility |

### Data Flow

```
UniFi Device → UDP 514 → syslog-ingestion → parser-pipeline (ECS JSON)
  → search-engine (index) → siem-core (correlate) → alerting-engine → email-notifier
                         ↘ dashboard-ui (WebSocket stream)
                         ↘ monitoring (Prometheus scrape)
```

### Log Types Ingested

Firewall, Authentication, VPN, Threat Management, IDS/IPS, DHCP, DNS, Admin Activity, Client Association, Traffic, System Events, WAN Events, Port Events, Wireless Events, Device Adoption.

### Correlation Rules

Brute force detection, rogue device/AP detection, port scan detection, excessive failed logins, VPN anomaly detection, lateral movement indicators, administrative abuse detection.

## Implementation Standards

From `prompt.txt` — these are non-negotiable:

- **Architecture**: Clean Architecture + DDD + SOLID + 12-Factor
- **Security**: TLS everywhere (internal + external), RBAC + API keys + sessions, non-root containers, read-only filesystems where possible, rate limiting, secure headers, secrets management
- **Storage**: 90-day retention, compression, log rotation, index lifecycle management, snapshot backups
- **Quality**: Strong typing, linting, unit + integration tests, security scanning
- **No placeholder logic, no toy examples, no insecure defaults**

## Key Deliverables (Spec-Defined)

When building, produce all of these:
- `docker-compose.yml` with health checks, restart policies, volumes, secrets, internal networking
- `.env.example` with all required environment variables
- Nginx/proxy config with TLS and security headers
- Parser pipeline definitions (regex rules per log type)
- Correlation rule engine
- Email alert HTML templates
- Dashboard component definitions (11 widgets)
- Prometheus scrape configs
- Backup/restore scripts
- README, architecture docs, deployment guide, troubleshooting guide

## Constraints

- **Read spec before implementing**: All decisions should trace to `prompt.txt`. If a requirement is infeasible or contradictory, state it explicitly rather than silently bypassing.
- **No scope creep**: Implement only what is requested or clearly necessary per spec.
- **No over-engineering**: No helpers/abstractions for one-time operations, no error handling for impossible scenarios.

## Agent skills

### Issue tracker

GitHub Issues via `gh` CLI (`SirGCMHatoRey/UniSOC-Sentinel`). See `docs/agents/issue-tracker.md`.

### Triage labels

Default vocabulary — `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context — `CONTEXT.md` + `docs/adr/` at repo root. See `docs/agents/domain.md`.

## Versioning & git (project convention — satisfies spec's "skill or memory")

After a plan/milestone is completed and `corepack pnpm check` passes:
**commit everything** with a Conventional Commit message and bump **SemVer**
(`MAJOR.MINOR.PATCH`); tag releases (`vX.Y.Z`). Foundation milestone = `v0.1.0`.
See `SKILLS.md` for the full workflow.
