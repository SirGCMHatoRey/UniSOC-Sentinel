# UniSOC Sentinel — Enterprise UniFi SIEM Platform

A production-grade Security Information and Event Management (SIEM) platform
purpose-built for UniFi networks. UniSOC Sentinel ingests syslog data from
UniFi hardware, normalises and enriches events, detects threats using
configurable alert rules, and presents everything through a unified dashboard.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Quick Start](#quick-start)
5. [UniFi Configuration](#unifi-configuration)
6. [Configuration Reference](#configuration-reference)
7. [TLS Options](#tls-options)
8. [Backup and Restore](#backup-and-restore)
9. [Monitoring](#monitoring)
10. [Troubleshooting](#troubleshooting)
11. [Security Notes](#security-notes)

---

## Overview

UniSOC Sentinel is a self-hosted, containerised SIEM stack composed of purpose-
built microservices. Each service has a single responsibility and communicates
over defined Redis streams and REST APIs. The entire stack runs via Docker
Compose and is designed to be deployed on a single host (minimum 4 GB RAM,
2 vCPUs) with optional multi-node expansion.

**Key capabilities:**

- Real-time syslog ingestion from UniFi controllers and devices over UDP 514
- ECS-normalised log parsing with GeoIP enrichment and threat-intelligence lookup
- Rule-based alerting with deduplication, throttling, and email delivery
- Full-text log search backed by OpenSearch
- REST API and live WebSocket feed for dashboard integration
- Prometheus metrics and Grafana dashboards for operational visibility
- JWT-authenticated multi-role user management (admin / analyst / viewer)

---

## Architecture

```
 ┌─────────────────────────────────────────────────────────────────────┐
 │  UniFi Network                                                      │
 │  Controller / APs / Switches / Gateways                             │
 └───────────────────────────┬─────────────────────────────────────────┘
                             │ UDP 514 (syslog)
                             ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │  syslog-ingestion                                                   │
 │  Receives raw syslog frames → publishes to Redis stream             │
 │  Stream: siem:raw_logs                                              │
 └───────────────────────────┬─────────────────────────────────────────┘
                             │ Redis XADD
                             ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │  parser-pipeline                                                    │
 │  Reads siem:raw_logs (consumer group: siem-parsers)                 │
 │  Normalises → ECS fields                                            │
 │  Enriches  → GeoIP, threat-intel feeds                              │
 │  Indexes   → OpenSearch  (siem-logs-YYYY.MM.DD)                     │
 │  Publishes → siem:parsed_logs                                       │
 └──────────────┬────────────────────────────┬────────────────────────┘
                │ Redis XADD                  │ HTTP bulk index
                ▼                             ▼
 ┌──────────────────────────┐   ┌──────────────────────────────────────┐
 │  alerting-engine         │   │  OpenSearch                          │
 │  Reads siem:parsed_logs  │   │  Indices: siem-logs-*, siem-alerts   │
 │  (group: siem-alerting)  │   │  Full-text search + aggregations     │
 │  Evaluates alert rules   │   └──────────────────┬───────────────────┘
 │  Deduplicates via Redis  │                      │ REST /api/v1/
 │  Stores → PostgreSQL     │                      │
 │  Publishes alert events  │                      │
 │  → siem:alert_notific.   │                      │
 └────────┬─────────────────┘                      │
          │ Redis PUBLISH                           │
          ▼                                        │
 ┌──────────────────────────┐                      │
 │  email-notifier          │                      │
 │  Subscribes to           │                      │
 │  siem:alert_notifications│                      │
 │  Sends SMTP emails       │                      │
 └──────────────────────────┘                      │
                                                   │
 ┌─────────────────────────────────────────────────▼───────────────────┐
 │  siem-core  (FastAPI)                                               │
 │  REST API prefix: /api/v1/                                          │
 │  WebSocket: /ws/live  (pub: siem:live_stream)                       │
 │  Auth: JWT + API keys     DB: PostgreSQL                            │
 └───────────────────────────┬─────────────────────────────────────────┘
                             │ HTTP upstream
                             ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │  reverse-proxy  (nginx)                                             │
 │  /api/  → siem-core:8000      /ws/  → siem-core:8000               │
 │  /grafana/ → grafana:3000     /    → dashboard-ui:3000             │
 │  TLS termination (self-signed or Let's Encrypt)                     │
 └──────────┬───────────────────────────────────────────────────────┬──┘
            │ TCP 80 / 443                                          │
            ▼                                                       ▼
      Browser (Dashboard)                                     Grafana UI
```

### Data stores

| Store       | Purpose                                  | Default port |
|-------------|------------------------------------------|:------------:|
| Redis       | Log streams, pub/sub, dedup cache        | 6379         |
| PostgreSQL  | Users, sessions, API keys, alerts, audit | 5432         |
| OpenSearch  | Log index (siem-logs-*), alert index     | 9200         |

### Monitoring stack

| Service    | Role                              | Default port |
|------------|-----------------------------------|:------------:|
| Prometheus | Scrapes /metrics from all services| 9090         |
| Grafana    | Dashboards served at /grafana/    | 3000 (internal) |

---

## Prerequisites

| Requirement | Minimum | Notes |
|---|---|---|
| Docker Engine | 24.0+ | `docker --version` |
| Docker Compose Plugin | v2.20+ | `docker compose version` |
| RAM | 4 GB | 8 GB recommended for production |
| CPU | 2 vCPUs | 4+ recommended |
| Disk | 20 GB | For logs, metrics, and backups |
| OS | Linux (amd64) | Ubuntu 22.04 LTS or Debian 12 recommended |
| `openssl` | any | Required for secret generation |
| `curl` / `bash` | any | Required for scripts |

> **Note for Windows users:** Run Docker Desktop with WSL 2 backend. Execute
> shell scripts (`generate-secrets.sh`, `backup.sh`) inside WSL or Git Bash.

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/your-org/unisoc-sentinel.git
cd unisoc-sentinel
```

### 2. Generate secrets

```bash
bash scripts/generate-secrets.sh
# or
make generate-secrets
```

This creates `./secrets/` containing:
- `postgres_password` — PostgreSQL siem user password
- `redis_password` — Redis authentication password
- `opensearch_password` — OpenSearch admin password
- `smtp_password` — SMTP authentication (placeholder, edit manually)
- `jwt_secret` — 64-byte JWT signing secret

### 3. Configure the environment

```bash
# .env was copied from .env.example by generate-secrets.sh
# Edit the values relevant to your deployment:
nano .env
```

At minimum, review and adjust:

| Variable | Action required |
|---|---|
| `DOMAIN` | Set to your server FQDN or IP |
| `TLS_MODE` | `self-signed` (lab) or `letsencrypt` (production) |
| `LETSENCRYPT_EMAIL` | Required when `TLS_MODE=letsencrypt` |
| `OPENSEARCH_INITIAL_ADMIN_PASSWORD` | Change from the default |
| `SMTP_HOST`, `SMTP_USER`, `SMTP_PORT` | Set for email delivery |
| `ALERT_RECIPIENTS` | Comma-separated notification recipients |
| `GRAFANA_ADMIN_PASSWORD` | Change from the default |

### 4. Build and start the stack

```bash
# Build custom images and start all services:
make build
make up

# Watch startup progress:
make logs
```

Allow up to 2 minutes for OpenSearch to become healthy on first boot.

### 5. Verify the stack

```bash
make ps
```

All services should show `healthy` or `running`. Then open:

- Dashboard: `https://<DOMAIN>/`
- Grafana: `https://<DOMAIN>/grafana/`
- API health: `https://<DOMAIN>/api/v1/health`

Default admin credentials: `admin` / `ChangeMe123!`
**Change this immediately** via the dashboard or the API.

---

## UniFi Configuration

Point your UniFi devices to send syslog to the host running UniSOC Sentinel.

### UniFi Network Application (Controller)

1. Log in to the UniFi Network Application.
2. Navigate to **Settings → System → Advanced**.
3. Enable **Remote Syslog Server**.
4. Set **Server IP** to the IP address of your UniSOC Sentinel host.
5. Set **Port** to `514`.
6. Set **Protocol** to `UDP`.
7. Click **Apply Changes**.

### Legacy UniFi Security Gateway (USG)

SSH into the USG and run:

```bash
configure
set system syslog host <SENTINEL_HOST_IP> facility all level info
commit
save
exit
```

### UniFi Dream Machine (UDM / UDM-Pro / UDM-SE)

In the UniFi OS settings:

1. Navigate to **Console Settings → Notifications → Remote Syslog**.
2. Enter the host IP and port `514`.

### Firewall considerations

Ensure UDP port 514 is open between your UniFi devices and the host:

```bash
# Linux example (ufw):
sudo ufw allow 514/udp comment "UniSOC Sentinel syslog"
```

---

## Configuration Reference

All configuration is done via the `.env` file. See `.env.example` for full
documentation of every variable.

### Critical variables

| Variable | Default | Description |
|---|---|---|
| `DOMAIN` | `localhost` | Public FQDN for TLS certificate and nginx vhost |
| `TLS_MODE` | `self-signed` | Certificate mode: `self-signed` or `letsencrypt` |
| `OPENSEARCH_INITIAL_ADMIN_PASSWORD` | `ChangeMe_1234!` | OpenSearch admin password |
| `LOG_LEVEL` | `INFO` | Global log verbosity for Python services |
| `CORS_ORIGINS` | `http://localhost,...` | Allowed CORS origins for the API |

### Scaling variables

| Variable | Default | Description |
|---|---|---|
| `SYSLOG_WORKERS` | `4` | Async workers in the syslog ingestion service |
| `SYSLOG_BUFFER_SIZE` | `10000` | In-memory queue depth for incoming frames |
| `PARSER_WORKERS` | `2` | Concurrent parser coroutines |
| `PARSER_BATCH_SIZE` | `100` | Redis XREADGROUP batch size |
| `SIEM_CORE_WORKERS` | `4` | Uvicorn worker processes |

### Alert rules

Alert rules are defined in `config/alert-rules/alert-rules.yml`. The file is
mounted read-only into the `alerting-engine` container. After editing, restart
the alerting engine:

```bash
make restart SERVICE=alerting-engine
```

See `config/alert-rules/alert-rules.yml` for the full rule schema.

### Threat intelligence feeds

Feed configuration lives in `config/threat-intel/feeds.yml`. The parser
pipeline automatically refreshes feeds according to `update_interval_hours`.

---

## TLS Options

### Self-signed (development / lab)

Set `TLS_MODE=self-signed` in `.env`. The `tls-manager` service generates a
self-signed certificate on first boot and stores it in the `tls-certs` volume.
Browsers will show a security warning — add an exception or trust the CA.

### Let's Encrypt (production)

Requirements:
- `DOMAIN` must resolve publicly to the host's IP
- Port `80` must be reachable from the internet (for ACME HTTP-01 challenge)
- A valid email address in `LETSENCRYPT_EMAIL`

Set `TLS_MODE=letsencrypt` in `.env` and start the stack. The `tls-manager`
service will obtain and cache the certificate automatically.

Certificate renewal is handled by the `tls-manager` service on each restart.
To trigger renewal manually:

```bash
docker compose restart tls-manager
docker compose restart reverse-proxy
```

---

## Backup and Restore

### Create a backup

```bash
make backup
```

Backs up:
- PostgreSQL database (pg_dump, compressed)
- OpenSearch data volume (tar.gz)
- Redis RDB snapshot

Backups are written to `./backups/YYYY-MM-DD_HH-MM-SS/` and the seven most
recent backups are retained (older ones are deleted automatically).

### Schedule automatic backups (cron)

```cron
# Run backup daily at 02:00
0 2 * * * cd /opt/unisoc-sentinel && bash scripts/backup.sh >> /var/log/sentinel-backup.log 2>&1
```

### Restore from a backup

```bash
bash scripts/restore.sh ./backups/2026-05-21_02-00-00
```

You will be prompted to confirm before any data is overwritten.

---

## Monitoring

### Prometheus

Prometheus is configured to scrape `/metrics` from each service.
Configuration: `services/monitoring/prometheus/prometheus.yml`

Access Prometheus directly (internal only, no public exposure):

```bash
docker compose exec prometheus wget -qO- http://localhost:9090/api/v1/targets
```

### Grafana

Access Grafana at `https://<DOMAIN>/grafana/`.
Default credentials: configured via `GRAFANA_ADMIN_USER` / `GRAFANA_ADMIN_PASSWORD`.

Pre-built dashboards are provisioned from `services/monitoring/grafana/dashboards/`.
Data sources are provisioned from `services/monitoring/grafana/provisioning/`.

---

## Troubleshooting

### Container not starting / unhealthy

```bash
# View logs for a specific service:
make logs SERVICE=opensearch

# Inspect the last 100 lines:
docker compose logs --tail=100 opensearch
```

### OpenSearch takes too long to become healthy

OpenSearch can take 60–90 seconds on first boot while it generates TLS
certificates and initialises the cluster. Wait for the `start_period` to
elapse before diagnosing. Check logs:

```bash
make logs SERVICE=opensearch
```

If `bootstrap.memory_lock` fails, increase the host's `vm.max_map_count`:

```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### No logs appearing in OpenSearch

1. Confirm your UniFi device is sending syslog to the host IP on UDP 514.
2. Verify `syslog-ingestion` is healthy: `make ps`.
3. Check for Redis connectivity: `make logs SERVICE=syslog-ingestion`.
4. Verify `parser-pipeline` is consuming: `make logs SERVICE=parser-pipeline`.

### Alerts not being sent

1. Check `alerting-engine` logs: `make logs SERVICE=alerting-engine`.
2. Check `email-notifier` logs: `make logs SERVICE=email-notifier`.
3. Verify SMTP credentials: `cat secrets/smtp_password`.
4. Test SMTP connectivity:

```bash
docker compose exec email-notifier python -c \
  "import smtplib; s = smtplib.SMTP('$SMTP_HOST', $SMTP_PORT); print(s.ehlo())"
```

### Reset everything and start fresh

```bash
make reset   # WARNING: destroys all data
make generate-secrets
make build
make up
```

---

## Security Notes

1. **Secrets** — All passwords and keys are stored in `./secrets/` files, never
   in environment variables or docker-compose.yml. The `secrets/` directory is
   excluded from git via `.gitignore`. Permissions are set to `600`.

2. **Non-root containers** — All custom services run as UID 1000 (or the
   appropriate service UID). Privilege escalation is blocked via
   `no-new-privileges:true`.

3. **Read-only filesystems** — Where practical, containers run with
   `read_only: true` and writable `/tmp` mounted as tmpfs.

4. **Capability dropping** — Custom services drop ALL Linux capabilities and
   only add back what is strictly needed (`NET_BIND_SERVICE` for the syslog
   listener on port 514).

5. **Network isolation** — All services communicate on the internal
   `siem-internal` Docker network. Only `reverse-proxy` and `grafana` are
   attached to the public-facing `siem-public` network.

6. **Default passwords** — Change `OPENSEARCH_INITIAL_ADMIN_PASSWORD`,
   `GRAFANA_ADMIN_PASSWORD`, and the default `admin` database user password
   (`ChangeMe123!`) before connecting to a production network.

7. **TLS** — Use `TLS_MODE=letsencrypt` in production. The self-signed mode
   is suitable only for internal lab environments.

8. **Audit logging** — All API actions are written to the `audit_log` table
   in PostgreSQL with user identity, IP address, and timestamp.
