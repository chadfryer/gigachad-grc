# GigaChad GRC - Configuration Reference

## Table of Contents

1. [Environment Variables](#environment-variables)
2. [Module Configuration](#module-configuration)
3. [Service Configuration](#service-configuration)
4. [Traefik Configuration](#traefik-configuration)
5. [Database Configuration](#database-configuration)
6. [Redis Configuration](#redis-configuration)
7. [Keycloak Configuration](#keycloak-configuration)
8. [RustFS Configuration](#rustfs-configuration)
9. [Security Configuration](#security-configuration)
10. [Monitoring Configuration](#monitoring-configuration)

---

## Module Configuration

GigaChad GRC is modular - you can enable/disable platform modules based on your needs.

You can configure modules in two layers:

- **Deployment defaults** via frontend environment variables (`VITE_ENABLE_*_MODULE`)
- **Per-organization** overrides via the **Module Configuration** page in the UI (Settings → Module Configuration)

**See [MODULE_CONFIGURATION.md](./MODULE_CONFIGURATION.md) for complete documentation including:**
- Available modules and their features
- Configuration presets (Full Platform, Core GRC, Compliance Only, etc.)
- Step-by-step configuration guide
- Module dependencies and best practices

### Quick Reference

| Module | Env Variable | Default |
|--------|--------------|---------|
| Compliance | `VITE_ENABLE_COMPLIANCE_MODULE` | `true` |
| Data | `VITE_ENABLE_DATA_MODULE` | `true` |
| Risk | `VITE_ENABLE_RISK_MODULE` | `true` |
| TPRM | `VITE_ENABLE_TPRM_MODULE` | `true` |
| BC/DR | `VITE_ENABLE_BCDR_MODULE` | `true` |
| Audit | `VITE_ENABLE_AUDIT_MODULE` | `true` |
| Trust | `VITE_ENABLE_TRUST_MODULE` | `true` |
| People | `VITE_ENABLE_PEOPLE_MODULE` | `true` |
| AI | `VITE_ENABLE_AI_MODULE` | `false` |
| Tools | `VITE_ENABLE_TOOLS_MODULE` | `true` |

> **Note:** If an organization has a saved module configuration, it takes precedence
> over the defaults above for that organization.

---

## Environment Variables

### Quick Reference

Copy `deploy/env.example` to `.env` and configure:

```bash
cp deploy/env.example .env
chmod 600 .env  # Restrict permissions
```

### Complete Variable Reference

#### General Settings

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NODE_ENV` | Yes | `development` | Environment: `development`, `staging`, `production` |
| `APP_DOMAIN` | Yes | `localhost` | Application domain (without protocol) |
| `LOG_LEVEL` | No | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `TZ` | No | `UTC` | Timezone for the application |
| `IMAGE_TAG` | No | `latest` | Docker image tag for deployments |

#### Database (PostgreSQL)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTGRES_USER` | Yes | `grc` | Database username |
| `POSTGRES_PASSWORD` | Yes | - | Database password (min 16 chars recommended) |
| `POSTGRES_DB` | Yes | `gigachad_grc` | Database name |
| `DATABASE_URL` | Auto | - | Full connection string (auto-generated) |
| `DATABASE_POOL_MIN` | No | `5` | Minimum pool connections |
| `DATABASE_POOL_MAX` | No | `20` | Maximum pool connections |

**Connection String Format**:
```
postgresql://USER:PASSWORD@HOST:PORT/DATABASE
```

#### Cache (Redis)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REDIS_PASSWORD` | Yes | - | Redis password |
| `REDIS_URL` | Auto | - | Full Redis URL (auto-generated) |
| `REDIS_MAX_MEMORY` | No | `512mb` | Maximum memory allocation |
| `REDIS_LOG_LEVEL` | No | `warning` | Log level: `debug`, `verbose`, `notice`, `warning` |

**URL Format**:
```
redis://:PASSWORD@HOST:PORT
```

#### Authentication (Keycloak)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KEYCLOAK_ADMIN` | Yes | `admin` | Admin username |
| `KEYCLOAK_ADMIN_PASSWORD` | Yes | - | Admin password |
| `KEYCLOAK_HOSTNAME` | Yes | - | Keycloak hostname (e.g., `auth.grc.example.com`) |
| `KEYCLOAK_REALM` | Yes | `gigachad-grc` | Realm name |
| `KC_DB_POOL_INITIAL_SIZE` | No | `5` | Initial DB pool size |
| `KC_DB_POOL_MIN_SIZE` | No | `5` | Minimum DB pool size |
| `KC_DB_POOL_MAX_SIZE` | No | `20` | Maximum DB pool size |
| `KC_LOG_LEVEL` | No | `info` | Keycloak log level |

#### Object Storage (RustFS/S3-Compatible)

RustFS is a high-performance, S3-compatible object storage.
See: https://github.com/rustfs/rustfs

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MINIO_ROOT_USER` | Yes | `rustfsadmin` | RustFS/S3 root username |
| `MINIO_ROOT_PASSWORD` | Yes | - | RustFS/S3 root password |
| `MINIO_BROWSER` | No | `on` | Enable web console (`on`/`off`) |
| `MINIO_DOMAIN` | No | - | RustFS domain (e.g., `storage.grc.example.com`) |

#### Security

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET` | Yes | - | JWT signing secret (min 64 chars) |
| `CORS_ORIGINS` | No | - | Allowed CORS origins (comma-separated) |

**Generate JWT Secret**:
```bash
openssl rand -base64 64 | tr -d '\n'
```

#### Rate Limiting

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RATE_LIMIT_ENABLED` | No | `true` | Enable rate limiting |
| `RATE_LIMIT_MAX` | No | `100` | Max requests per window |
| `RATE_LIMIT_WINDOW_MS` | No | `60000` | Window duration (ms) |

#### TLS/SSL (Let's Encrypt)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ACME_EMAIL` | Yes | - | Email for certificate notifications |

#### API Gateway (Traefik)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TRAEFIK_LOG_LEVEL` | No | `WARN` | Log level: `DEBUG`, `INFO`, `WARN`, `ERROR` |

#### Email/SMTP (Optional)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SMTP_HOST` | No | - | SMTP server hostname |
| `SMTP_PORT` | No | `587` | SMTP port |
| `SMTP_USER` | No | - | SMTP username |
| `SMTP_PASSWORD` | No | - | SMTP password |
| `SMTP_FROM` | No | - | From address |
| `SMTP_SECURE` | No | `true` | Use TLS |

#### Monitoring (Optional)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `METRICS_ENABLED` | No | `false` | Enable Prometheus metrics |
| `METRICS_PORT` | No | `9090` | Metrics port |
| `SENTRY_DSN` | No | - | Sentry error tracking DSN |

#### AI Configuration (Optional)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AI_PROVIDER` | No | `disabled` | AI provider: `openai`, `anthropic`, `disabled` |
| `OPENAI_API_KEY` | No | - | OpenAI API key (starts with `sk-`) |
| `OPENAI_MODEL` | No | `gpt-5` | OpenAI model: `gpt-5`, `gpt-5-mini`, `o3`, `o3-mini`, `gpt-4o` |
| `ANTHROPIC_API_KEY` | No | - | Anthropic API key (starts with `sk-ant-`) |
| `ANTHROPIC_MODEL` | No | `claude-opus-4-5-20250514` | Anthropic model: `claude-opus-4-5-20250514`, `claude-sonnet-4-20250514`, `claude-3-5-sonnet-20241022`, `claude-3-5-haiku-20241022` |
| `AI_TEMPERATURE` | No | `0.3` | AI response temperature (0-2) |
| `AI_MAX_TOKENS` | No | `4096` | Maximum tokens for AI responses |

**AI Features** (enable/disable in UI at Settings → AI Configuration):
- Risk Scoring - AI-suggested risk likelihood and impact
- Auto-Categorization - Automatic categorization and tagging
- Smart Search - Natural language search across all modules
- Policy Drafting - Generate policy drafts from requirements
- Control Suggestions - Recommend controls for risks

#### MCP Server Configuration (Optional)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MCP_ENABLED` | No | `false` | Enable MCP server integration |
| `MCP_EVIDENCE_SERVER` | No | - | Path to GRC Evidence Collection MCP server |
| `MCP_COMPLIANCE_SERVER` | No | - | Path to GRC Compliance Automation MCP server |
| `MCP_AI_ASSISTANT_SERVER` | No | - | Path to GRC AI Assistant MCP server |
| `GITHUB_TOKEN` | No | - | GitHub token for MCP GitHub evidence collection |
| `OKTA_ORG_URL` | No | - | Okta org URL for MCP Okta evidence collection |
| `OKTA_API_TOKEN` | No | - | Okta API token for MCP Okta evidence collection |
| `AZURE_SUBSCRIPTION_ID` | No | - | Azure subscription ID for MCP Azure evidence |

**MCP Servers Available**:
- **grc-evidence** - Automated evidence collection from AWS, Azure, GitHub, Okta, Google Workspace, Jamf
- **grc-compliance** - Compliance automation for SOC 2, ISO 27001, HIPAA, GDPR checks
- **grc-ai-assistant** - AI-powered risk analysis, control suggestions, policy drafting

#### Backup Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BACKUP_RETENTION_DAYS` | No | `30` | Backup retention period |
| `BACKUP_S3_BUCKET` | No | - | S3 bucket for backups |
| `BACKUP_S3_REGION` | No | - | S3 region |
| `BACKUP_S3_ACCESS_KEY` | No | - | S3 access key |
| `BACKUP_S3_SECRET_KEY` | No | - | S3 secret key |

---

## Service Configuration

### Controls Service (Port 3001)

```yaml
environment:
  NODE_ENV: production
  PORT: 3001
  DATABASE_URL: postgresql://...
  REDIS_URL: redis://...
  MINIO_ENDPOINT: rustfs
  MINIO_PORT: 9000
  MINIO_USE_SSL: false
  MINIO_ACCESS_KEY: ${MINIO_ROOT_USER}
  MINIO_SECRET_KEY: ${MINIO_ROOT_PASSWORD}
  KEYCLOAK_URL: http://keycloak:8080/auth
  KEYCLOAK_REALM: ${KEYCLOAK_REALM}
  JWT_SECRET: ${JWT_SECRET}
  LOG_LEVEL: ${LOG_LEVEL:-info}
  RATE_LIMIT_ENABLED: ${RATE_LIMIT_ENABLED:-true}
  RATE_LIMIT_MAX: ${RATE_LIMIT_MAX:-100}
  RATE_LIMIT_WINDOW_MS: ${RATE_LIMIT_WINDOW_MS:-60000}
```

### All Services Follow Same Pattern

Each service accepts:

| Variable | Description |
|----------|-------------|
| `PORT` | Service port |
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection string |
| `MINIO_*` / `S3_*` | RustFS/S3 storage configuration |
| `KEYCLOAK_*` | Keycloak configuration |
| `JWT_SECRET` | JWT signing secret |
| `LOG_LEVEL` | Logging level |
| `RATE_LIMIT_*` | Rate limiting settings |

---

## Traefik Configuration

### Static Configuration (`gateway/traefik.yml`)

```yaml
# API Dashboard
api:
  dashboard: true
  insecure: false  # Require authentication in production

# Logging
log:
  level: INFO
  format: json
  filePath: /var/log/traefik/traefik.log

accessLog:
  format: json
  filePath: /var/log/traefik/access.log
  bufferingSize: 100
  fields:
    defaultMode: keep
    headers:
      defaultMode: drop
      names:
        User-Agent: keep
        Authorization: drop

# Entry Points
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
  websecure:
    address: ":443"
    http:
      tls:
        certResolver: letsencrypt
    transport:
      respondingTimeouts:
        readTimeout: 60s
        writeTimeout: 60s
        idleTimeout: 120s

# Providers
providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
    network: grc-network
    watch: true
    
  file:
    directory: /etc/traefik/dynamic
    watch: true

# Certificate Resolvers
certificatesResolvers:
  letsencrypt:
    acme:
      email: ${ACME_EMAIL}
      storage: /letsencrypt/acme.json
      httpChallenge:
        entryPoint: web

# Health Check
ping:
  entryPoint: web
  manualRouting: false

# Metrics (optional)
metrics:
  prometheus:
    addEntryPointsLabels: true
    addServicesLabels: true
    buckets:
      - 0.1
      - 0.3
      - 1.2
      - 5.0
```

### Dynamic Configuration (Docker Labels)

```yaml
# Service Labels Template
labels:
  # Enable Traefik
  - "traefik.enable=true"
  
  # Router configuration
  - "traefik.http.routers.${SERVICE}.rule=Host(`${APP_DOMAIN}`) && PathPrefix(`/api/${PATH}`)"
  - "traefik.http.routers.${SERVICE}.entrypoints=websecure"
  - "traefik.http.routers.${SERVICE}.tls.certresolver=letsencrypt"
  
  # Service configuration
  - "traefik.http.services.${SERVICE}.loadbalancer.server.port=${PORT}"
  - "traefik.http.services.${SERVICE}.loadbalancer.healthcheck.path=/health"
  - "traefik.http.services.${SERVICE}.loadbalancer.healthcheck.interval=10s"
  
  # Middleware
  - "traefik.http.middlewares.${SERVICE}-ratelimit.ratelimit.average=100"
  - "traefik.http.middlewares.${SERVICE}-ratelimit.ratelimit.burst=50"
  - "traefik.http.routers.${SERVICE}.middlewares=${SERVICE}-ratelimit"
```

### Security Headers Middleware

```yaml
# Add to dynamic configuration
http:
  middlewares:
    security-headers:
      headers:
        frameDeny: true
        sslRedirect: true
        browserXssFilter: true
        contentTypeNosniff: true
        stsIncludeSubdomains: true
        stsPreload: true
        stsSeconds: 31536000
        customFrameOptionsValue: "SAMEORIGIN"
        referrerPolicy: "strict-origin-when-cross-origin"
        contentSecurityPolicy: "default-src 'self'"
```

---

## Database Configuration

### PostgreSQL Settings

#### `postgresql.conf` Optimizations

```ini
# Memory
shared_buffers = 256MB                # 25% of RAM for dedicated server
effective_cache_size = 768MB          # 75% of RAM
work_mem = 16MB                       # Per-operation memory
maintenance_work_mem = 128MB          # For VACUUM, CREATE INDEX

# Connections
max_connections = 200
superuser_reserved_connections = 3

# WAL
wal_level = replica
max_wal_senders = 3
wal_keep_size = 1GB

# Logging
log_destination = 'stderr'
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d.log'
log_statement = 'ddl'
log_min_duration_statement = 1000     # Log queries > 1s

# Checkpoints
checkpoint_completion_target = 0.9
checkpoint_timeout = 10min

# Autovacuum
autovacuum = on
autovacuum_naptime = 1min
autovacuum_vacuum_threshold = 50
autovacuum_analyze_threshold = 50
```

#### Connection Pooling (PgBouncer)

```ini
[databases]
gigachad_grc = host=postgres port=5432 dbname=gigachad_grc

[pgbouncer]
listen_addr = 0.0.0.0
listen_port = 6432
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
max_client_conn = 1000
default_pool_size = 25
min_pool_size = 5
reserve_pool_size = 5
reserve_pool_timeout = 3
```

---

## Redis Configuration

### `redis.conf`

```conf
# Network
bind 0.0.0.0
port 6379
protected-mode yes
requirepass ${REDIS_PASSWORD}

# Memory
maxmemory 512mb
maxmemory-policy allkeys-lru

# Persistence
appendonly yes
appendfsync everysec
save 900 1
save 300 10
save 60 10000

# Logging
loglevel warning
logfile ""

# Limits
maxclients 10000
timeout 300

# Security
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command DEBUG ""
rename-command CONFIG "CONFIG_SECURE_KEY"
```

---

## Keycloak Configuration

### Realm Configuration

Export current realm:
```bash
docker exec grc-keycloak /opt/keycloak/bin/kc.sh export \
  --dir /tmp/export \
  --realm grc
```

### Client Configuration

```json
{
  "clientId": "grc-frontend",
  "name": "GRC Frontend",
  "enabled": true,
  "publicClient": true,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "redirectUris": [
    "https://grc.example.com/*",
    "http://localhost:3000/*"
  ],
  "webOrigins": [
    "https://grc.example.com",
    "http://localhost:3000"
  ],
  "attributes": {
    "pkce.code.challenge.method": "S256"
  }
}
```

### Role Configuration

| Role | Description | Permissions |
|------|-------------|-------------|
| `admin` | Full access | All resources |
| `compliance_manager` | Manage compliance | Controls, frameworks, policies |
| `risk_manager` | Manage risks | Risks, risk config |
| `auditor` | Audit access | Read all, audit management |
| `vendor_manager` | Manage vendors | Vendors, assessments, contracts |
| `viewer` | Read-only | View all resources |

---

## RustFS Configuration

### Bucket Setup

```bash
# Create buckets
mc alias set grc http://localhost:9000 ${MINIO_ROOT_USER} ${MINIO_ROOT_PASSWORD}
mc mb grc/evidence
mc mb grc/policies
mc mb grc/integrations

# Set bucket policies
mc policy set download grc/evidence
mc policy set private grc/policies
```

### Lifecycle Rules

```json
{
  "Rules": [
    {
      "ID": "evidence-retention",
      "Status": "Enabled",
      "Filter": {
        "Prefix": "evidence/"
      },
      "Expiration": {
        "Days": 365
      }
    }
  ]
}
```

---

## Security Configuration

### TLS/SSL

Generate self-signed certificates (development):

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout server.key \
  -out server.crt \
  -subj "/CN=localhost"
```

### Secrets Management

Using Docker secrets:

```yaml
secrets:
  db_password:
    file: ./secrets/db_password.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt

services:
  controls:
    secrets:
      - db_password
      - jwt_secret
    environment:
      DATABASE_URL_FILE: /run/secrets/db_password
```

### Network Policies

```yaml
# Kubernetes NetworkPolicy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: grc-services
spec:
  podSelector:
    matchLabels:
      app: grc
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: traefik
      ports:
        - protocol: TCP
          port: 3001
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
```

---

## Monitoring Configuration

### Prometheus Targets

```yaml
scrape_configs:
  - job_name: 'grc-services'
    static_configs:
      - targets:
          - 'controls:3001'
          - 'frameworks:3002'
          - 'policies:3004'
          - 'tprm:3005'
          - 'trust:3006'
          - 'audit:3007'
    metrics_path: '/health'
```

### Alert Rules

```yaml
groups:
  - name: grc-alerts
    rules:
      - alert: ServiceDown
        expr: up{job="grc-services"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "GRC service {{ $labels.instance }} is down"
          
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate on {{ $labels.service }}"
```

### Grafana Dashboards

Import dashboards from:
- `deploy/monitoring/dashboards/grc-overview.json`
- `deploy/monitoring/dashboards/service-metrics.json`

---

## Configuration Validation

### Validate Environment

```bash
# Check all required variables
./deploy/preflight-check.sh

# Validate specific service
docker-compose config --services
docker-compose config | grep -A5 controls
```

### Test Connectivity

```bash
# Database
docker exec grc-controls nc -zv postgres 5432

# Redis
docker exec grc-controls redis-cli -h redis -a $REDIS_PASSWORD ping

# Keycloak
curl -s http://keycloak:8080/auth/health | jq
```


