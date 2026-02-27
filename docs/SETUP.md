# SOC Lab Docker – Setup & Deployment Guide

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Detailed Configuration](#detailed-configuration)
4. [Verification & Troubleshooting](#verification--troubleshooting)
5. [Security & Hardening](#security--hardening)
6. [Advanced Options](#advanced-options)
7. [Cleanup & Teardown](#cleanup--teardown)

---

## Prerequisites

### System Requirements

- **Operating System:** Linux, macOS, or Windows (with WSL2)
- **RAM:** 4GB minimum (6GB+ recommended)
- **Disk Space:** 10GB free for initial deployment + data
- **CPU:** 2 cores minimum (4+ cores recommended)
- **Network:** Internet access for Docker image downloads

### Software Requirements

- **Docker:** Version 20.10+ ([Install Docker](https://docs.docker.com/get-docker/))
- **Docker Compose:** Version 2.0+ (usually included with Docker Desktop)
- **Git:** For cloning the repository
- **Bash/PowerShell:** Terminal for running commands
- **Text editor:** For editing `.env` configuration

### Verify Prerequisites

```bash
# Check Docker
docker --version
# Expected output: Docker version 20.10.x or higher

# Check Docker Compose
docker-compose --version
# Expected output: Docker Compose version 2.x.x or higher

# Check Git
git --version
# Expected output: git version 2.x.x or higher
```

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/soc-lab-docker.git
cd soc-lab-docker
```

### 2. Configure Environment

```bash
# Copy example configuration
cp .env.example .env

# Review and edit if needed
cat .env
# Edit with your preferred editor:
# nano .env, code .env, vim .env, etc.
```

### 3. Start the Lab Stack

```bash
# Pull latest images and start services
docker-compose up -d

# Verify all services are running
docker-compose ps

# Expected output:
# NAME                      STATUS              PORTS
# soc-lab-elasticsearch     Up (healthy)        0.0.0.0:9200->9200/tcp
# soc-lab-filebeat          Up
# soc-lab-log-generator     Up
# soc-lab-kibana            Up (healthy)        0.0.0.0:5601->5601/tcp
```

> **Windows users:** Docker Desktop must be running before using any Docker commands.
> Enable **Start Docker Desktop when you sign in** in Settings → General to avoid this step.
> Run attack simulation scripts via WSL: `wsl bash scripts/brute_force_simulation.sh`

### 4. Access the Lab

```bash
# Web UI – open in browser
http://localhost:5601

# Direct API access (Elasticsearch)
curl http://localhost:9200

# Check data availability
curl http://localhost:9200/_cat/indices?v
# Should see indices like: .ds-soc-lab-2026.02.27-000001
```

### 5. Create Kibana Data View

Before browsing data in Kibana you need to create a data view:

1. Open `http://localhost:5601/app/management/kibana/dataViews`
2. Click **Create data view**
3. Set **Index pattern** to `soc-lab-*` and **Timestamp field** to `@timestamp`
4. Click **Save data view to Kibana**

Then go to **Analytics → Discover** to explore live events.

### 6. Verify Data Generation

```bash
# Monitor the generator
docker-compose logs --tail=10 log-generator

# Check events in Elasticsearch
curl -X GET "localhost:9200/soc-lab-*/_count"

# Expected output:
# {"count":1234,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0}}
```

**✅ Lab is running! Proceed to [Verification & Troubleshooting](#verification--troubleshooting).**

---

## Detailed Configuration

### Environment Variables

All configuration is controlled via the `.env` file. Key variables:

```bash
# ============================================================================
# Data Store Configuration
# ============================================================================

# Where Elasticsearch listens
ELASTICSEARCH_HOST=elasticsearch
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_HEAP_SIZE=512m    # Increase for large datasets

# How long to keep data
DATA_RETENTION_DAYS=7           # Change to 14, 30, etc.

# ============================================================================
# Log Generator
# ============================================================================

# Enable/disable generator
LOG_GENERATOR_ENABLED=true

# Event rate (events per second)
LOG_GENERATION_RATE=10          # Increase to 50+ for high-volume testing

# Event types to generate
EVENT_TYPES=authentication,web_traffic,process_execution,network

# ============================================================================
# Web UI
# ============================================================================

ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme123      # ⚠️ CHANGE THIS!
WEB_UI_PORT=5601               # Use 8080 if 5601 is already in use
```

### Customization Examples

#### Example 1: Increase Event Volume

For simulating busier environment:

```bash
# Edit .env
LOG_GENERATION_RATE=100         # 100 events/second instead of 10
ELASTICSEARCH_HEAP_SIZE=2g      # Increase memory
```

Then restart:

```bash
docker-compose restart
```

#### Example 2: Change Data Retention

To keep data longer for historical analysis:

```bash
DATA_RETENTION_DAYS=30          # Keep 30 days instead of 7
ELASTICSEARCH_HEAP_SIZE=4g      # Larger heap for more data
```

#### Example 3: Use Alternative Port

If port 5601 is already in use:

```bash
WEB_UI_PORT=8080                # Use port 8080 instead
```

Then access at: `http://localhost:8080`

---

## Verification & Troubleshooting

### Health Checks

#### 1. Verify All Containers Are Running

```bash
docker-compose ps

# Expected output: All services "Up", some marked "healthy"
```

#### 2. Test Elasticsearch Connection

```bash
curl -s http://localhost:9200 | jq .

# Expected output:
# {
#   "name": "node-1",
#   "cluster_name": "soc-lab-cluster",
#   "cluster_uuid": "...",
#   "version": {"number": "8.x.x", ...},
#   "tagline": "You Know, for Search"
# }
```

#### 3. Check Log Generation

```bash
# Verify logs file exists and is being written
ls data/logs/

# Monitor live log output (Linux/macOS/WSL)
tail -f data/logs/soc-lab-events.json
```

#### 4. Test Data in Index

```bash
# Count total events
curl -s "http://localhost:9200/soc-lab-*/_count"

# Sample a recent event
curl -s "http://localhost:9200/soc-lab-*/_search?size=1"
```

### Common Issues & Solutions

#### Issue: "Port Already in Use"

**Symptom:**

```
ERROR: bind: address already in use
```

**Solution:**

```bash
# Option 1: Change port in .env
WEB_UI_PORT=8080  # or any available port

# Option 2: Find what's using the port
lsof -i :5601  # (macOS/Linux)
netstat -ano | findstr :5601  # (Windows)

# Option 3: Stop the conflicting service
# Then start SOC Lab Docker
```

#### Issue: "Elasticsearch Not Responding"

**Symptom:**

```
Failed to connect to Elasticsearch at http://elasticsearch:9200
```

**Solution:**

```bash
# Check Elasticsearch logs
docker-compose logs elasticsearch

# Restart Elasticsearch
docker-compose restart elasticsearch

# Wait a few seconds and check status
docker-compose ps elasticsearch
# Should show "Up (healthy)" after ~10 seconds
```

#### Issue: "Docker Daemon Not Running"

**Symptom:**

```
Cannot connect to Docker daemon
```

**Solution:**

```bash
# macOS
open -a Docker

# Windows
# Start Docker Desktop from Start Menu

# Linux
sudo systemctl start docker
```

#### Issue: "Out of Memory"

**Symptom:**

```
137 exit code (Killed) or OOMKilled
```

**Solution:**

```bash
# Option 1: Increase Elasticsearch heap (in .env)
ELASTICSEARCH_HEAP_SIZE=1g  # Depending on available RAM

# Option 2: Increase Docker Desktop memory allocation
# Docker Desktop Settings → Resources → Memory (set higher)

# Option 3: Reduce event generation rate (in .env)
LOG_GENERATION_RATE=5  # Instead of 10
```

#### Issue: "Indices Not Appearing"

**Symptom:**

```
curl http://localhost:9200/_cat/indices?v
(Empty output or no soc-lab-* indices)
```

**Solution:**

```bash
# 1. Check generator is running
docker-compose ps  # log-generator should be "Up"

# 2. Check logs exist on host
ls data/logs/

# 3. Check filebeat logs
docker-compose logs filebeat
# Look for errors about log file or Elasticsearch connection

# 4. Force restart filebeat
docker-compose restart filebeat

# Wait 30 seconds, then check again
curl http://localhost:9200/_cat/indices?v
```

---

## Security & Hardening

⚠️ **Important:** The default configuration is development-only and insecure.

### Critical: Change Default Password

```bash
# Edit .env
ADMIN_PASSWORD=<choose-a-strong-password>

# Restart
docker-compose up -d
```

### Enable TLS/SSL (Production)

```bash
# 1. Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout certs/server.key -out certs/server.crt

# 2. Enable TLS in .env
ENABLE_TLS=true
TLS_CERT_PATH=./certs/server.crt
TLS_KEY_PATH=./certs/server.key

# 3. Restart
docker-compose up -d
```

### Network Isolation

For running in untrusted environments:

```bash
# Enable isolated Docker network
NETWORK_ISOLATED=true

# Also enable authentication between services
# (Requires custom Docker Compose override)
```

### Elasticsearch Authentication

Default: No authentication. For production:

```yaml
# In docker-compose.yml (add to elasticsearch service)
environment:
  - xpack.security.enabled=true
  - ELASTIC_PASSWORD=your-strong-password
```

Then update connectors with credentials.

### Firewall Rules

If exposed to network:

```bash
# Allow only local access (default)
WEB_UI_HOST=127.0.0.1  # Listen only on localhost

# Or restrict to specific IP
WEB_UI_HOST=192.168.1.100

# Restart
docker-compose up -d
```

---

## Advanced Options

### Persistent Storage (Keep Data After Shutdown)

Elasticsearch data is persisted in a named Docker volume (`elasticsearch-data`) by default —
it survives `docker-compose stop/start`. Only `docker-compose down -v` removes it.

Generated log files are written to `./data/logs/` on the host and persist between restarts.

### Custom Log Generator Configuration

```bash
# Create custom event template in generator/templates/
# Then rebuild and restart the generator
docker-compose up -d --build log-generator
```

### Scale Event Generation

For performance testing:

```bash
# Increase event rate significantly
LOG_GENERATION_RATE=500  # 500 events/second
ELASTICSEARCH_HEAP_SIZE=8g
COMPOSE_PROJECT_NAME=soc-lab-large  # Avoid port conflicts

docker-compose up -d
```

### Multi-Instance Deployment

For team training (multiple independent lab instances):

```bash
# Instance 1
COMPOSE_PROJECT_NAME=soc-lab-team1 WEB_UI_PORT=5601 docker-compose up -d

# Instance 2
COMPOSE_PROJECT_NAME=soc-lab-team2 WEB_UI_PORT=5602 docker-compose up -d

# Instance 3
COMPOSE_PROJECT_NAME=soc-lab-team3 WEB_UI_PORT=5603 docker-compose up -d

# Each team gets their own isolated stack on different port
```

---

## Cleanup & Teardown

### Stop the Lab (Data Preserved)

```bash
docker-compose stop

# Restart later
docker-compose start
```

### Shutdown & Remove Containers (Data Lost)

```bash
docker-compose down

# All containers removed, volumes cleared (default)
```

### Clean Up Everything (Including Volumes)

```bash
docker-compose down -v

# Warning: This deletes all data and volumes
# Use carefully!
```

### Full Cleanup (Images Too)

```bash
docker-compose down -v --remove-orphans
docker system prune -a

# Frees up all Docker resources
# Will need to re-download images on next `up`
```

### Export Data Before Cleanup

```bash
# Export all indices
curl -X GET "localhost:9200/_data/export" > backup.json

# Backup volumes
docker run --rm \
  -v soc-lab-docker_elasticsearch-data:/data \
  -v $(pwd)/backup:/backup \
  busybox tar czf /backup/elasticsearch-backup.tar.gz /data
```

---

## Next Steps

- ✅ [Simulate your first attack](../scripts/README.md)
- ✅ [Run a detection query](../detections/README.md)
- ✅ [View dashboards](../dashboards/README.md)
- ✅ [Learn architecture details](./ARCHITECTURE.md)

---

## Getting Help

**Issues or questions?**

1. Check [Troubleshooting section](#verification--troubleshooting) above
2. Review Docker Compose logs: `docker-compose logs -f`
3. Check component logs: `docker-compose logs <service-name>`
4. Open a GitHub issue with:
   - Error message and full output
   - Your OS and Docker version (from `docker --version`)
   - `.env` configuration (without passwords)

---

**Last Updated:** February 2026
