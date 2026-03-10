# 🛡️ A-HIDS – نظام كشف التسلل المستند إلى الذكاء الاصطناعي
# A-HIDS – AI-based Host Intrusion Detection System

<div dir="rtl">

## نظرة عامة

**A-HIDS** هو نظام متكامل لكشف التسلل إلى المضيف (HIDS) يستخدم الذكاء الاصطناعي لتحليل سلوك النظام وكشف التهديدات الأمنية في الوقت الفعلي. يجمع النظام بين نماذج التعلم الآلي (Random Forest + Isolation Forest) ومحرك القواعد الحتمي لتوفير أقصى قدر من الاكتشاف.

</div>

## Overview

**A-HIDS** is a full-featured Host Intrusion Detection System that uses AI/ML to analyze system behavior and detect security threats in real time. It combines machine learning models (Random Forest + Isolation Forest) with a deterministic rule engine for maximum detection coverage.

---

## Architecture / البنية المعمارية

```
┌─────────────────────────────────────────────────────────────────┐
│                     A-HIDS Architecture                         │
└─────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────┐
  │           Client Agents                 │
  │  ┌──────────┐  ┌──────────┐  ┌───────┐ │
  │  │ Process  │  │  File    │  │  Log  │ │
  │  │ Monitor  │  │Integrity │  │Monitor│ │
  │  └────┬─────┘  └────┬─────┘  └───┬───┘ │
  │       │              │            │      │
  │  ┌────▼──────────────▼────────────▼───┐ │
  │  │         Data Collector             │ │
  │  │    (system_info + network_monitor) │ │
  │  └───────────────────┬───────────────┘ │
  │                       │ HTTP POST /api/data
  └───────────────────────┼─────────────────┘
                          │
  ┌───────────────────────▼─────────────────┐
  │            REST API Server              │
  │  ┌─────────────┐    ┌────────────────┐  │
  │  │  AI Engine  │    │  Rule Engine   │  │
  │  │  RF + ISO   │    │  YAML Rules    │  │
  │  └──────┬──────┘    └───────┬────────┘  │
  │         │                   │            │
  │  ┌──────▼───────────────────▼────────┐  │
  │  │          Alert Manager            │  │
  │  │  (dedup + email + file logging)   │  │
  │  └──────────────┬────────────────────┘  │
  │                 │                        │
  │  ┌──────────────▼────────────────────┐  │
  │  │         SQLite Database           │  │
  │  │  clients / events / alerts /rules │  │
  │  └───────────────────────────────────┘  │
  └───────────────────┬─────────────────────┘
                      │ HTTP
  ┌───────────────────▼─────────────────────┐
  │           Web Dashboard                  │
  │  Flask + Bootstrap 5 (Arabic RTL UI)    │
  │  Charts · Alerts · Clients · Reports    │
  └─────────────────────────────────────────┘
```

---

## Features / المميزات

- 🔍 **Process Monitoring / مراقبة العمليات**: Detects high-CPU/memory and known-malicious processes
- 📁 **File Integrity / سلامة الملفات**: SHA-256 hashing and modification detection for critical files
- 📋 **Log Monitoring / مراقبة السجلات**: Parses auth.log/syslog for failed logins and privilege escalation
- 🌐 **Network Monitoring / مراقبة الشبكة**: Flags suspicious connections and dangerous listening ports
- 🤖 **AI Engine / الذكاء الاصطناعي**: RandomForest classifier + IsolationForest anomaly detection
- 📊 **Arabic Dashboard / لوحة التحكم**: Dark-themed web UI with Chart.js visualizations
- 🚨 **Alert System / نظام التنبيهات**: Deduplicated alerts with email notifications and file logging
- 📄 **HTML Reports / التقارير**: Professional security reports with inline CSS

---

## Requirements / المتطلبات

- Python 3.8+

```
flask>=2.3.0
flask-cors>=4.0.0
psutil>=5.9.0
scikit-learn>=1.3.0
numpy>=1.24.0
pandas>=2.0.0
requests>=2.31.0
pyyaml>=6.0
watchdog>=3.0.0
jinja2>=3.1.0
werkzeug>=2.3.0
```

---

## Installation / التثبيت

```bash
git clone https://github.com/example/a-hids.git
cd a-hids
pip install -r requirements.txt
```

---

## Usage / الاستخدام

```bash
# Train the AI model
python models/train_model.py

# Start the server
python server/main.py

# Start the client agent
python client/main.py

# Start the dashboard
python dashboard/app.py

# Run tests
python -m pytest tests/ -v
```

---

## API Documentation / توثيق API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth` | Validate authentication token |
| `POST` | `/api/data` | Submit collected host data |
| `GET`  | `/api/alerts` | Retrieve alerts (`?severity=HIGH`) |
| `POST` | `/api/alerts/<id>/acknowledge` | Acknowledge alert |
| `GET`  | `/api/clients` | List registered client agents |
| `GET`  | `/api/stats` | Aggregated statistics |
| `GET`  | `/api/events` | Raw event log |
| `GET`  | `/api/report` | Generate HTML security report |
| `GET`  | `/health` | Health check (no auth required) |

---

## License / الترخيص

MIT License – Copyright (c) 2024 A-HIDS Project

---

## Phase 1 Features / ميزات المرحلة الأولى

### 1. 🔐 HTTPS/TLS Support
- Auto-generates self-signed SSL certificates (`cryptography` library)
- Certificates stored in `certs/server.crt` and `certs/server.key`
- Enable in `config.yaml`: `server.ssl_enabled: true`
- Client supports `verify_ssl: false` for self-signed certs (development)

### 2. 🔑 JWT Per-Client Authentication
- Each client gets a unique JWT (via `PyJWT`) by registering with the master key
- Tokens expire after 24 hours (configurable)
- New endpoints: `POST /api/auth/register`, `/api/auth/refresh`, `/api/auth/revoke`
- Token blacklist stored in database
- Legacy shared-token auth still works for backward compatibility

### 3. 💾 PostgreSQL Support (with SQLite fallback)
- `server/database_pg.py` — PostgreSQL adapter with connection pooling
- `create_database(config)` factory function selects SQLite or PostgreSQL
- Enable in `config.yaml`: `server.database_type: "postgresql"`
- Automatically falls back to SQLite if PostgreSQL is unavailable

### 4. ⚡ Redis Caching
- `server/cache_manager.py` — Redis-backed cache with graceful fallback
- Caches: stats (30s), clients (60s), alerts (15s)
- Enable in `config.yaml`: `server.redis.enabled: true`
- Cache is automatically invalidated when new data arrives

### 5. 📡 WebSocket Real-Time Updates
- `server/websocket_manager.py` — Flask-SocketIO integration
- Events: `new_alert`, `client_status`, `stats_update`, `new_event`
- Dashboard auto-updates without page refresh
- Toast notifications for new CRITICAL/HIGH alerts
- Graceful fallback if `flask-socketio` is not installed

### 6. 🐳 Docker Support
```bash
# Start the full stack
docker-compose up

# Server only
docker build -t ahids-server .
docker run -p 5000:5000 ahids-server

# Client agent
docker build -f Dockerfile.client -t ahids-client .
docker run ahids-client
```

### 7. 🔧 Celery Background Tasks
- `server/tasks.py` — async task queue using Celery + Redis broker
- Tasks: `analyze_data_task`, `send_email_alert_task`, `generate_report_task`,
  `retrain_model_task`, `cleanup_old_data_task`
- Periodic schedule via Celery Beat
- Graceful no-op if Celery is not installed

### 8. 🔒 Rate Limiting & Security Hardening
- `server/security.py` — IP-based rate limits via `flask-limiter`
- Limits: 60/min POST /api/data, 10/min auth endpoints, 120/min GET endpoints
- Security headers on all responses (X-Frame-Options, CSP, HSTS, etc.)
- IP whitelist/blacklist support
- 1 MB request body size limit
- Graceful no-op if `flask-limiter` is not installed

### 9. 📊 Enhanced Logging
- `server/log_config.py` — structured rotating log files
- Separate logs: `logs/server.log`, `logs/api.log`, `logs/security.log`, `logs/ai.log`
- Colour console output in development, plain in production
- Max 10 MB per file, 5 backup files

---

## Docker Setup / إعداد Docker

```bash
# Prerequisites: Docker + Docker Compose

# Build and start all services
docker-compose up --build

# Services started:
#   server  → http://localhost:5000  (API)
#   server  → http://localhost:8080  (Dashboard)
#   redis   → localhost:6379
#   client  (agent connecting to server)
#   celery-worker
#   celery-beat
```

---

## PostgreSQL Setup (Optional) / إعداد PostgreSQL

```bash
# Create database and user
psql -U postgres -c "CREATE USER ahids_user WITH PASSWORD 'secure_password';"
psql -U postgres -c "CREATE DATABASE ahids OWNER ahids_user;"

# Update config.yaml
# server:
#   database_type: "postgresql"
#   postgresql:
#     host: "localhost"
#     port: 5432
#     database: "ahids"
#     user: "ahids_user"
#     password: "secure_password"
#     pool_size: 10
```

---

## Redis Setup (Optional) / إعداد Redis

```bash
# Install and start Redis
sudo apt install redis-server  # or: brew install redis
redis-server

# Update config.yaml
# server:
#   redis:
#     enabled: true
#     host: "localhost"
#     port: 6379
```

---

## Environment Variables / متغيرات البيئة

| Variable | Default | Description |
|----------|---------|-------------|
| `PYTHONUNBUFFERED` | `1` | Disable Python output buffering |

---

## Updated API Documentation / توثيق API المحدّث

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/auth` | No | Legacy token validation |
| `POST` | `/api/auth/register` | No | Register client, receive JWT |
| `POST` | `/api/auth/refresh` | No | Refresh expiring JWT |
| `POST` | `/api/auth/revoke` | No | Revoke a JWT |
| `POST` | `/api/data` | Bearer | Submit collected host data |
| `GET`  | `/api/alerts` | Bearer | Retrieve alerts (cached 15s) |
| `POST` | `/api/alerts/<id>/acknowledge` | Bearer | Acknowledge alert |
| `GET`  | `/api/clients` | Bearer | List client agents (cached 60s) |
| `GET`  | `/api/stats` | Bearer | Statistics (cached 30s) |
| `GET`  | `/api/events` | Bearer | Raw event log |
| `GET`  | `/api/report` | Bearer | Generate HTML security report |
| `GET`  | `/health` | No | Health check |
