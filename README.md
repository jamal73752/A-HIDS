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
