#  Python & FastAPI Integration Guide

This guide explains how to integrate STEALTHWALL into **FastAPI** and **Starlette** web applications.

---

## 1. Installation

```bash
# Minimal installation
pip install stealthwall

# With full ONNX Runtime ML & Redis support:
pip install "stealthwall[all]"
```

---

## 2. Quickstart: 1-Line Plug-and-Play

```python
from fastapi import FastAPI
from stealthwall import StealthWall

app = FastAPI(title="Production Service")

#  ONE LINE: Activates ML scoring, sliding windows, and graduated response
StealthWall(app)

@app.get("/")
def home():
    return {"status": "ok", "message": "Protected by StealthWall ML"}
```

---

## 3. Advanced Configuration Options

For production applications with custom needs, pass configuration arguments directly to `StealthWall()`:

```python
from fastapi import FastAPI
from stealthwall import StealthWall

app = FastAPI(title="Enterprise API")

StealthWall(
    app,
    # 1. Trusted Whitelist: Corporate subnets, monitoring systems, and developer IPs
    whitelist=[
        "192.168.1.100",
        "10.0.0.0/8",
        "203.0.113.50"
    ],

    # 2. Excluded Paths: Bypass static assets or Prometheus scrapers
    exclude_paths=[
        "/health",
        "/metrics",
        "/favicon.ico",
        "/static/*"
    ],

    # 3. Real-Time Alert Webhook (Discord / Slack / Telegram):
    alert_webhook="https://discord.com/api/webhooks/123456789/abcdefgh",

    # 4. Distributed State via Redis (For Kubernetes / Multi-worker clusters):
    redis_url="redis://localhost:6379/0",

    # 5. Dry-Run Mode: Log and evaluate attacks without dropping connections
    dry_run=False,

    # 6. ASN Gate Safety: Enforce routing infrastructure safety
    enable_asn=True
)
```

---

## 4. How the Request Pipeline Works

```
Incoming Request
       │
       ▼
[Pre-Enforcement Gate] ─── (Is IP in Active Blocklist?) ──► 403 Forbidden
       │
       ▼ (Pass to App)
[FastAPI Route Execution]
       │
       ▼
[Post-Response Scoring]
       │
       ├─► Record in 60s Sliding Window (In-Memory or Redis)
       ├─► Extract 14-Dimension Vector (Shannon Entropy, Variance, Scan Signals)
       ├─► Evaluate ONNX ML Model (~0.03ms inference)
       └─► If Attack Detected ──► Escalate Tier & Apply Graduated Block
```

---

## 5. Running the Operations Dashboard

To view real-time traffic, active blocks, and threat maps:

```bash
stealthwall dashboard --port 9377
```
Open `http://localhost:9377` in your browser.
