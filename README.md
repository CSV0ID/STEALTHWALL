# STEALTHWALL

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Node.js 18+](https://img.shields.io/badge/node-18+-green.svg)](https://nodejs.org/)

Self-hosted machine-learning intrusion prevention middleware and firewall. Evaluates sliding-window traffic behavior across 14 normalized statistical features in sub-millisecond time to detect and mitigate automated cyberattacks (SQL injection, directory scans, brute force, exploit probes) before requests reach backend application logic.

---

## Architecture Overview

STEALTHWALL operates as an in-process middleware or reverse-proxy sidecar:

1. **Pre-Enforcement Gate**: Checks incoming requests against local kernel firewall tables (`iptables`/`nftables`) and active cooldown lists. Drops blocked IPs immediately (`403 Forbidden`).
2. **Feature Extraction**: Tracks requests in sliding time windows (60 seconds) per source IP. Computes 14 normalized statistical metrics (Shannon entropy, inter-arrival variance, status code distribution, enumeration entropy, signature presence).
3. **ML Inference**: Evaluates an optimized LightGBM decision model (`coldstart.onnx`) running on ONNX Runtime with pure-Python fallback.
4. **Graduated Response**: Implements progressive cooldown tiers (`rate_limit` -> `pow_challenge` -> `provisional_block` -> `temp_block` -> `long_cooldown`). Includes shared-IP protection for CGNAT / proxy gateways.

---

## Quickstart

### Python (FastAPI / Starlette)

```bash
pip install stealthwall
```

```python
from fastapi import FastAPI
from stealthwall import StealthWall

app = FastAPI()
StealthWall(app)

@app.get("/")
def index():
    return {"status": "online"}
```

### Node.js (Express)

```bash
npm install stealthwall
```

```javascript
const express = require('express');
const { stealthwall } = require('stealthwall');

const app = express();
app.use(stealthwall());

app.get('/', (req, res) => {
  res.json({ status: 'online' });
});

app.listen(3000);
```

---

## CLI & Operations Console

```bash
# Launch visual monitoring dashboard and WebSocket feed
stealthwall dashboard --port 8000

# Run simulated attack traffic against a target
stealthwall attack --tool sqlmap --target http://localhost:8000

# Print configuration and model artifact status
stealthwall status

# Run full test suite and cross-language parity assertions
stealthwall test
```

### Dashboard Authentication & Docker

When running the dashboard in production, configure admin credentials via environment variables:

```bash
export STEALTHWALL_ADMIN_USER="admin"
export STEALTHWALL_ADMIN_PASSWORD="YourStrongPassword123!"
stealthwall dashboard --port 8000
```

Or deploy the complete stack (Dashboard + Redis + Prometheus) via Docker Compose:

```bash
docker compose up -d
```
Visit `http://localhost:8000` to access the real-time dark-theme Operations Console and live incident stream.

---

## Documentation

- [Publishing to PyPI & npm](docs/PUBLISHING_GUIDE.md)
- [FastAPI / Python Integration](docs/INTEGRATION_PYTHON.md)
- [Express / Node.js Integration](docs/INTEGRATION_NODEJS.md)
- [Next.js Edge Middleware](docs/INTEGRATION_NEXTJS.md)
- [PHP & WordPress Integration](docs/INTEGRATION_PHP.md)
- [Nginx Reverse Proxy Integration](docs/INTEGRATION_NGINX.md)
- [REST & WebSocket API Reference](docs/API_REFERENCE.md)
- [Attack Simulator & Penetration Testing](docs/ATTACK_SIMULATION_GUIDE.md)
- [Changelog](CHANGELOG.md)

---

## License

MIT License.
