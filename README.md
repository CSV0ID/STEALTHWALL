<p align="center">
  <img src="docs/assets/banner.svg" alt="STEALTHWALL by CS VOID LABS" width="100%">
</p>

<p align="center">
  <strong>Sub-millisecond machine-learning intrusion prevention system and self-healing Web Application Firewall.</strong><br>
  <em>Engineered by <strong>CS VOID LABS</strong> to mitigate zero-day web attacks, polyglots, and automated scrapers before requests hit backend logic.</em>
</p>

<p align="center">
  <a href="https://stealthwall.chinmayshinde.tech">
    <img src="https://img.shields.io/badge/🌐_Official_Website-stealthwall.chinmayshinde.tech-0f172a?style=for-the-badge&logo=googlechrome&logoColor=38bdf8&labelColor=020617" alt="Official Website">
  </a>
  <a href="https://stealthwall.chinmayshinde.tech/demo.html">
    <img src="https://img.shields.io/badge/⚡_Live_3D_Sandbox-Attack_Simulator-0f172a?style=for-the-badge&logo=three.js&logoColor=34d399&labelColor=020617" alt="Live Sandbox">
  </a>
  <a href="https://stealthwall.chinmayshinde.tech/how-it-works.html">
    <img src="https://img.shields.io/badge/📖_Architecture-Math_&_Heuristics-0f172a?style=for-the-badge&logo=gitbook&logoColor=a855f7&labelColor=020617" alt="Architecture Docs">
  </a>
  <a href="https://stealthwall.chinmayshinde.tech/benchmarks.html">
    <img src="https://img.shields.io/badge/📊_Benchmarks-Latency_&_Parity-0f172a?style=for-the-badge&logo=speedtest&logoColor=fbbf24&labelColor=020617" alt="Benchmarks">
  </a>
</p>

<p align="center">
  <a href="https://pypi.org/project/stealthwall/"><img src="https://img.shields.io/badge/PyPI-pip_install_stealthwall-3776ab?style=flat-square&logo=pypi&logoColor=white" alt="PyPI Package"></a>
  <a href="https://www.npmjs.com/package/stealthwall"><img src="https://img.shields.io/badge/npm-npm_i_stealthwall-cb3837?style=flat-square&logo=npm&logoColor=white" alt="npm Package"></a>
  <a href="https://github.com/CSV0ID/STEALTHWALL/releases/tag/v5.0.0"><img src="https://img.shields.io/badge/release-v5.0.0-22c55e?style=flat-square&logo=github&logoColor=white" alt="Release"></a>
  <a href="https://github.com/CSV0ID/STEALTHWALL/actions"><img src="https://img.shields.io/badge/tests-40%20passed%20(100%25)-brightgreen?style=flat-square" alt="Tests Passed"></a>
  <a href="https://github.com/CSV0ID/STEALTHWALL/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square" alt="License: Apache 2.0"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.9+-38bdf8?style=flat-square&logo=python&logoColor=white" alt="Python 3.9+"></a>
  <a href="https://nodejs.org/"><img src="https://img.shields.io/badge/node-18+-34d399?style=flat-square&logo=nodedotjs&logoColor=white" alt="Node.js 18+"></a>
</p>

---

## ⚡ Why STEALTHWALL?

Traditional Web Application Firewalls (ModSecurity, Cloudflare WAF, AWS WAF) force engineering teams into an unacceptable tradeoff:

1. **Static Regex Latency**: Evaluating hundreds of bloated regular expression rules adds **15–40ms** of overhead to every HTTP request.
2. **Blind to 0-Day Evasion**: Signature engines fail against novel polyglots, whitespace variations, and polymorphic payload encodings.
3. **Cloud SaaS Telemetry Leakage**: Routing customer request bodies and headers through third-party cloud infrastructure introduces privacy compliance (GDPR/HIPAA) risks.

**STEALTHWALL eliminates this compromise.** Built by **CS VOID LABS**, it executes entirely in-process inside your application runtime or edge proxy, extracting **14 normalized behavioral entropy metrics** and scoring requests via an optimized **LightGBM decision forest compiled to ONNX** in **under 0.8 milliseconds**.

---

## 🏛️ 5-Stage Defense Architecture

```
[ Incoming HTTP Request (FastAPI / Express / Nginx) ]
                          │
  ┌───────────────────────▼─────────────────────────────────┐
  │  Stage 1: Pre-Enforcement Kernel Gate                   │
  │  • Fast-path iptables / nftables kernel table check     │
  │  • Active CIDR cooldown & CGNAT whitelist lookup        │
  └───────────────────────┬─────────────────────────────────┘
                          │ (Allowed / Unbanned)
  ┌───────────────────────▼─────────────────────────────────┐
  │  Stage 2: 14-Feature Sliding Window Extraction          │
  │  • Shannon path entropy & parameter token distribution  │
  │  • Inter-arrival time delta jitter (sub-burst variance) │
  │  • Status code anomaly ratio & HTTP verb entropy        │
  └───────────────────────┬─────────────────────────────────┘
                          │
  ┌───────────────────────▼─────────────────────────────────┐
  │  Stage 3: Dynamic 0-Day Threat Engine                   │
  │  • Heuristic semantic scanning: SSRF, Log4j/JNDI,       │
  │    Prototype Pollution, XXE, SSTI, and polyglot probes  │
  └───────────────────────┬─────────────────────────────────┘
                          │
  ┌───────────────────────▼─────────────────────────────────┐
  │  Stage 4: Sub-Millisecond ONNX Inference (<0.8ms)       │
  │  • High-performance LightGBM forest on ONNX Runtime     │
  │  • Exact mathematical bit-parity (5e-8) across Python/JS│
  └───────────────────────┬─────────────────────────────────┘
                          │ (Calculated Threat Score: 0.00 – 1.00)
  ┌───────────────────────▼─────────────────────────────────┐
  │  Stage 5: Automated Graduated Defense                   │
  │  • [0.00 - 0.50] Clean Traffic     ──► Allow (200 OK)   │
  │  • [0.51 - 0.70] Suspicious Jitter ──► Progressive Rate │
  │  • [0.71 - 0.85] High Entropy Scan ──► PoW Challenge    │
  │  • [0.86 - 1.00] Active Attack     ──► Kernel Drop (403)│
  └─────────────────────────────────────────────────────────┘
```

---

## 📊 Head-to-Head Comparison Matrix

| Feature | STEALTHWALL (CS VOID LABS) | ModSecurity / Coraza | Cloudflare WAF | AWS WAF |
| :--- | :---: | :---: | :---: | :---: |
| **Inference Overhead** | **`<0.8 ms`** | `15 – 35 ms` | `20 – 60 ms` (Network) | `10 – 30 ms` |
| **Detection Methodology** | **Behavioral ML + 0-Day Heuristics** | Static Regex Signatures | Proprietary Cloud Rules | Managed Rulesets |
| **Data Privacy** | **100% Self-Hosted (Zero Leak)** | Self-Hosted | Third-Party SaaS | Cloud-Locked |
| **Cross-Language Bit-Parity** | **`5e-8` (Python & Node.js)** | N/A | N/A | N/A |
| **Automated Graduated Defense** | **Progressive (PoW / Rate / Drop)** | Binary Block / Allow | CAPTCHA / Block | Challenge / Block |
| **Zero-Day Heuristics** | **SSRF / Log4j / XXE / SSTI** | Requires Signature Update | Managed Cloud Update | Managed Cloud Update |
| **License** | **Apache 2.0 (Open Source)** | Apache 2.0 | Commercial | Commercial |

---

## 🚀 Quickstart Guides

### 🐍 Python (FastAPI / Starlette / ASGI)

```bash
pip install stealthwall
```

```python
from fastapi import FastAPI
from stealthwall.middleware import StealthwallMiddleware

app = FastAPI(title="Secure Production API")

# Attach STEALTHWALL in 1 line of code
app.add_middleware(StealthwallMiddleware)

@app.get("/")
def home():
    return {"status": "protected by stealthwall"}

@app.post("/api/login")
def login(data: dict):
    return {"authenticated": True}
```

---

### 🟢 Node.js (Express / Connect)

```bash
npm install stealthwall
```

```javascript
const express = require('express');
const { stealthwall } = require('stealthwall');

const app = express();

// Attach STEALTHWALL middleware
app.use(stealthwall());

app.get('/', (req, res) => {
  res.json({ status: 'protected by stealthwall' });
});

app.listen(3000, () => console.log('Server running on port 3000'));
```

---

### 🐳 Full Stack Monitoring (Docker Compose)

Deploy the complete enterprise monitoring stack (Operations Dashboard, Redis sliding-window cache, and Prometheus metrics) with one command:

```bash
docker compose up -d
```

Access the real-time dark-theme Operations Console at `http://localhost:8000`.

---

## 💻 CLI & Penetration Testing Toolkit

STEALTHWALL includes a built-in command-line interface for telemetry management and security validation:

```bash
# 1. Launch real-time telemetry monitoring dashboard & WebSocket feed
stealthwall dashboard --port 8000

# 2. Simulate penetration testing traffic against a local or staging target
stealthwall attack --tool sqlmap --target http://localhost:8000
stealthwall attack --tool nikto --target http://localhost:8000
stealthwall attack --tool hydra --target http://localhost:8000

# 3. Inspect model artifact status, ONNX runtime, and feature extractors
stealthwall status

# 4. Run automated test suite and cross-language bit-parity verification
stealthwall test
```

---

## 📈 Empirical Benchmarks

Tested on a standard 4-core Linux VPS (Ubuntu 22.04 LTS, AMD EPYC 7763, Python 3.11, Node.js 20 LTS):

| Benchmark Metric | Observed Value | Production Standard | Status |
| :--- | :---: | :---: | :---: |
| **Median Inference Latency (P50)** | **`0.72 ms`** | `< 2.0 ms` | **PASSED** |
| **99th Percentile Latency (P99)** | **`0.94 ms`** | `< 5.0 ms` | **PASSED** |
| **Memory Footprint (In-Process)** | **`< 28 MB`** | `< 100 MB` | **PASSED** |
| **Attack Detection Accuracy** | **`99.82%`** | `> 95.0%` | **PASSED** |
| **Cross-Runtime Numerical Parity** | **`5e-8` max diff** | `< 1e-6` | **PASSED** |

---

## 📚 Documentation & Integrations

- [🌐 Interactive Live 3D Sandbox](https://stealthwall.chinmayshinde.tech/demo.html)
- [📖 Architecture & Mathematical Specifications](https://stealthwall.chinmayshinde.tech/how-it-works.html)
- [🚀 Production Deployment Architectures](docs/DEPLOYMENT_GUIDE.md)
- [⚡ Next.js Edge Middleware Integration](docs/INTEGRATION_NEXTJS.md)
- [🐘 PHP & WordPress WAF Integration](docs/INTEGRATION_PHP.md)
- [🛡️ Nginx Reverse Proxy Sidecar Guide](docs/INTEGRATION_NGINX.md)
- [📡 REST & WebSocket API Reference](docs/API_REFERENCE.md)
- [🎯 Penetration Testing & Attack Simulation Guide](docs/ATTACK_SIMULATION_GUIDE.md)
- [📜 Changelog & Release Notes](CHANGELOG.md)

---

## 🤝 Contributing & Community

We welcome contributions from security researchers, ML practitioners, and backend engineers. 

- Review our **[CONTRIBUTING.md](CONTRIBUTING.md)** for developer setup, PEP 8/ESLint standards, and pull request workflows.
- Please adhere to our **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** in all interactions.
- Report potential security vulnerabilities following our responsible disclosure process in **[SECURITY.md](SECURITY.md)**.

---

## 🏢 Organization & Author

<p align="left">
  <strong>CS VOID LABS</strong> • <em>Offensive Security & Machine Learning Division</em><br>
  Founder & Lead Architect: <strong>Chinmay Shinde</strong> (<a href="https://github.com/CSV0ID">@CSV0ID</a>)
</p>

<p align="left">
  <a href="https://chinmayshinde.dev"><img src="https://img.shields.io/badge/Portfolio-chinmayshinde.dev-38bdf8?style=flat-square&logo=googlechrome&logoColor=white" alt="Personal Website"></a>
  <a href="https://linkedin.com/in/cs-dev"><img src="https://img.shields.io/badge/LinkedIn-cs--dev-0077b5?style=flat-square&logo=linkedin&logoColor=white" alt="LinkedIn"></a>
  <a href="https://github.com/CSV0ID"><img src="https://img.shields.io/badge/GitHub-CSV0ID-181717?style=flat-square&logo=github&logoColor=white" alt="GitHub"></a>
  <a href="https://instagram.com/chinmay.shinde247"><img src="https://img.shields.io/badge/Instagram-@chinmay.shinde247-e4405f?style=flat-square&logo=instagram&logoColor=white" alt="Instagram"></a>
  <a href="https://twitter.com/CS2407"><img src="https://img.shields.io/badge/Twitter-@CS2407-1da1f2?style=flat-square&logo=twitter&logoColor=white" alt="Twitter"></a>
</p>

---

## ⚖️ License

STEALTHWALL is open-source software licensed under the [Apache License 2.0](LICENSE).
