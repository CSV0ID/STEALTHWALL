# Changelog

All notable changes to the STEALTHWALL project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [5.0.0] - 2026-08-23

### Added
- Comprehensive technical documentation in `docs/`:
  - `PUBLISHING_GUIDE.md`: Build and release instructions for PyPI and npm with GitHub Actions workflows.
  - `INTEGRATION_PYTHON.md`: FastAPI and Starlette integration guide with custom configs and Redis clustering.
  - `INTEGRATION_NODEJS.md`: Express.js CommonJS and TypeScript setup guide.
  - `INTEGRATION_NEXTJS.md`: Next.js Edge Middleware (`middleware.ts`) implementation.
  - `INTEGRATION_PHP.md`: PHP, Laravel, and WordPress setup via `auto_prepend_file` and `wp-config.php`.
  - `INTEGRATION_NGINX.md`: Nginx reverse-proxy `auth_request` configuration for language-agnostic deployments.
  - `API_REFERENCE.md`: Specifications for REST endpoints and `/ws/feed` WebSocket streams.
  - `ATTACK_SIMULATION_GUIDE.md`: Testing instructions for `stealthwall attack`.
- Universal Nginx reverse proxy configuration (`integrations/nginx/stealthwall_nginx.conf`).
- Drop-in PHP protection script (`integrations/php/stealthwall.php`) with 50ms timeout bounds.
- Drop-in Next.js Edge Middleware (`integrations/nextjs/middleware.ts`).

### Changed
- Cleaned all codebase and terminal output to strict ASCII / UTF-8 standards without emoji characters.
- Upgraded package version to 5.0.0 in `pyproject.toml` and `middleware/express/package.json`.
- Verified 36/36 automated unit and integration tests passing.

---

## [4.0.0] - 2026-08-23

### Added
- Multi-channel asynchronous webhook notifier (`block_engine/alerting.py`) supporting Discord, Slack, and Telegram with 60-second alert debouncing per source IP.
- Cloudflare IP Access Rules and AWS WAF IPSet edge synchronization driver (`block_engine/cdn_integrations/edge_sync.py`).
- Native client-side Proof-of-Work challenge generator and validator (`block_engine/captcha/pow_challenge.py`) with HMAC signatures and replay protection.
- CLI attack simulation tool (`data/simulator.py`) supporting 9 tool profiles: SQLMap, WPScan, Nikto, Gobuster, Hydra, Nuclei, Commix, XSStrike, and Low-and-Slow.
- Automated AI model drift monitoring and recalibration daemon (`models/adaptive_scoring/drift_daemon.py`).
- Top-level 1-line Python SDK wrapper (`StealthWall(app)`) supporting `whitelist`, `exclude_paths`, `alert_webhook`, `redis_url`, and `dry_run` parameters.

---

## [3.0.0] - 2026-08-23

### Added
- Redis Sorted-Set sliding window engine (`middleware/fastapi/stealthwall_fastapi/redis_window.py`) for multi-worker and Kubernetes horizontal auto-scaling.
- Real-time WebSocket live feed (`/ws/feed`) in operations console (`dashboard/app.py`).
- Offline GeoIP and Tor exit node threat intelligence resolver (`block_engine/threat_intel.py`) with in-memory LRU cache.
- Standard Prometheus metrics exporter (`/metrics`) and Grafana dashboard template (`monitoring/grafana_stealthwall.json`).
- Production `Dockerfile` and `docker-compose.yml` configuration.
- Health and status endpoints (`/api/health`, `/api/stats`).

---

## [2.0.0] - 2026-08-23

### Added
- 10-Million sample dataset generator modeling 11 modern cyberattack tools and benign browser traffic.
- 800-tree LightGBM GBDT model trained on 7.5M training windows and validated on 2.5M test windows.
- 30% signature cap constraint verified across 100 benign traffic windows to eliminate false positives on search queries.
- ONNX export with 5e-8 bit-parity validation and pure-Python zero-dependency fallback loader (`FallbackColdstartModel`).
- Graduated Response Engine (`block_engine/graduated_response.py`) with multi-tier cooldowns, shared-IP blast radius protection, and ASN fail-loud safety.
- Unified developer CLI (`stealthwall_cli.py`).
- Automated 22-test Pytest test suite and 11 cross-language feature parity corpora.

---

## [1.0.0] - 2026-08-22

### Added
- Initial Feature Specification v1 defining 14 normalized statistical float metrics.
- Canonical feature extractors in Python (`fastapi/features.py`) and Node.js (`express/src/features.js`).
- 11 cross-language mathematical parity test corpora.
- Base Random Forest cold-start training pipeline.
