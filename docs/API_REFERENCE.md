#  REST & WebSocket API Reference

The STEALTHWALL control plane runs on port `9377` by default.

---

## 1. REST Endpoints

### `POST /internal/decide`
Evaluates a request window and returns the graduated response decision.

- **Request Body**:
  ```json
  {
    "ip": "203.0.113.88",
    "path": "/items?id=1' OR '1'='1",
    "method": "GET",
    "ua": "sqlmap/1.8",
    "ts": 1724400000.0,
    "score": 0.95
  }
  ```

- **Response (`200 OK`)**:
  ```json
  {
    "action": "temp_block",
    "tier": "high",
    "final_score": 0.95,
    "ttl_seconds": 1800,
    "reason": "High-confidence SQL injection pattern",
    "asn_tag": { "asn": 13335, "isp": "Cloudflare" },
    "intel": { "country": "US", "is_tor": false, "threat_level": "high" }
  }
  ```

---

### `GET /api/health`
Health check status of the daemon, ASN gate, and active blocks.

- **Response (`200 OK`)**:
  ```json
  {
    "status": "ok",
    "timestamp": 1724400100.0,
    "asn_gate_state": "ok",
    "active_blocks_count": 3,
    "threat_intel_loaded": true
  }
  ```

---

### `GET /metrics`
Standard Prometheus metrics export endpoint for scraping by Prometheus and Grafana.

---

## 2. WebSocket Endpoint

### `WS /ws/feed`
Real-time streaming feed broadcasting live requests, ML scoring, and firewall blocks.

- **Event Schema (`type: incident`)**:
  ```json
  {
    "type": "incident",
    "data": {
      "ts": 1724400100.0,
      "ip": "185.220.101.5",
      "raw_score": 0.98,
      "action": "temp_block",
      "tier": "very_high",
      "ttl_seconds": 3600,
      "reason": "Brute force attack burst from Tor node",
      "country": "EU",
      "is_tor": true
    }
  }
  ```
