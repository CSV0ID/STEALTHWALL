# REST, WebSocket & Authentication API Reference

The STEALTHWALL Operations Console and Control Plane runs on port `8000` (or `9377` in headless mode).

---

## 1. Authentication & Security

STEALTHWALL protects the operations console with enterprise-grade session authentication.

### `POST /api/auth/login`
Authenticates an administrator with username and password.

- **Request Type**: `application/x-www-form-urlencoded` or `multipart/form-data`
- **Parameters**:
  - `username` *(string)*: Admin username.
  - `password` *(string)*: Admin password.
- **Response**: `302 Redirect` to `/` with secure `Set-Cookie: sid=<token>; HttpOnly; Max-Age=86400`.

### Environment Configuration
You can configure default credentials without touching the database:
```bash
export STEALTHWALL_ADMIN_USER="security_admin"
export STEALTHWALL_ADMIN_PASSWORD="YourStrongPassword123!"
```

### `GET /logout`
Invalidates the current session and clears the `sid` cookie.

### API Header Authentication
Automated systems, CLI utilities, and monitoring collectors can authenticate via header:
```bash
curl -H "X-Session-ID: <valid_session_sid>" http://localhost:8000/api/stats
```

---

## 2. REST Control Plane Endpoints

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
    "country": "US",
    "is_tor": false,
    "is_datacenter": false
  }
  ```

---

### `GET /api/feed`
Retrieves recent audit log events with threat intelligence enrichment.

- **Query Parameters**:
  - `limit` *(int, default: 100)*: Max events to return.
- **Authentication**: Requires valid admin session.

---

### `POST /api/unblock`
Manually releases an active firewall IP block.

- **Query Parameters**:
  - `ip` *(string, required)*: The IP address to unblock.
- **Response (`200 OK`)**:
  ```json
  {
    "status": "unblocked",
    "ip": "203.0.113.88",
    "reason": "manual_unblock_by_admin"
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
    "asn_gate_state": "healthy",
    "active_blocks_count": 3,
    "threat_intel_loaded": true
  }
  ```

---

### `GET /api/stats`
Returns live system metrics and graduated action breakdown.

- **Response (`200 OK`)**:
  ```json
  {
    "active_blocks_count": 14,
    "total_whitelist_count": 2,
    "asn_table_state": "healthy",
    "total_requests": 14200,
    "blocked_requests": 34,
    "action_breakdown": {
      "log": 14100,
      "rate_limit": 66,
      "challenge": 20,
      "temp_block": 14
    }
  }
  ```

---

### `GET /metrics`
Standard Prometheus metrics export endpoint for scraping by Prometheus and Grafana.

---

## 3. WebSocket Real-Time Stream

### `WS /ws/feed`
Real-time streaming feed broadcasting live requests, ML scoring, and firewall blocks with auto-reconnect.

- **Event Schema (`type: incident`)**:
  ```json
  {
    "type": "incident",
    "data": {
      "ts": 1724400100.0,
      "ip": "185.220.101.5",
      "raw_score": 0.9842,
      "action": "temp_block",
      "tier": "very_high",
      "ttl_seconds": 3600,
      "reason": "SQLMap blind time-based injection burst",
      "country": "DE",
      "is_tor": true
    }
  }
  ```
