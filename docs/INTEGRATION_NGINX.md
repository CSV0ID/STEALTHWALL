#  Universal Nginx & Static HTML Integration Guide

This guide explains how to use StealthWall as an **Nginx Reverse Proxy Authentication Gate** to protect **ANY website or backend** (raw HTML, Go, Rust, Ruby on Rails, Java Spring Boot, Python, PHP) with **zero modifications to application source code**.

---

## 1. Nginx `auth_request` Architecture

```
Internet Visitor
       │
       ▼
 [Nginx Reverse Proxy]
       │
       ├─► (Subrequest) ──► [StealthWall Daemon:9377]
       │                         │
       │                   ┌─────┴─────┐
       │                   │ (Verdict) │
       │                   └─────┬─────┘
       │                         │
       ├─► If 200 OK ────────────┴──► Proxy to Target App / HTML Root
       │
       └─► If 403 Forbidden ────────► Return 403 & Drop Request
```

---

## 2. Nginx Server Configuration

Add this block to your Nginx configuration (e.g. `/etc/nginx/sites-available/default`):

```nginx
server {
    listen 80;
    server_name example.com;

    # 1. Verification gate subrequest
    location = /_stealthwall_auth {
        internal;
        proxy_pass http://127.0.0.1:9377/internal/decide;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_connect_timeout 50ms;
        proxy_read_timeout 50ms;
    }

    # 2. Main website / Application proxy
    location / {
        auth_request /_stealthwall_auth;

        # Serve static HTML or reverse proxy to backend:
        # root /var/www/html;
        proxy_pass http://127.0.0.1:8000;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Custom 403 page
    error_page 403 /403_blocked.html;
    location = /403_blocked.html {
        return 403 '{"error": "Forbidden", "message": "Blocked by StealthWall ML"}';
    }
}
```

---

## 3. Reload Nginx
```bash
sudo nginx -t && sudo systemctl reload nginx
```
Your entire website is now protected by StealthWall at the web server layer!
