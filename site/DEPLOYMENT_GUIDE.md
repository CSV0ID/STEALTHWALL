# Production Deployment Architecture Guide

STEALTHWALL is architected for total infrastructure flexibility. You can deploy as a monolithic server, a decoupled Jamstack app, or a serverless edge middleware.

---

## Architecture 1: Decoupled (Frontend on Vercel + Backend on VPS / Cloud)

This is the most common modern production setup:

```
[ Visitor / Attacker ]
          │
          ▼
┌─────────────────────────┐
│   Frontend (Vercel)     │  <-- Next.js, React, or Static UI on Vercel / Netlify / S3
│   (UI & Public App)     │
└────────────┬────────────┘
             │ (HTTPS / WSS / REST)
             ▼
┌─────────────────────────┐
│   Backend (VPS / Cloud) │  <-- STEALTHWALL Daemon on AWS EC2, DigitalOcean, Hetzner
│   STEALTHWALL Core      │
└─────────────────────────┘
```

### 1. Run the Backend on your VPS (Docker or Native)
```bash
# Via Docker Compose:
docker compose up -d

# Or natively via Python:
pip install stealthwall
export STEALTHWALL_ADMIN_USER="security_admin"
export STEALTHWALL_ADMIN_PASSWORD="StrongProductionPassword!2026"
stealthwall dashboard --port 8000
```

### 2. Connect Your Frontend (Vercel / Netlify)
In your frontend `.env.production` or Vercel Environment Variables:
```env
NEXT_PUBLIC_STEALTHWALL_API=https://api.yourdomain.com
NEXT_PUBLIC_STEALTHWALL_WS=wss://api.yourdomain.com/ws/feed
```

---

## Architecture 2: Pure Frontend Protection via Next.js Edge Middleware

If your application is 100% frontend on Vercel with zero dedicated backend servers:

1. Copy `integrations/nextjs/middleware.ts` into your Next.js project root:
   ```typescript
   // middleware.ts
   import { NextResponse } from 'next/server';
   import type { NextRequest } from 'next/server';

   export async function middleware(req: NextRequest) {
     const decision = await fetch('https://api.yourdomain.com/internal/decide', {
       method: 'POST',
       headers: { 'Content-Type': 'application/json' },
       body: JSON.stringify({
         ip: req.ip || req.headers.get('x-forwarded-for') || '127.0.0.1',
         path: req.nextUrl.pathname,
         method: req.method,
         ua: req.headers.get('user-agent') || ''
       })
     }).then(r => r.json()).catch(() => ({ action: 'log' }));

     if (decision.action && decision.action.includes('block')) {
       return new NextResponse('403 Forbidden - Blocked by STEALTHWALL', { status: 403 });
     }
     return NextResponse.next();
   }
   ```
2. Vercel Edge automatically filters traffic before executing frontend server components.

---

## Architecture 3: Native Linux / VPS Deployment (Without Docker)

To run entirely natively on Ubuntu / Debian / Rocky Linux:

```bash
# 1. Install STEALTHWALL and Uvicorn
pip3 install stealthwall uvicorn

# 2. Set up Systemd Service for Auto-restart on Boot
sudo nano /etc/systemd/system/stealthwall.service
```

```ini
[Unit]
Description=STEALTHWALL Control Plane & SOC Dashboard
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/stealthwall
Environment="STEALTHWALL_ADMIN_USER=admin"
Environment="STEALTHWALL_ADMIN_PASSWORD=YourPasswordHere"
ExecStart=/usr/local/bin/stealthwall dashboard --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
# 3. Enable and Start
sudo systemctl daemon-reload
sudo systemctl enable --now stealthwall
```

---

## Architecture 4: All-in-One Multi-Container Stack (Docker Compose)

```yaml
version: '3.8'

services:
  stealthwall:
    build: .
    ports:
      - "8000:8000"
    environment:
      - STEALTHWALL_ADMIN_USER=admin
      - STEALTHWALL_ADMIN_PASSWORD=admin123
      - REDIS_HOST=redis
    depends_on:
      - redis
    restart: always

  redis:
    image: redis:7-alpine
    restart: always

  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
    restart: always
```

Run:
```bash
docker compose up -d
```
