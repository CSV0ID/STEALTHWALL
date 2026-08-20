#  Next.js Edge Middleware Integration Guide

This guide explains how to protect **Next.js** applications (App Router and Pages Router) using Next.js Edge Middleware.

---

## 1. Setup in 1 File (`middleware.ts`)

Create a `middleware.ts` file in your Next.js project root:

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  // 1. Extract real client IP
  const ip = request.ip 
    || request.headers.get('x-forwarded-for')?.split(',')[0].trim() 
    || '127.0.0.1';

  // 2. Query local StealthWall decision daemon with 50ms fast timeout
  try {
    const res = await fetch('http://127.0.0.1:9377/internal/decide', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ip,
        path: request.nextUrl.pathname,
        method: request.method,
        ua: request.headers.get('user-agent') || '',
        ts: Date.now() / 1000
      }),
      signal: AbortSignal.timeout(50) // 50ms fast fail-open
    });

    if (res.ok) {
      const decision = await res.json();
      
      // If malicious activity was detected and blocked:
      if (['temp_block', 'provisional_block', 'long_cooldown_block'].includes(decision.action)) {
        return new NextResponse(
          JSON.stringify({
            error: 'Forbidden',
            message: 'Access blocked by StealthWall intrusion prevention.',
            incident_ip: ip
          }),
          {
            status: 403,
            headers: { 'content-type': 'application/json' }
          }
        );
      }
    }
  } catch (err) {
    // Fail-open: Never block innocent traffic if daemon is unreachable
  }

  return NextResponse.next();
}

// 3. Match all application routes, excluding static assets
export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

---

## 2. Advantages of Next.js Middleware Integration:
- **Edge Execution**: Malicious requests are stopped before rendering React components or executing server actions.
- **Fail-Open Safety**: Uses `AbortSignal.timeout(50)` so even if the security daemon is rebooting, your Next.js app stays 100% online.
