import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * STEALTHWALL — Drop-in Next.js Edge Middleware.
 * Place this file as `middleware.ts` in your Next.js root.
 */
export async function middleware(request: NextRequest) {
  const ip = request.ip 
    || request.headers.get('x-forwarded-for')?.split(',')[0].trim() 
    || '127.0.0.1';

  // Fast evaluation check against local StealthWall daemon
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
      signal: AbortSignal.timeout(50) // 50ms fast timeout
    });

    if (res.ok) {
      const decision = await res.json();
      if (['temp_block', 'provisional_block', 'long_cooldown_block'].includes(decision.action)) {
        return new NextResponse(
          JSON.stringify({ error: 'Forbidden', reason: 'Blocked by StealthWall ML' }),
          { status: 403, headers: { 'content-type': 'application/json' } }
        );
      }
    }
  } catch (e) {
    // Fail-open: Never block innocent traffic if daemon is unreachable
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
