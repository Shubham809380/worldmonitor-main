// Rate limiting for the WorldGuard credential endpoints (register, login,
// clerk-bridge) and the local dev server.
//
// WHY THIS EXISTS
//   The credential endpoints treat the rate limit AS the abuse defence: an
//   attacker can enumerate passwords against /api/auth/login without it. So the
//   production posture is `failClosed: true` — if Upstash is unreachable, refuse
//   the request rather than serve it unthrottled. That is the correct trade for
//   production and the wrong one for `npm run dev`: without Upstash configured
//   locally every sign-in returned 503 `Rate-limit service temporarily
//   unavailable`, which is indistinguishable from "the app is broken" and blocked
//   all local sign-in work.
//
//   So: production keeps failing closed, and the dev server substitutes an
//   in-process limiter instead. Local development gets a real (if per-process)
//   budget rather than an outage, and production behaviour is untouched.
//
// PRODUCTION DETECTION
//   `VERCEL_ENV` is the deployed signal; on Vercel it is `production`,
//   `preview`, or `development`. Everything else — `npm run dev`, a bare
//   `vite build` preview, CI — is treated as non-production. This is
//   deliberately fail-toward-the-limit: an unrecognised environment is a
//   workstation, and a workstation does not need a distributed budget. A
//   production deploy is never affected because Vercel always sets VERCEL_ENV.
//
//   The in-memory path is per-process and lost on restart. That is acceptable
//   precisely because it is unreachable in production; it is a development
//   affordance, not a second implementation of the production control.
//
// UPSTASH STILL WINS IN DEV
//   When Upstash IS configured locally, this delegates to it unchanged. The
//   in-memory fallback only engages when there is nothing to delegate to.

/**
 * True when this process is a real deployment, where an unreachable Redis must
 * fail the request closed rather than fall back to a per-process budget.
 */
export function isProductionRuntime() {
  const vercelEnv = process.env.VERCEL_ENV;
  if (typeof vercelEnv === 'string' && vercelEnv.length > 0) {
    return vercelEnv !== 'development';
  }
  // Not on Vercel at all. Treat a plain `NODE_ENV=production` build as
  // production; otherwise this is a workstation.
  return process.env.NODE_ENV === 'production';
}

function upstashConfigured() {
  return Boolean(process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN);
}

// ---- In-process dev limiter ------------------------------------------------

const buckets = new Map();

/** Periodic sweep so a long dev session cannot accumulate empty buckets. */
let lastSweep = Date.now();

function sweep(now) {
  // A minute of slack keeps a request that arrives just before expiry counted
  // against the bucket it started in, rather than resetting it early.
  if (now - lastSweep < 60_000) return;
  lastSweep = now;
  for (const [key, bucket] of buckets) {
    if (bucket.windowStart + 60_000 <= now) buckets.delete(key);
  }
}

/**
 * Consume one unit from `key`'s budget for the current minute.
 *
 * Returns null when the caller may proceed, or a ready-to-return 503-style
 * `Response` when the budget is exhausted.
 */
function consumeInProcess(key, limit, corsHeaders) {
  const now = Date.now();
  sweep(now);

  const existing = buckets.get(key);
  if (!existing || existing.windowStart + 60_000 <= now) {
    buckets.set(key, { key, windowStart: now, count: 1 });
    return null;
  }

  existing.count += 1;
  if (existing.count <= limit) return null;

  const retryAfter = Math.max(1, Math.ceil((existing.windowStart + 60_000 - now) / 1000));
  return new Response(
    JSON.stringify({
      error: 'rate_limited',
      message: 'Too many attempts. Please wait a moment and try again.',
    }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store',
        'Retry-After': String(retryAfter),
        ...corsHeaders,
      },
    },
  );
}

/**
 * Best-effort caller identity for the in-process budget. Deliberately coarse:
 * this only has to stop a runaway script or a held-down key in a single
 * dev-server process, so the header is trusted here and nowhere else.
 */
function devClientKey(req) {
  const forwarded = req.headers.get('x-forwarded-for');
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0].trim() || 'unknown';
  }
  return req.headers.get('x-real-ip') || 'local';
}

/**
 * Rate-limit a WorldGuard credential request.
 *
 * Delegates to the shared Upstash-backed `checkRateLimit` whenever that is
 * configured or whenever this is a production deploy. Only a non-production
 * runtime with no Upstash falls back to the in-process budget.
 *
 * `scope` should identify the endpoint so the budgets stay independent, and
 * `limit` is per minute per client.
 */
export async function authRateLimit(req, corsHeaders, opts) {
  const production = isProductionRuntime();

  if (production || upstashConfigured()) {
    const { checkRateLimit } = await import('./_rate-limit.js');
    return checkRateLimit(req, corsHeaders, {
      failClosed: true,
      ctx: opts.ctx ?? {},
      scope: opts.scope,
      limit: opts.limit,
      window: opts.window ?? '60 s',
    });
  }

  return consumeInProcess(`${opts.scope}:${devClientKey(req)}`, opts.limit, corsHeaders);
}
