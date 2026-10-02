// POST /api/auth/clerk-bridge
//
// Exchanges a Clerk browser session for a WorldGuard session.
//
// Division of responsibility: Clerk OWNS the Google OAuth. It runs the popup,
// talks to Google, and holds the resulting browser session. WorldGuard does not
// re-implement any Google OAuth code. This endpoint is the one-way BRIDGE at the
// end of that flow:
//
//   1. The browser presents its Clerk session token as a Bearer credential.
//   2. We verify it locally against Clerk's JWKS (server/auth-session.ts — the
//      repo's audited verifier, reused so WorldGuard cannot drift from it).
//   3. We read the AUTHORITATIVE profile from the Clerk Backend API, by
//      `sub` only.
//   4. We resolve it to a row in `worldguard_users` (api/_worldguard-db.js) and
//      mint the same user-bound `wgu_` token the password endpoints issue.
//   5. The browser's only session handle becomes the HttpOnly `wg-session`
//      cookie, exactly as with a password login.
//
// WorldGuard never reads Clerk again after this call: the session cookie, not
// the Clerk token, is what the rest of the surface authorizes with. The Clerk
// token is a one-time bridge credential and is not persisted.
//
// SECURITY — why step 4 keys on a Clerk-API-confirmed verified email:
//   The signed JWT `email` claim is deliberately NOT trusted as the link key.
//   A Clerk JWT template is operator-configured and can emit `email` for an
//   account whose address is not verified; linking on it would let anyone who
//   can open a Clerk account on someone else's address adopt that person's
//   WorldGuard password account. So the token supplies only the identity
//   (`sub`), and the address comes from `verification.status === 'verified'`
//   on the Clerk Backend API. When that API is unreachable we fail closed with a
//   retryable 503 rather than guessing an address. Cost: one extra API call per
//   bridge, once per login — paid for one unambiguous linking rule.
//   The token's own `email`, when present, is used only as a cross-check that
//   warns on disagreement; it never selects the account.
//
// SECURITY — the bridge is unauthenticated by design at the HTTP layer, because
// the credential is the Clerk token itself. Every request therefore runs through
// the fail-closed auth rate limiter before any Clerk or database call, so an
// unauthenticated flood is bounded.
//
// Runs on the Edge runtime: jose and @neondatabase/serverless are both
// fetch-based, and no bcrypt is involved on this path.

// @ts-expect-error - JS module, no declaration file
import { authRateLimit } from '../_auth-rate-limit.js';
// @ts-expect-error - JS module, no declaration file
import { getCorsHeaders } from '../_cors.js';
// @ts-expect-error - JS module, no declaration file
import { issueUserSessionToken } from '../_session.js';
// @ts-expect-error - JS module, no declaration file
import { wgSessionCookie } from '../_wg-session.js';
import { isDbConfigured, upsertClerkUser } from '../_worldguard-db.js';
import { validateBearerToken, type SessionResult } from '../../server/auth-session';

export const config = { runtime: 'edge' };

const RATE_LIMIT_SCOPE = 'auth-clerk-bridge';
// Generous relative to the password endpoints: a legitimate user may retry a
// failed bridge, but this is still the pre-authenticated flood surface.
const RATE_LIMIT_PER_MINUTE = 10;
const RATE_LIMIT_WINDOW = '60 s';

// Bounded so a Clerk stall cannot pin an Edge invocation open indefinitely.
// Mirrors the bound in server/auth-session.ts.
const CLERK_PROFILE_TIMEOUT_MS = 5_000;

/** The subset of a Clerk user record this bridge is allowed to rely on. */
export interface ClerkUserProfile {
  email: string;
  /** True only when Clerk reports `verification.status === 'verified'`. */
  emailVerified: boolean;
  name?: string;
  picture?: string;
}

/**
 * Network and storage seams, injected for tests. The DB write and the session
 * mint stay REAL so tests exercise genuine linking and cookie behaviour against
 * Postgres; only the Clerk trust boundary and the limiter are faked.
 */
export interface ClerkBridgeDeps {
  validateBearerToken: (token: string) => Promise<SessionResult>;
  fetchClerkUser: (clerkUserId: string) => Promise<ClerkUserProfile | null>;
  rateLimit: (
    req: Request,
    corsHeaders: Record<string, string>,
  ) => Promise<Response | null>;
}

function jsonResponse(
  body: unknown,
  status: number,
  corsHeaders: Record<string, string>,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...corsHeaders,
      ...extraHeaders,
    },
  });
}

/**
 * Read the Clerk session token.
 *
 * Accepts a standard `Authorization: Bearer` header and, as the path the
 * WorldGuard client actually uses, a JSON `{ token }` body field. The body form
 * exists so a failed bridge cannot leave a Clerk token attached to ordinary
 * WorldGuard API traffic: the client sets it explicitly for this one call and
 * nowhere else. Both forms are equivalent — this is a bridge credential, not a
 * session, so neither is replayable without a live Clerk session.
 */
async function readClerkToken(req: Request): Promise<string | null> {
  const header = req.headers.get('authorization');
  if (typeof header === 'string') {
    const match = /^Bearer\s+(.+)$/i.exec(header.trim());
    const token = match?.[1]?.trim();
    if (token) return token;
  }
  try {
    const body: unknown = await req.json();
    if (body && typeof body === 'object') {
      const token = (body as { token?: unknown }).token;
      if (typeof token === 'string' && token.trim()) return token.trim();
    }
  } catch {
    // Not JSON, or already consumed. The header form above still applies.
  }
  return null;
}

/**
 * Read the primary address and its verification state from a Clerk user record.
 * Clerk marks exactly one address primary via `primary_email_address_id`; the
 * first-entry fallback is only for a record that omits the pointer.
 */
export function readClerkUserProfile(user: unknown): ClerkUserProfile | null {
  if (typeof user !== 'object' || user === null) return null;
  const record = user as {
    primary_email_address_id?: unknown;
    email_addresses?: unknown;
    first_name?: unknown;
    last_name?: unknown;
    image_url?: unknown;
  };
  if (!Array.isArray(record.email_addresses) || record.email_addresses.length === 0) {
    return null;
  }

  const addresses = record.email_addresses.filter(
    (entry): entry is Record<string, unknown> => typeof entry === 'object' && entry !== null,
  );
  if (addresses.length === 0) return null;

  const primaryId = typeof record.primary_email_address_id === 'string'
    ? record.primary_email_address_id
    : null;
  const matched = primaryId
    ? addresses.find((entry) => entry.id === primaryId)
    : undefined;
  const primary = matched ?? addresses[0];
  // `addresses` is non-empty and indexed access is unchecked here, so the
  // fallback can still be absent; refuse rather than invent an address.
  if (!primary) return null;

  const email = typeof primary.email_address === 'string' ? primary.email_address.trim() : '';
  if (!email) return null;

  // Clerk's Backend API serializes the verification state as `verification` on
  // the email_address record (EmailAddressJSON in @clerk/shared), and it is
  // explicitly nullable for an address with no verification attempt. Only the
  // exact status string 'verified' counts; anything else is unverified.
  const verification = primary.verification;
  const status =
    typeof verification === 'object' && verification !== null
      ? (verification as { status?: unknown }).status
      : undefined;

  const given = typeof record.first_name === 'string' ? record.first_name.trim() : '';
  const family = typeof record.last_name === 'string' ? record.last_name.trim() : '';
  const name = [given, family].filter(Boolean).join(' ');
  const picture = typeof record.image_url === 'string' ? record.image_url.trim() : '';

  return {
    email,
    // Anything other than the exact string 'verified' is treated as unverified.
    emailVerified: status === 'verified',
    ...(name ? { name } : {}),
    ...(picture ? { picture } : {}),
  };
}

/**
 * Production Clerk Backend API lookup, bounded and fail-closed: any transport,
 * status, or shape problem resolves null so the caller answers 503.
 */
export async function fetchClerkUserProfile(clerkUserId: string): Promise<ClerkUserProfile | null> {
  const secretKey = process.env.CLERK_SECRET_KEY;
  if (!secretKey) return null;

  try {
    const resp = await globalThis.fetch(`https://api.clerk.com/v1/users/${clerkUserId}`, {
      headers: {
        Authorization: `Bearer ${secretKey}`,
        // AGENTS.md: always set User-Agent on server-side fetches. Matches
        // server/auth-session.ts and the other sibling auth lookups.
        'User-Agent': 'worldmonitor-auth-bridge/1.0',
      },
      signal: AbortSignal.timeout(CLERK_PROFILE_TIMEOUT_MS),
    });
    if (!resp.ok) {
      console.warn(`[auth-clerk-bridge] Clerk profile lookup unavailable: http-${resp.status}`);
      return null;
    }
    return readClerkUserProfile(await resp.json());
  } catch (err) {
    console.warn(
      '[auth-clerk-bridge] Clerk profile lookup unavailable:',
      err instanceof Error ? err.message : String(err),
    );
    return null;
  }
}

export async function clerkBridgeHandler(
  req: Request,
  deps: ClerkBridgeDeps,
): Promise<Response> {
  const corsHeaders = getCorsHeaders(req, 'POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }
  if (req.method !== 'POST') {
    return jsonResponse({ error: 'method_not_allowed' }, 405, corsHeaders, {
      Allow: 'POST, OPTIONS',
    });
  }
  if (!isDbConfigured()) {
    return jsonResponse({ error: 'not_configured' }, 503, corsHeaders);
  }

  const limited = await deps.rateLimit(req, corsHeaders);
  if (limited) return limited;

  const token = await readClerkToken(req);
  if (!token) {
    return jsonResponse({ error: 'auth_required' }, 401, corsHeaders);
  }

  const session = await deps.validateBearerToken(token);
  if (!session.valid) {
    // 'unverifiable' means WE cannot check the token right now (JWKS issuer not
    // configured, or Clerk unreachable) — a deploy-side, retryable condition.
    // Everything else is a confirmed bad credential.
    if (session.reason === 'unverifiable') {
      return jsonResponse({ error: 'auth_unavailable' }, 503, corsHeaders);
    }
    return jsonResponse({ error: 'invalid_session' }, 401, corsHeaders);
  }

  const clerkUserId = session.userId;
  if (!clerkUserId) {
    return jsonResponse({ error: 'invalid_session' }, 401, corsHeaders);
  }

  // Identity is proven; now establish a verified address for it. A null profile
  // covers both "Clerk unreachable" and "no usable address" — neither may be
  // guessed past.
  const profile = await deps.fetchClerkUser(clerkUserId);
  if (!profile) {
    return jsonResponse({ error: 'identity_unavailable' }, 503, corsHeaders);
  }
  if (profile.emailVerified !== true) {
    return jsonResponse(
      {
        error: 'email_not_verified',
        message: 'Your sign-in provider has not verified this email address.',
      },
      422,
      corsHeaders,
    );
  }

  // Cross-check only. The signed claim never selects the account; a mismatch is
  // logged and ignored so the link still follows the authoritative record.
  if (session.email && session.email.toLowerCase() !== profile.email.toLowerCase()) {
    console.warn('[auth-clerk-bridge] token/profile email mismatch; using the Clerk profile');
  }

  let user;
  try {
    user = await upsertClerkUser({
      clerkUserId,
      email: profile.email,
      name: profile.name ?? session.name ?? '',
      picture: profile.picture ?? '',
      // Proven above; the helper independently re-checks this so no future
      // caller can reach the linking path without a verified address.
      emailVerified: true,
    });
  } catch (error) {
    console.error('[auth-clerk-bridge] upsert_failed', error instanceof Error ? error.message : error);
    return jsonResponse({ error: 'server_error' }, 500, corsHeaders);
  }

  let session_;
  try {
    session_ = await issueUserSessionToken({
      userId: user.id,
      email: user.email,
      name: user.name,
      picture: user.avatarUrl ?? '',
    });
  } catch (error) {
    console.error(
      '[auth-clerk-bridge] session_issue_failed',
      error instanceof Error ? error.message : error,
    );
    return jsonResponse({ error: 'server_error' }, 500, corsHeaders);
  }

  return jsonResponse(
    { authenticated: true, user: { id: user.id, email: user.email, name: user.name } },
    200,
    corsHeaders,
    { 'Set-Cookie': wgSessionCookie(req, session_.token) },
  );
}

export default async function handler(req: Request, ctx: unknown): Promise<Response> {
  return clerkBridgeHandler(req, {
    validateBearerToken,
    fetchClerkUser: fetchClerkUserProfile,
    rateLimit: (request, corsHeaders) =>
      authRateLimit(request, corsHeaders, {
        ctx: (ctx ?? {}) as Record<string, unknown>,
        scope: RATE_LIMIT_SCOPE,
        limit: RATE_LIMIT_PER_MINUTE,
        window: RATE_LIMIT_WINDOW,
      }),
  });
}