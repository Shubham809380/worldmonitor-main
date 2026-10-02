// POST /api/auth/login
//
// Signs an existing WorldGuard password account in: validate -> look the account
// up by normalized email -> bcrypt-compare -> mint the user-bound HMAC session
// token (api/_session.js) -> set it in the HttpOnly `wg-session` cookie
// (api/_wg-session.js).
//
// User-enumeration resistance: an unknown address and a wrong password return
// the identical 401 body, and the not-found path still performs a bcrypt
// comparison against a fixed dummy hash so the response time does not reveal
// whether an address is registered.
//
// A Google-only account (clerk_user_id set, password_hash NULL) is not a password
// account. It is reported as 409 with a message pointing at Google rather than
// 401, because telling that user to retry a password they never set would be
// misleading, and hiding it would strand them.
//
// Runs on the Node runtime so bcryptjs can use Node's crypto.

import bcrypt from 'bcryptjs';

import { getCorsHeaders } from '../_cors.js';
import { authRateLimit } from '../_auth-rate-limit.js';
import { issueUserSessionToken } from '../_session.js';
import { wgSessionCookie } from '../_wg-session.js';
import { findUserByEmail, isDbConfigured, touchLastLogin } from '../_worldguard-db.js';
import { readJsonBody, validateLogin } from '../_auth-validate.js';

const RATE_LIMIT_SCOPE = 'auth-login';
const RATE_LIMIT_PER_MINUTE = 10;
const RATE_LIMIT_WINDOW = '60 s';

// Cost must match api/auth/register.js so the dummy comparison below costs the
// same as a real one. A valid bcrypt hash of a value nobody knows, used only to
// burn the same CPU when the address is unknown.
const BCRYPT_COST = 10;
const DUMMY_HASH = '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy';

const GENERIC_FAILURE = { error: 'invalid_credentials' };

function jsonResponse(body, status, corsHeaders, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...corsHeaders, ...extraHeaders },
  });
}

export default async function handler(req, ctx) {
  const corsHeaders = getCorsHeaders(req, 'POST, OPTIONS');

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== 'POST') {
    return jsonResponse({ error: 'method_not_allowed' }, 405, corsHeaders, { Allow: 'POST, OPTIONS' });
  }

  if (!isDbConfigured()) {
    return jsonResponse({ error: 'not_configured' }, 503, corsHeaders);
  }

  // Tighter than register: this is the endpoint worth guessing against.
  const rl = await authRateLimit(req, corsHeaders, {
    ctx: ctx ?? {},
    scope: RATE_LIMIT_SCOPE,
    limit: RATE_LIMIT_PER_MINUTE,
    window: RATE_LIMIT_WINDOW,
  });
  if (rl) return rl;

  const body = await readJsonBody(req);
  if (!body) {
    return jsonResponse({ error: 'invalid_input', field: 'body' }, 400, corsHeaders);
  }

  const validated = validateLogin(body);
  if (!validated.ok) {
    return jsonResponse({ error: 'invalid_input', field: validated.field, message: validated.message }, 422, corsHeaders);
  }

  const { identifier, password } = validated.value;

  let user = null;
  try {
    user = await findUserByEmail(identifier);
  } catch (error) {
    console.error('[auth-login] lookup_failed', error?.message);
    return jsonResponse({ error: 'server_error' }, 500, corsHeaders);
  }

  // Always run a comparison so the timing of every exit below matches: unknown
  // address, Google-only address, and wrong password all cost one bcrypt.
  const isKnownUser = Boolean(user);
  const hasLocalPassword = Boolean(user?.passwordHash);
  const hashToCompare = user?.passwordHash ?? DUMMY_HASH;
  let passwordMatches = false;
  try {
    passwordMatches = await bcrypt.compare(password, hashToCompare);
  } catch {
    passwordMatches = false;
  }

  // A Google-only account has no local password, so it can never satisfy the
  // comparison above. Branch on it before the generic failure, or this would be
  // dead code and the user would be told to retry a password they never set.
  if (isKnownUser && !hasLocalPassword) {
    return jsonResponse(
      { error: 'google_only_account', message: 'This account uses Google sign-in. Continue with Google instead.' },
      409,
      corsHeaders,
    );
  }

  if (!isKnownUser || !passwordMatches) {
    return jsonResponse(GENERIC_FAILURE, 401, corsHeaders);
  }

  try {
    user = (await touchLastLogin(user.id)) ?? user;
  } catch (error) {
    // A failed bookkeeping write must not block a valid sign-in.
    console.error('[auth-login] touch_last_login_failed', error?.message);
  }

  let session;
  try {
    session = await issueUserSessionToken({
      userId: user.id,
      email: user.email,
      name: user.name,
      picture: user.avatarUrl ?? '',
    });
  } catch (error) {
    console.error('[auth-login] session_issue_failed', error?.message);
    return jsonResponse({ error: 'server_error' }, 500, corsHeaders);
  }

  return jsonResponse(
    { authenticated: true, user: { id: user.id, email: user.email, name: user.name } },
    200,
    corsHeaders,
    { 'Set-Cookie': wgSessionCookie(req, session.token) },
  );
}
