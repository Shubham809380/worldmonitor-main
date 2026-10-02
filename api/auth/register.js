// POST /api/auth/register
//
// Creates a WorldGuard password account and signs the user in.
//
// Flow: validate on the server (the browser copy in
// src/worldguard/services/validation.ts is a UX affordance, not a boundary) ->
// hash the password with bcrypt -> insert the row -> mint the user-bound HMAC
// session token (api/_session.js) -> set it in the HttpOnly `wg-session` cookie
// (api/_wg-session.js) -> return the session summary.
//
// Duplicate email is settled by the unique index on `normalized_email`, not by
// a pre-flight SELECT: two concurrent registrations for one address can both
// pass a read, and only the constraint decides. The raised unique violation
// becomes 409 so the UI can show the duplicate-email message.
//
// The response deliberately carries no token: the browser's only window into the
// session is the cookie-backed /api/auth/session endpoint.
//
// Runs on the Node runtime rather than Edge so bcryptjs can use Node's crypto.
// Scrypt/argon2 were rejected because they cannot run under Vercel Edge.

import bcrypt from 'bcryptjs';

import { getCorsHeaders } from '../_cors.js';
import { authRateLimit } from '../_auth-rate-limit.js';
import { issueUserSessionToken } from '../_session.js';
import { wgSessionCookie } from '../_wg-session.js';
import { createPasswordUser, isDbConfigured, isUniqueViolation } from '../_worldguard-db.js';
import { readJsonBody, validateRegistration } from '../_auth-validate.js';

const RATE_LIMIT_SCOPE = 'auth-register';
const RATE_LIMIT_PER_MINUTE = 5;
const RATE_LIMIT_WINDOW = '60 s';

// bcrypt cost. OWASP's floor is 10; bcryptjs is pure JS and roughly 4x slower
// than the native binding, so 10 here costs about what native 12 would.
const BCRYPT_COST = 10;

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

  const validated = validateRegistration(body);
  if (!validated.ok) {
    return jsonResponse({ error: 'invalid_input', field: validated.field, message: validated.message }, 422, corsHeaders);
  }

  const { email, name, password } = validated.value;

  // Hash before touching the database so a duplicate insert is not paid for
  // with an unnecessary bcrypt round-trip.
  const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

  let user;
  try {
    user = await createPasswordUser({ name, email, passwordHash });
  } catch (error) {
    if (isUniqueViolation(error)) {
      return jsonResponse(
        { error: 'conflict', field: 'email', message: 'An account with this email already exists.' },
        409,
        corsHeaders,
      );
    }
    console.error('[auth-register] create_user_failed', error?.message);
    return jsonResponse({ error: 'server_error' }, 500, corsHeaders);
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
    // The account exists but no session was issued. Do not delete the account —
    // the user can sign in with the password they just chose.
    console.error('[auth-register] session_issue_failed', error?.message);
    return jsonResponse({ error: 'server_error' }, 500, corsHeaders);
  }

  return jsonResponse(
    { authenticated: true, user: { id: user.id, email: user.email, name: user.name } },
    200,
    corsHeaders,
    { 'Set-Cookie': wgSessionCookie(req, session.token) },
  );
}
