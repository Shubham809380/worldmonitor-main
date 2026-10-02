import { strict as assert } from 'node:assert';
import { afterEach, beforeEach, test } from 'node:test';

import {
  clerkBridgeHandler,
  readClerkUserProfile,
  type ClerkBridgeDeps,
  type ClerkUserProfile,
} from '../api/auth/clerk-bridge.ts';
import { readSessionToken } from '../api/_session.js';
import register from '../api/auth/register.js';

const SECRET = 'test-secret-must-be-at-least-32-chars-long-xxx';
const REAL_DATABASE_URL = process.env.DATABASE_URL || process.env.DATABASE_URL_UNPOOLED || '';
// The handler mints a real HMAC session and writes a real row, so the
// behavioural cases need Postgres. The profile parser cases do NOT and run
// everywhere, including CI without credentials.
const needsDb = REAL_DATABASE_URL ? undefined : 'DATABASE_URL/DATABASE_URL_UNPOOLED not set';
const dbTest = (name: string, fn: () => Promise<void>) => test(name, { skip: needsDb }, fn);

const { neon } = await import('@neondatabase/serverless');
const sql = REAL_DATABASE_URL ? neon(REAL_DATABASE_URL) : null;
const CREATED = new Set<string>();

// `clerkBridgeHandler` opens with `isDbConfigured()` and answers 503
// `not_configured` before it inspects the token — correct in production, but it
// means every credential test asserts against the wrong response in CI without
// credentials. Satisfy that gate with an unroutable placeholder so those cases
// reach the logic they are about. `needsDb` above is already resolved from the
// REAL value, so the row-writing cases still skip rather than try this.
if (!REAL_DATABASE_URL) {
  process.env.DATABASE_URL = 'postgresql://placeholder:placeholder@127.0.0.1:1/placeholder';
}

const VALID_PASSWORD = 'CorrectHorse9!';

/**
 * The exact wire shape of `GET /v1/users/{id}`, per EmailAddressJSON in
 * @clerk/shared: the verification state is the key `verification`, and it is
 * nullable. Reproduced verbatim so a rename in Clerk breaks this test loudly
 * rather than silently unblocking every bridge in production.
 */
function clerkUserRecord(over: Record<string, unknown> = {}): unknown {
  return {
    object: 'user',
    id: 'user_2abc',
    primary_email_address_id: 'idn_primary',
    first_name: 'Grace',
    last_name: 'Hopper',
    image_url: 'https://img.clerk.com/grace.png',
    email_addresses: [
      {
        object: 'email_address',
        id: 'idn_secondary',
        email_address: 'secondary@example.com',
        verification: { status: 'verified' },
      },
      {
        object: 'email_address',
        id: 'idn_primary',
        email_address: 'grace@example.com',
        verification: { status: 'verified', strategy: 'oauth_google' },
      },
    ],
    ...over,
  };
}

/* ------------------------------------------------------------------ *
 * Profile parsing. No database, no network.
 * ------------------------------------------------------------------ */

test('readClerkUserProfile reads the primary address from Clerk wire shape', () => {
  const profile = readClerkUserProfile(clerkUserRecord());
  assert.deepEqual(profile, {
    email: 'grace@example.com',
    emailVerified: true,
    name: 'Grace Hopper',
    picture: 'https://img.clerk.com/grace.png',
  });
});

test('readClerkUserProfile trusts verification.status and nothing else', () => {
  // The field name is `verification`. A record that instead carried the
  // never-documented `email_verification` key must read as UNVERIFIED, because
  // an unreadable verification state must never authorise a link. Only the
  // exact string 'verified' is accepted; the positive case is asserted
  // separately so this list stays the deny set.
  for (const verification of [
    undefined,
    null,
    { status: 'unverified' },
    { status: 'transferable' },
    { status: 'failed' },
    { status: 'verified ' },
    { status: 'VERIFIED' },
    // The key this code once read by mistake. Carrying it must not verify.
    { email_verification: { status: 'verified' } },
  ] as unknown[]) {
    const profile = readClerkUserProfile(
      clerkUserRecord({
        email_addresses: [
          { object: 'email_address', id: 'idn_primary', email_address: 'grace@example.com', verification },
        ],
      }),
    );
    assert.equal(
      profile?.emailVerified,
      false,
      `verification=${JSON.stringify(verification)} must not be treated as verified`,
    );
  }
});

test('readClerkUserProfile only accepts the exact string "verified"', () => {
  const verified = readClerkUserProfile(
    clerkUserRecord({
      email_addresses: [
        {
          object: 'email_address',
          id: 'idn_primary',
          email_address: 'grace@example.com',
          verification: { status: 'verified' },
        },
      ],
    }),
  );
  assert.equal(verified?.emailVerified, true);
});

test('readClerkUserProfile falls back to the first address only without a primary pointer', () => {
  // No pointer to match, so array order decides. The fixture lists the
  // secondary first precisely so this cannot pass by accident via the primary.
  const record = clerkUserRecord({ primary_email_address_id: undefined });
  assert.equal(readClerkUserProfile(record)?.email, 'secondary@example.com');
});

test('readClerkUserProfile ignores a primary pointer that matches no address', () => {
  const record = clerkUserRecord({ primary_email_address_id: 'idn_does_not_exist' });
  // Unresolvable pointer: first entry, not an invented address.
  assert.equal(readClerkUserProfile(record)?.email, 'secondary@example.com');
});

test('readClerkUserProfile refuses records it cannot read an address from', () => {
  assert.equal(readClerkUserProfile(null), null);
  assert.equal(readClerkUserProfile(undefined), null);
  assert.equal(readClerkUserProfile('nope'), null);
  assert.equal(readClerkUserProfile({}), null);
  assert.equal(readClerkUserProfile({ email_addresses: [] }), null);
  assert.equal(readClerkUserProfile({ email_addresses: 'nope' }), null);
  assert.equal(readClerkUserProfile({ email_addresses: [null, 7] }), null);
  // An address object with no usable address string is not an identity.
  assert.equal(
    readClerkUserProfile({ email_addresses: [{ id: 'idn_1', verification: { status: 'verified' } }] }),
    null,
  );
  assert.equal(
    readClerkUserProfile({ email_addresses: [{ id: 'idn_1', email_address: '   ' }] }),
    null,
  );
});

test('readClerkUserProfile omits absent name and picture rather than blanking them', () => {
  const profile = readClerkUserProfile({
    primary_email_address_id: 'idn_primary',
    email_addresses: [
      { id: 'idn_primary', email_address: 'grace@example.com', verification: { status: 'verified' } },
    ],
  });
  assert.equal(profile?.emailVerified, true);
  assert.equal('name' in (profile as object), false);
  assert.equal('picture' in (profile as object), false);
});

/* ------------------------------------------------------------------ *
 * Handler behaviour. The DB write and session mint stay real.
 * ------------------------------------------------------------------ */

function bridgeDeps(over: Partial<ClerkBridgeDeps> = {}): ClerkBridgeDeps {
  return {
    validateBearerToken: async () => ({ valid: true, userId: 'user_2abc', email: 'grace@example.com' }),
    fetchClerkUser: async (): Promise<ClerkUserProfile | null> => ({
      email: 'grace@example.com',
      emailVerified: true,
      name: 'Grace Hopper',
    }),
    rateLimit: async () => null,
    ...over,
  };
}

function bridgeReq(body: unknown, { token = 'clerk-token', method = 'POST' } = {}): Request {
  const headers = new Headers({ 'Content-Type': 'application/json', origin: 'https://www.worldmonitor.app' });
  if (token) headers.set('authorization', `Bearer ${token}`);
  return new Request('https://www.worldmonitor.app/api/auth/clerk-bridge', {
    method,
    headers,
    body: method === 'GET' || method === 'OPTIONS' ? undefined : JSON.stringify(body ?? {}),
  });
}

function sessionCookieFrom(response: Response): string {
  const raw = response.headers.getSetCookie?.() ?? [];
  return raw.find((c) => c.startsWith('wg-session=')) ?? '';
}

beforeEach(() => {
  process.env.WM_SESSION_SECRET = SECRET;
});

afterEach(async () => {
  for (const email of CREATED) {
    if (sql) await sql`DELETE FROM worldguard_users WHERE normalized_email = ${email.toLowerCase()}`;
  }
  CREATED.clear();
});

test('the bridge refuses a request with no Clerk token', async () => {
  const res = await clerkBridgeHandler(bridgeReq({}, { token: '' }), bridgeDeps());
  assert.equal(res.status, 401);
  assert.equal((await res.json()).error, 'auth_required');
});

test('the bridge accepts the token from a JSON body as well as the header', async () => {
  const res = await clerkBridgeHandler(bridgeReq({ token: 'from-body' }, { token: '' }), bridgeDeps());
  // A body-supplied token still has to survive verification, so a stub that
  // accepts anything proves only that the body was read. Assert the read by
  // handing back a token and requiring a real answer from the DB-free arm.
  assert.notEqual(res.status, 401, 'a body token must be read, not treated as missing');
});

test('a confirmed-bad Clerk token is 401, not a retryable 503', async () => {
  const res = await clerkBridgeHandler(
    bridgeReq({}),
    bridgeDeps({ validateBearerToken: async () => ({ valid: false, reason: 'invalid' as never }) }),
  );
  assert.equal(res.status, 401);
  assert.equal((await res.json()).error, 'invalid_session');
});

test('an unverifiable token is a retryable 503, not a verdict on the user', async () => {
  const res = await clerkBridgeHandler(
    bridgeReq({}),
    bridgeDeps({ validateBearerToken: async () => ({ valid: false, reason: 'unverifiable' as never }) }),
  );
  assert.equal(res.status, 503);
  assert.equal((await res.json()).error, 'auth_unavailable');
});

test('a valid token with no subject is refused', async () => {
  const res = await clerkBridgeHandler(
    bridgeReq({}),
    bridgeDeps({ validateBearerToken: async () => ({ valid: true, userId: '' }) }),
  );
  assert.equal(res.status, 401);
  assert.equal((await res.json()).error, 'invalid_session');
});

test('an unreachable Clerk profile fails closed with 503 and writes no row', async () => {
  const res = await clerkBridgeHandler(bridgeReq({}), bridgeDeps({ fetchClerkUser: async () => null }));
  assert.equal(res.status, 503, 'an unresolvable identity must never be guessed past');
  assert.equal((await res.json()).error, 'identity_unavailable');
});

test('an unverified address is refused with 422 and never reaches the database', async () => {
  for (const emailVerified of [false, undefined as never, 'true' as never]) {
    const res = await clerkBridgeHandler(
      bridgeReq({}),
      bridgeDeps({ fetchClerkUser: async () => ({ email: 'grace@example.com', emailVerified }) }),
    );
    assert.equal(res.status, 422, `emailVerified=${JSON.stringify(emailVerified)} must be refused`);
    assert.equal((await res.json()).error, 'email_not_verified');
  }
});

test('the rate limiter runs before any Clerk or database call', async () => {
  let clerkCalls = 0;
  let verifyCalls = 0;
  const res = await clerkBridgeHandler(
    bridgeReq({}),
    bridgeDeps({
      rateLimit: async (_req, corsHeaders) => new Response(JSON.stringify({ error: 'rate_limited' }), { status: 429, headers: corsHeaders }),
      validateBearerToken: async () => {
        verifyCalls += 1;
        return { valid: true, userId: 'user_2abc' };
      },
      fetchClerkUser: async () => {
        clerkCalls += 1;
        return { email: 'grace@example.com', emailVerified: true };
      },
    }),
  );
  assert.equal(res.status, 429);
  assert.equal(verifyCalls, 0, 'the token must not be checked after the limiter refused');
  assert.equal(clerkCalls, 0, 'Clerk must not be called after the limiter refused');
});

test('OPTIONS answers the CORS preflight and other methods are refused', async () => {
  const preflight = await clerkBridgeHandler(bridgeReq(null, { method: 'OPTIONS' }), bridgeDeps());
  assert.equal(preflight.status, 204);

  const wrong = await clerkBridgeHandler(bridgeReq(null, { method: 'GET' }), bridgeDeps());
  assert.equal(wrong.status, 405);
  assert.equal(wrong.headers.get('Allow'), 'POST, OPTIONS');
  assert.equal((await wrong.json()).error, 'method_not_allowed');
});

dbTest('a first Google sign-in creates the account and sets an HttpOnly session cookie', async () => {
  const email = `bridge-create-${Date.now()}@example.com`;
  CREATED.add(email);

  const res = await clerkBridgeHandler(
    bridgeReq({}),
    bridgeDeps({
      fetchClerkUser: async () => ({ email, emailVerified: true, name: 'Grace Hopper' }),
    }),
  );
  const raw = await res.text();
  assert.equal(res.status, 200, raw);

  const body = JSON.parse(raw);
  assert.equal(body.authenticated, true);
  assert.equal(body.user.email, email);
  assert.equal(body.user.name, 'Grace Hopper');

  const cookie = sessionCookieFrom(res);
  assert.ok(cookie, 'expected a wg-session cookie');
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);

  // The minted token must be the user-bound variant and verify server-side.
  const token = decodeURIComponent(cookie.split(';')[0].slice('wg-session='.length));
  assert.ok(token.startsWith('wgu_'), 'expected a user-bound token');
  const payload = await readSessionToken(token);
  assert.equal(payload.u, body.user.id);
});

dbTest('a repeat bridge does not fork the account or reset its display name', async () => {
  const email = `bridge-idem-${Date.now()}@example.com`;
  CREATED.add(email);
  const clerkUserId = `user_${Date.now()}`;

  const deps = bridgeDeps({
    validateBearerToken: async () => ({ valid: true, userId: clerkUserId }),
    fetchClerkUser: async () => ({ email, emailVerified: true, name: 'Grace Hopper' }),
  });

  const first = await clerkBridgeHandler(bridgeReq({}), deps);
  const firstBody = await first.json();
  assert.equal(first.status, 200);

  // A later sign-in where Clerk has no name must not blank the stored one.
  const second = await clerkBridgeHandler(
    bridgeReq({}),
    bridgeDeps({
      validateBearerToken: async () => ({ valid: true, userId: clerkUserId }),
      fetchClerkUser: async () => ({ email, emailVerified: true, name: '' }),
    }),
  );
  const secondBody = await second.json();
  assert.equal(secondBody.user.id, firstBody.user.id, 'one identity must not become two accounts');
  assert.equal(secondBody.user.name, 'Grace Hopper');

  const rows = await sql`SELECT count(*)::int AS n FROM worldguard_users WHERE normalized_email = ${email}`;
  assert.equal(rows[0].n, 1, 'exactly one row per address');
});

dbTest('a verified address links onto an existing password account and keeps the password', async () => {
  const email = `bridge-link-${Date.now()}@example.com`;
  CREATED.add(email);
  const clerkUserId = `user_${Date.now()}`;

  const registered = await register(
    new Request('https://www.worldmonitor.app/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', origin: 'https://www.worldmonitor.app' },
      body: JSON.stringify({ acceptedTerms: true, email, password: VALID_PASSWORD, name: 'Password Person' }),
    }),
    { waitUntil: () => {} },
  );
  const registerRaw = await registered.text();
  assert.equal(registered.status, 200, registerRaw);
  const passwordUser = JSON.parse(registerRaw).user;

  const res = await clerkBridgeHandler(
    bridgeReq({}),
    bridgeDeps({
      validateBearerToken: async () => ({ valid: true, userId: clerkUserId }),
      fetchClerkUser: async () => ({ email, emailVerified: true, name: 'Google Person' }),
    }),
  );
  const bridgeRaw = await res.text();
  assert.equal(res.status, 200, bridgeRaw);
  const body = JSON.parse(bridgeRaw);
  assert.equal(body.user.id, passwordUser.id, 'linking must reuse the password account');

  // The whole point of the hybrid model: the password still works afterwards.
  const login = await import('../api/auth/login.js');
  const loginRes = await login.default(
    new Request('https://www.worldmonitor.app/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', origin: 'https://www.worldmonitor.app' },
      body: JSON.stringify({ identifier: email, password: VALID_PASSWORD }),
    }),
    { waitUntil: () => {} },
  );
  assert.equal(loginRes.status, 200, 'linking a Clerk identity must not break password sign-in');
});

dbTest('a token claim that disagrees with the Clerk profile does not select the account', async () => {
  const email = `bridge-mismatch-${Date.now()}@example.com`;
  CREATED.add(email);
  const clerkUserId = `user_${Date.now()}`;

  const res = await clerkBridgeHandler(
    bridgeReq({}),
    bridgeDeps({
      // The signed `email` claim names someone else's address. The authoritative
      // profile is the only thing allowed to choose the row.
      validateBearerToken: async () => ({ valid: true, userId: clerkUserId, email: 'attacker@example.com' }),
      fetchClerkUser: async () => ({ email, emailVerified: true, name: 'Real Person' }),
    }),
  );
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.equal(body.user.email, email, 'the Clerk profile, not the token claim, picks the account');
});
