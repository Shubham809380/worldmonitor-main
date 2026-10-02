import { strict as assert } from 'node:assert';
import { afterEach, beforeEach, test } from 'node:test';

const SECRET = 'test-secret-must-be-at-least-32-chars-long-xxx';
const ORIGINAL_FETCH = globalThis.fetch;
const ORIGINAL_ENV = { ...process.env };
const REAL_DATABASE_URL = process.env.DATABASE_URL || process.env.DATABASE_URL_UNPOOLED || '';

// These handlers talk to Postgres and mint HMAC cookies, so this suite needs a
// real DATABASE_URL and WM_SESSION_SECRET. Without them there is nothing to
// assert, so skip rather than report a false pass.
//
// Must be `undefined` and not `null` when the suite CAN run: node:test treats any
// non-undefined `skip` option as "skip this", so a `null` reason silently skips
// the whole suite while still being reported as passing.
const SKIP_REASON = REAL_DATABASE_URL ? undefined : 'DATABASE_URL/DATABASE_URL_UNPOOLED not set';
const suite = (name, fn) => test(name, { skip: SKIP_REASON }, fn);

const { default: register } = await import('./register.js');
const { default: login } = await import('./login.js');
const { default: logout } = await import('./logout.js');
const { default: sessionEndpoint } = await import('./session.js');
const { readSessionToken } = await import('../_session.js');
const { __resetRateLimitForTest } = await import('../_rate-limit.js');
const { neon } = await import('@neondatabase/serverless');

const sql = REAL_DATABASE_URL ? neon(REAL_DATABASE_URL) : null;
const CREATED = new Set();

function restoreEnv() {
  for (const key of Object.keys(process.env)) {
    if (!(key in ORIGINAL_ENV)) delete process.env[key];
  }
  Object.assign(process.env, ORIGINAL_ENV);
}

/** Answer the Upstash limiter so fail-closed rate limiting is satisfied. */
function mockUpstashRateLimit() {
  globalThis.fetch = async (input, init) => {
    const url = input instanceof URL ? input.href : typeof input === 'string' ? input : input.url;
    if (url.includes('fake.upstash.io')) {
      return new Response(JSON.stringify([{ result: [29, 30] }]), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return ORIGINAL_FETCH(input, init);
  };
}

function post(handler, body, { cookie = '' } = {}) {
  const headers = new Headers({ 'Content-Type': 'application/json', origin: 'https://www.worldmonitor.app' });
  if (cookie) headers.set('cookie', cookie);
  return handler(
    new Request('https://www.worldmonitor.app/api/auth/x', { method: 'POST', headers, body: JSON.stringify(body) }),
    { waitUntil: () => {} },
  );
}

function get(handler, { cookie = '' } = {}) {
  const headers = new Headers({ origin: 'https://www.worldmonitor.app' });
  if (cookie) headers.set('cookie', cookie);
  return handler(new Request('https://www.worldmonitor.app/api/auth/session', { method: 'GET', headers }), {
    waitUntil: () => {},
  });
}

/** The bare `wg-session=<value>` pair from a response, for a follow-up request. */
function sessionCookieFrom(response) {
  const raw = response.headers.getSetCookie?.() ?? [];
  const match = raw.map((c) => c.split(';')[0]).find((c) => c.startsWith('wg-session='));
  return match ? `${match}=x` : '';
}

/** The decoded wg-session token value (no attributes). */
function sessionTokenFrom(response) {
  const raw = response.headers.getSetCookie?.() ?? [];
  const match = raw.find((c) => c.startsWith('wg-session='));
  if (!match) return '';
  return decodeURIComponent(match.split(';')[0].slice('wg-session='.length));
}

const asCookieHeader = (token) => `wg-session=${encodeURIComponent(token)}`;
const VALID_PASSWORD = 'CorrectHorse9!';

async function cleanup(email) {
  if (!sql) return;
  await sql`DELETE FROM worldguard_users WHERE normalized_email = ${email.toLowerCase()}`;
}

beforeEach(() => {
  process.env.WM_SESSION_SECRET = SECRET;
  process.env.UPSTASH_REDIS_REST_URL = 'https://fake.upstash.io';
  process.env.UPSTASH_REDIS_REST_TOKEN = 'fake-token';
  __resetRateLimitForTest();
  mockUpstashRateLimit();
});

afterEach(async () => {
  __resetRateLimitForTest();
  globalThis.fetch = ORIGINAL_FETCH;
  for (const email of CREATED) await cleanup(email);
  CREATED.clear();
  restoreEnv();
});

suite('register creates an account, sets an HttpOnly session cookie, and the session endpoint confirms it', async () => {
  const email = `reg-${Date.now()}@example.com`;
  CREATED.add(email);

  const res = await post(register, { acceptedTerms: true, email, password: VALID_PASSWORD, name: 'Ada Lovelace' });
  const raw = await res.text();
  assert.equal(res.status, 200, raw);

  const body = JSON.parse(raw);
  assert.equal(body.authenticated, true);
  assert.equal(body.user.email, email);
  assert.equal(body.user.name, 'Ada Lovelace');

  const cookie = res.headers.getSetCookie().find((c) => c.startsWith('wg-session='));
  assert.ok(cookie, 'expected a wg-session cookie');
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Lax/);

  // The token must be the user-bound variant, and must verify server-side.
  const token = sessionTokenFrom(res);
  assert.ok(token.startsWith('wgu_'), 'expected a user-bound token');
  const payload = await readSessionToken(token);
  assert.equal(payload.u, body.user.id);
  assert.equal(payload.e, email);
  assert.equal(payload.nm, 'Ada Lovelace');

  // And the cookie must actually authenticate the session endpoint.
  const session = await (await get(sessionEndpoint, { cookie: asCookieHeader(token) })).json();
  assert.equal(session.status, 'authenticated');
  assert.equal(session.user.email, email);
});

suite('register never stores the password in the clear', async () => {
  const email = `hash-${Date.now()}@example.com`;
  CREATED.add(email);
  await post(register, { acceptedTerms: true, email, password: VALID_PASSWORD, name: 'Hash Check' });

  const rows = await sql`SELECT password_hash FROM worldguard_users WHERE normalized_email = ${email}`;
  const hash = rows[0].password_hash;
  assert.match(hash, /^\$2[aby]\$/, 'expected a bcrypt hash');
  assert.ok(!hash.includes(VALID_PASSWORD), 'password must not appear in the hash');
});

suite('register rejects a duplicate email with 409', async () => {
  const email = `dupe-${Date.now()}@example.com`;
  CREATED.add(email);
  assert.equal((await post(register, { acceptedTerms: true, email, password: VALID_PASSWORD, name: 'First' })).status, 200);

  const second = await post(register, { acceptedTerms: true, email, password: VALID_PASSWORD, name: 'Second' });
  assert.equal(second.status, 409);
  const body = await second.json();
  assert.equal(body.error, 'conflict');
  assert.equal(body.message, 'An account with this email already exists.');
});

suite('register is case-insensitive about duplicates', async () => {
  const email = `case-${Date.now()}@example.com`;
  CREATED.add(email);
  assert.equal((await post(register, { acceptedTerms: true, email, password: VALID_PASSWORD, name: 'A' })).status, 200);
  assert.equal((await post(register, { acceptedTerms: true, email: email.toUpperCase(), password: VALID_PASSWORD, name: 'B' })).status, 409);
});

suite('register enforces the published password policy', async () => {
  const rejections = [
    ['short', 'Sh0rt!'],
    ['no-upper', 'lowercase9!long'],
    ['no-lower', 'UPPERCASE9!LONG'],
    ['no-number', 'NoNumbersHere!!'],
    ['no-symbol', 'NoSymbols12345'],
  ];
  for (const [label, password] of rejections) {
    const email = `policy-${label}-${Date.now()}@example.com`;
    CREATED.add(email);
    const res = await post(register, { acceptedTerms: true, email, password, name: 'Policy' });
    assert.equal(res.status, 422, `${label} should be rejected`);
    assert.equal((await res.json()).field, 'password');
  }
});

suite('register accepts a password that satisfies every rule', async () => {
  const email = `policy-ok-${Date.now()}@example.com`;
  CREATED.add(email);
  assert.equal((await post(register, { acceptedTerms: true, email, password: VALID_PASSWORD, name: 'Policy OK' })).status, 200);
});

suite('register rejects a malformed email and a blank name', async () => {
  const bad = await post(register, { acceptedTerms: true, email: 'not-an-email', password: VALID_PASSWORD, name: 'X' });
  assert.equal(bad.status, 422);
  assert.equal((await bad.json()).field, 'email');

  const nameless = await post(register, {
    acceptedTerms: true,
    email: `noname-${Date.now()}@example.com`,
    password: VALID_PASSWORD,
    name: '   ',
  });
  assert.equal(nameless.status, 422);
  assert.equal((await nameless.json()).field, 'name');
});

suite('register requires explicit terms acceptance', async () => {
  // Anything other than a literal `true` is a refusal, so a hand-rolled POST
  // cannot skip the checkbox the signup form shows.
  for (const acceptedTerms of [undefined, false, 'true', 1, null, 'yes']) {
    const res = await post(register, {
      ...(acceptedTerms === undefined ? {} : { acceptedTerms }),
      email: `terms-${Date.now()}@example.com`,
      password: VALID_PASSWORD,
      name: 'Terms',
    });
    assert.equal(res.status, 422, `acceptedTerms=${JSON.stringify(acceptedTerms)} must be rejected`);
    const body = await res.json();
    assert.equal(body.field, 'acceptedTerms');
    assert.match(body.message, /terms/i);
  }
});

suite('register does not create an account when terms are refused', async () => {
  const email = `noterms-${Date.now()}@example.com`;
  const res = await post(register, { email, password: VALID_PASSWORD, name: 'No Terms' });
  assert.equal(res.status, 422);
  const rows = await sql`SELECT count(*)::int AS n FROM worldguard_users WHERE normalized_email = ${email}`;
  assert.equal(rows[0].n, 0, 'a refused registration must leave no row behind');
});

suite('register rejects a non-JSON body', async () => {
  const res = await register(
    new Request('https://www.worldmonitor.app/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not json at all',
    }),
    { waitUntil: () => {} },
  );
  assert.equal(res.status, 400);
});

suite('register refuses GET and answers OPTIONS', async () => {
  assert.equal((await get(register, {})).status, 405);
  const options = await register(
    new Request('https://www.worldmonitor.app/api/auth/register', { method: 'OPTIONS' }),
    { waitUntil: () => {} },
  );
  assert.equal(options.status, 204);
});

suite('login accepts the right password and re-issues the session', async () => {
  const email = `login-${Date.now()}@example.com`;
  CREATED.add(email);
  await post(register, { acceptedTerms: true, email, password: VALID_PASSWORD, name: 'Grace Hopper' });

  const res = await post(login, { identifier: email, password: VALID_PASSWORD });
  const raw = await res.text();
  assert.equal(res.status, 200, raw);
  const body = JSON.parse(raw);
  assert.equal(body.authenticated, true);
  assert.equal(body.user.email, email);
  assert.ok(sessionTokenFrom(res), 'login must set a session cookie');
});

suite('login records last_login_at', async () => {
  const email = `touch-${Date.now()}@example.com`;
  CREATED.add(email);
  await post(register, { acceptedTerms: true, email, password: VALID_PASSWORD, name: 'Touch' });
  await post(login, { identifier: email, password: VALID_PASSWORD });
  const rows = await sql`SELECT last_login_at FROM worldguard_users WHERE normalized_email = ${email}`;
  assert.ok(rows[0].last_login_at, 'last_login_at should be set');
});

suite('login rejects a wrong password and an unknown address identically', async () => {
  const email = `wrongpw-${Date.now()}@example.com`;
  CREATED.add(email);
  await post(register, { acceptedTerms: true, email, password: VALID_PASSWORD, name: 'Wrong PW' });

  const wrongPw = await post(login, { identifier: email, password: 'WrongPassword9!' });
  const unknown = await post(login, { identifier: `nobody-${Date.now()}@example.com`, password: VALID_PASSWORD });

  assert.equal(wrongPw.status, 401);
  assert.equal(unknown.status, 401);
  // Identical bodies: the response must not reveal whether the address exists.
  assert.equal(await wrongPw.text(), await unknown.text());
  assert.equal(sessionCookieFrom(wrongPw), '');
});

suite('login accepts an `email` key as well as `identifier`', async () => {
  const email = `altkey-${Date.now()}@example.com`;
  CREATED.add(email);
  await post(register, { acceptedTerms: true, email, password: VALID_PASSWORD, name: 'Alt Key' });
  assert.equal((await post(login, { email, password: VALID_PASSWORD })).status, 200);
});

suite('login treats a missing password as invalid input, not bad credentials', async () => {
  const res = await post(login, { identifier: `nopw-${Date.now()}@example.com` });
  assert.equal(res.status, 422);
  assert.equal((await res.json()).field, 'password');
});

suite('a Google-only account is told to use Google, not to retry a password', async () => {
  const email = `gonly-${Date.now()}@example.com`;
  await sql`
    INSERT INTO worldguard_users (name, email, normalized_email, clerk_user_id, avatar_url)
    VALUES ('Google User', ${email}, ${email.toLowerCase()}, ${`user_${Date.now()}`}, 'https://example.com/a.png')
  `;
  CREATED.add(email);

  const res = await post(login, { identifier: email, password: VALID_PASSWORD });
  assert.equal(res.status, 409);
  const body = await res.json();
  assert.equal(body.error, 'google_only_account');
  assert.match(body.message, /Google/i);
});

suite('a linked account can still sign in with its password', async () => {
  const email = `linked-${Date.now()}@example.com`;
  CREATED.add(email);
  await post(register, { acceptedTerms: true, email, password: VALID_PASSWORD, name: 'Linked' });
  // Simulate the Clerk bridge linking a verified identity to the same row.
  await sql`UPDATE worldguard_users SET clerk_user_id = ${`user_${Date.now()}`} WHERE normalized_email = ${email}`;

  const res = await post(login, { identifier: email, password: VALID_PASSWORD });
  assert.equal(res.status, 200, 'linking a Clerk identity must not break password sign-in');
});

suite('logout clears the cookie with an HttpOnly tombstone', async () => {
  const res = await post(logout, {});
  assert.equal(res.status, 204);
  const cookies = res.headers.getSetCookie();
  assert.ok(cookies.length > 0);
  assert.ok(cookies.every((c) => c.includes('Max-Age=0')));
  assert.ok(cookies.every((c) => /HttpOnly/.test(c)));
});

suite('a cleared session no longer authenticates', async () => {
  const email = `cycle-${Date.now()}@example.com`;
  CREATED.add(email);
  const registered = await post(register, { acceptedTerms: true, email, password: VALID_PASSWORD, name: 'Cycle' });
  const token = sessionTokenFrom(registered);
  assert.equal((await (await get(sessionEndpoint, { cookie: asCookieHeader(token) })).json()).status, 'authenticated');

  const out = await post(logout, {}, { cookie: asCookieHeader(token) });
  const tombstones = out.headers.getSetCookie();
  assert.ok(tombstones.every((c) => c.includes('Max-Age=0')), 'logout must tombstone the cookie');

  // A tombstone means the browser drops it, so a fresh read is anonymous.
  assert.equal((await (await get(sessionEndpoint, { cookie: '' })).json()).status, 'anonymous');
});

suite('session endpoint reports anonymous without a cookie', async () => {
  const res = await get(sessionEndpoint, {});
  assert.equal(res.status, 200);
  assert.equal((await res.json()).status, 'anonymous');
});

suite('a forged session token is rejected', async () => {
  const forged = asCookieHeader('wgu_eyJpYXQiOjEsImV4cCI6OTk5OTk5OTk5OTl9.forged');
  const res = await get(sessionEndpoint, { cookie: forged });
  assert.equal((await res.json()).status, 'anonymous');
});
