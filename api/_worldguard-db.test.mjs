import { strict as assert } from 'node:assert';
import { afterEach, beforeEach, test } from 'node:test';

import {
  createPasswordUser,
  findUserByEmail,
  findUserByClerkUserId,
  isUniqueViolation,
  touchLastLogin,
  upsertClerkUser,
} from './_worldguard-db.js';

const { neon } = await import('@neondatabase/serverless');
// bcryptjs is CommonJS: only `default` is exposed under ESM, same as api/auth/*.
const { default: bcrypt } = await import('bcryptjs');

const REAL_DATABASE_URL = process.env.DATABASE_URL || process.env.DATABASE_URL_UNPOOLED || '';
// The DB-backed cases need a real Neon URL. The `emailVerified` policy cases do
// NOT — upsertClerkUser throws before it ever opens a connection — so they run
// everywhere, including CI without credentials.
const needsDb = REAL_DATABASE_URL ? undefined : 'DATABASE_URL/DATABASE_URL_UNPOOLED not set';
const dbTest = (name, fn) => test(name, { skip: needsDb }, fn);

const sql = REAL_DATABASE_URL ? neon(REAL_DATABASE_URL) : null;
const CREATED = new Set();

async function cleanup(email) {
  if (!sql) return;
  await sql`DELETE FROM worldguard_users WHERE normalized_email = ${email.toLowerCase()}`;
}

beforeEach(() => {
  CREATED.clear();
});

afterEach(async () => {
  for (const email of CREATED) await cleanup(email);
  CREATED.clear();
});

const VERIFIED = { emailVerified: true };
const CLERK = (over = {}) => ({
  clerkUserId: 'user_1',
  email: 'user@example.com',
  name: 'User',
  picture: '',
  ...VERIFIED,
  ...over,
});

/* ------------------------------------------------------------------ *
 * Policy: linking is only ever allowed on a Clerk-verified address.
 * These need no database.
 * ------------------------------------------------------------------ */

test('upsertClerkUser refuses an unverified email', async () => {
  for (const emailVerified of [undefined, false, null, 'true', 1, 0]) {
    await assert.rejects(
      () => upsertClerkUser(CLERK({ emailVerified })),
      /not verified/,
      `emailVerified=${JSON.stringify(emailVerified)} must be rejected`,
    );
  }
});

test('upsertClerkUser requires a Clerk id and an email even when verified', async () => {
  await assert.rejects(() => upsertClerkUser(CLERK({ clerkUserId: '  ' })), /required/);
  await assert.rejects(() => upsertClerkUser(CLERK({ email: '  ' })), /required/);
});

test('isUniqueViolation only recognises Postgres 23505', () => {
  assert.equal(isUniqueViolation({ code: '23505' }), true);
  assert.equal(isUniqueViolation({ message: 'duplicate key value violates unique constraint' }), true);
  assert.equal(isUniqueViolation({ code: '23503' }), false);
  assert.equal(isUniqueViolation(null), false);
  assert.equal(isUniqueViolation(new Error('connection reset')), false);
});

/* ------------------------------------------------------------------ *
 * Behavior: requires Neon.
 * ------------------------------------------------------------------ */

dbTest('a verified first sign-in creates a Clerk-only account with no password', async () => {
  const email = `gcreate-${Date.now()}@example.com`;
  CREATED.add(email);

  const user = await upsertClerkUser(CLERK({ clerkUserId: `user_${Date.now()}`, email }));
  assert.equal(user.email, email);
  assert.equal(user.clerkUserId.startsWith('user_'), true);
  assert.equal(user.passwordHash, null, 'a Clerk-only account must not fabricate a password');

  // Reachable by sub, which is what makes repeat sign-ins work.
  assert.equal((await findUserByClerkUserId(user.clerkUserId)).id, user.id);
});

dbTest('a verified email links onto an existing password account and keeps the password', async () => {
  const email = `glink-${Date.now()}@example.com`;
  CREATED.add(email);

  const passwordUser = await createPasswordUser({
    name: 'Password Person',
    email,
    passwordHash: bcrypt.hashSync('placeholder-not-a-real-password', 4),
  });

  const linked = await upsertClerkUser(CLERK({ clerkUserId: `user_${Date.now()}`, email, name: 'Clerk Person' }));
  assert.equal(linked.id, passwordUser.id, 'linking must reuse the existing row, not create a second account');
  assert.equal(linked.passwordHash, passwordUser.passwordHash, 'linking must not disturb the stored password');

  // One human, one account: the email still resolves to exactly that row.
  assert.equal((await findUserByEmail(email)).id, passwordUser.id);
  assert.equal((await findUserByClerkUserId(linked.clerkUserId)).id, passwordUser.id);
});

dbTest('repeat sign-ins with the same sub are idempotent', async () => {
  const email = `gidemp-${Date.now()}@example.com`;
  CREATED.add(email);
  const clerkId = `user_${Date.now()}`;

  const first = await upsertClerkUser(CLERK({ clerkUserId: clerkId, email }));
  const second = await upsertClerkUser(CLERK({ clerkUserId: clerkId, email, name: 'Renamed' }));
  assert.equal(second.id, first.id, 'the same Clerk identity must not fork into two accounts');
  assert.equal(second.name, 'Renamed', 'a later sign-in may refresh the display name');

  const rows = await sql`SELECT count(*)::int AS n FROM worldguard_users WHERE normalized_email = ${email}`;
  assert.equal(rows[0].n, 1, 'exactly one row per address');
});

dbTest('an empty Clerk name falls back instead of blanking the display name', async () => {
  const email = `gname-${Date.now()}@example.com`;
  CREATED.add(email);
  const user = await upsertClerkUser(CLERK({ clerkUserId: `user_${Date.now()}`, email, name: '' }));
  assert.ok(user.name && user.name.length > 0, 'name must never be empty');

  // A later sign-in that omits the name must not erase what we already have.
  const again = await upsertClerkUser(CLERK({ clerkUserId: user.clerkUserId, email, name: '' }));
  assert.equal(again.name, user.name);
});

dbTest('duplicate email registration raises a unique violation rather than a second row', async () => {
  const email = `dbdupe-${Date.now()}@example.com`;
  CREATED.add(email);
  await createPasswordUser({ name: 'First', email, passwordHash: 'x' });
  await assert.rejects(
    () => createPasswordUser({ name: 'Second', email, passwordHash: 'y' }),
    (err) => isUniqueViolation(err),
    'the unique index must be the authority on duplicates',
  );
});

dbTest('email lookup is case-insensitive', async () => {
  const email = `dbcase-${Date.now()}@example.com`;
  CREATED.add(email);
  const user = await createPasswordUser({ name: 'Case', email, passwordHash: 'x' });
  assert.equal((await findUserByEmail(email.toUpperCase())).id, user.id);
});

dbTest('touchLastLogin updates the timestamp', async () => {
  const email = `dbtouch-${Date.now()}@example.com`;
  CREATED.add(email);
  const user = await createPasswordUser({ name: 'Touch', email, passwordHash: 'x' });
  const touched = await touchLastLogin(user.id);
  assert.equal(new Date(touched.lastLoginAt).getTime() >= new Date(user.createdAt).getTime(), true);
});
