// Postgres access for WorldGuard local accounts (api/auth/register.js,
// api/auth/login.js, api/auth/clerk-bridge.ts).
//
// Store ownership: `worldguard_users` is the single identity table for the
// custom auth surface. It is deliberately separate from Convex `users`, which is
// Clerk-keyed for the main dashboard's billing/entitlement features — nothing in
// that lifecycle (deletion webhooks, Pro entitlements) applies to WorldGuard
// accounts.
//
// Clerk's role is deliberately narrow: it brokers the Google OAuth and holds
// the browser session, and this table is where that identity becomes durable
// for WorldGuard. A row can carry a local password, a Clerk identity, or both:
//   password only -> password_hash set,   clerk_user_id NULL
//   Clerk only   -> clerk_user_id set,    password_hash NULL
//   linked       -> both set, matched on the verified email at bridge time
//
// Driver: @neondatabase/serverless `neon()` — a fetch/HTTP tagged-query client,
// so it runs unchanged on the Vercel Edge runtime and in Node (the Vite dev
// dispatcher and the Node test suite) without a TCP pool or `node:net`.
//
// Secrets: reads the same pooled/unpooled pair the rest of the app uses
// (DATABASE_URL, then DATABASE_URL_UNPOOLED). Nothing is hardcoded and no env
// parser is introduced.
//
// NOTE: `neon()` only binds *parameters* for `${}` interpolations — there is no
// safe identifier interpolation — so every column list below is literal SQL.
// Never interpolate a caller-supplied string here.

import { neon } from '@neondatabase/serverless';

let cachedSql = null;

function connectionString() {
  return process.env.DATABASE_URL || process.env.DATABASE_URL_UNPOOLED || '';
}

/** False when no Postgres URL is configured, so callers can answer `not_configured`. */
export function isDbConfigured() {
  return Boolean(connectionString());
}

function sql() {
  if (cachedSql) return cachedSql;
  const url = connectionString();
  if (!url) throw new Error('DATABASE_URL is not configured');
  cachedSql = neon(url);
  return cachedSql;
}

function normalizeEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : '';
}

function rowToUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    normalizedEmail: row.normalized_email,
    passwordHash: row.password_hash,
    clerkUserId: row.clerk_user_id,
    avatarUrl: row.avatar_url,
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at,
  };
}

// Clerk omits the name for some accounts; fall back to the local part of the
// address so the UI never shows an empty name.
function fallbackName(name, email) {
  return name || String(email).split('@')[0] || 'WorldGuard user';
}

/** Look up one account by email (case-insensitive). Returns null when absent. */
export async function findUserByEmail(email) {
  const normalized = normalizeEmail(email);
  if (!normalized) return null;
  const rows = await sql()`
    SELECT * FROM worldguard_users WHERE normalized_email = ${normalized} LIMIT 1
  `;
  return rowToUser(rows[0]);
}

/** Look up one account by its Clerk user id. Returns null when absent. */
export async function findUserByClerkUserId(clerkUserId) {
  const id = typeof clerkUserId === 'string' ? clerkUserId.trim() : '';
  if (!id) return null;
  const rows = await sql()`
    SELECT * FROM worldguard_users WHERE clerk_user_id = ${id} LIMIT 1
  `;
  return rowToUser(rows[0]);
}

/**
 * Create a password account.
 *
 * The unique index on normalized_email is the authority on duplicates, not a
 * pre-flight SELECT: two concurrent registrations for the same address can both
 * pass a read, and only the constraint settles it. Callers must treat a unique
 * violation (see `isUniqueViolation`) as `conflict`.
 */
export async function createPasswordUser({ name, email, passwordHash }) {
  const trimmedEmail = String(email).trim();
  const rows = await sql()`
    INSERT INTO worldguard_users (name, email, normalized_email, password_hash, last_login_at)
    VALUES (${String(name).trim()}, ${trimmedEmail}, ${normalizeEmail(trimmedEmail)}, ${passwordHash}, now())
    RETURNING *
  `;
  return rowToUser(rows[0]);
}

/** Record a successful sign-in without touching identity columns. */
export async function touchLastLogin(userId) {
  const rows = await sql()`
    UPDATE worldguard_users SET last_login_at = now(), updated_at = now()
    WHERE id = ${userId}
    RETURNING *
  `;
  return rowToUser(rows[0]);
}

/** True when a Postgres unique violation surfaced (SQLSTATE 23505). */
export function isUniqueViolation(err) {
  if (!err) return false;
  return err?.code === '23505' || /duplicate key value/i.test(String(err?.message || ''));
}

/**
 * Resolve a Clerk-authenticated identity to a WorldGuard account, linking by
 * email when the address already has a local password account.
 *
 * `emailVerified` is a REQUIRED boolean, not a hint. Callers must establish that
 * the address is verified from an authoritative source — the Clerk Backend
 * API's `email_addresses[].verification.status` (the snake_case `GET /v1/users`
 * record) — and this function throws unless it is exactly `true`. A signed JWT
 * `email` claim is NOT such a source: that claim is operator-configurable and
 * can be emitted for an unverified address. That is what makes account linking
 * safe: an address whose ownership is unconfirmed must never be matched against
 * an existing row, or anybody able to open a Clerk account on someone else's
 * address could adopt that person's password account. Keeping the check here
 * rather than only in the caller means a future caller cannot skip it.
 *
 * A row that already carries this `clerkUserId` is refreshed in place (never
 * re-keyed). A verified-email match adopts the Clerk identity and backfills the
 * avatar; a new address creates a Clerk-only account (no password hash, so the
 * user can still set one later).
 */
export async function upsertClerkUser({ clerkUserId, email, name, picture, emailVerified }) {
  if (emailVerified !== true) {
    throw new Error('refusing to store a Clerk identity: email is not verified');
  }
  const id = typeof clerkUserId === 'string' ? clerkUserId.trim() : '';
  const trimmedEmail = typeof email === 'string' ? email.trim() : '';
  if (!id || !trimmedEmail) throw new Error('clerkUserId and email are required');
  const normalized = normalizeEmail(trimmedEmail);
  const trimmedName = (typeof name === 'string' ? name : '').trim();
  const trimmedPicture = (typeof picture === 'string' ? picture : '').trim();

  const existingById = await findUserByClerkUserId(id);
  if (existingById) {
    const rows = await sql()`
      UPDATE worldguard_users
      SET name = COALESCE(NULLIF(${trimmedName}, ''), name),
          email = ${trimmedEmail},
          normalized_email = ${normalized},
          avatar_url = COALESCE(NULLIF(${trimmedPicture}, ''), avatar_url),
          last_login_at = now(),
          updated_at = now()
      WHERE id = ${existingById.id}
      RETURNING *
    `;
    return rowToUser(rows[0]);
  }

  const existingByEmail = await findUserByEmail(trimmedEmail);
  if (existingByEmail) {
    const rows = await sql()`
      UPDATE worldguard_users
      SET clerk_user_id = ${id},
          name = COALESCE(NULLIF(${trimmedName}, ''), name),
          avatar_url = COALESCE(${trimmedPicture || null}, avatar_url),
          last_login_at = now(),
          updated_at = now()
      WHERE id = ${existingByEmail.id}
      RETURNING *
    `;
    return rowToUser(rows[0]);
  }

  const rows = await sql()`
    INSERT INTO worldguard_users (name, email, normalized_email, clerk_user_id, avatar_url, last_login_at)
    VALUES (${fallbackName(trimmedName, trimmedEmail)}, ${trimmedEmail}, ${normalized}, ${id}, ${trimmedPicture || null}, now())
    RETURNING *
  `;
  return rowToUser(rows[0]);
}
