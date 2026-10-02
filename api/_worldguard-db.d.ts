/**
 * Types for the WorldGuard account store (`api/_worldguard-db.js`).
 *
 * Declared separately so TypeScript API entries — currently
 * `api/auth/clerk-bridge.ts` — get real types instead of `@ts-expect-error any`.
 * The JS implementation is the source of truth; keep the two in sync.
 *
 * Invariants enforced by the implementation, restated here so a caller cannot
 * rely on weaker behaviour:
 *   - `password_hash` and `clerk_user_id` are independently optional; a row can
 *     be password-only, Clerk-only, or both (linked on a verified email).
 *   - `upsertClerkUser` throws unless `emailVerified` is exactly `true`.
 *   - no identifier is ever interpolated into SQL; every value is bound.
 */

export interface WorldGuardUser {
  id: string;
  name: string;
  email: string;
  normalizedEmail: string;
  passwordHash: string | null;
  clerkUserId: string | null;
  avatarUrl: string | null;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | null;
}

/** True when a pooled or unpooled Neon connection string is available. */
export function isDbConfigured(): boolean;

/** Case-insensitive lookup by email. Resolves null when the address is unknown. */
export function findUserByEmail(email: string): Promise<WorldGuardUser | null>;

/** Lookup by Clerk user id. Resolves null when the identity is unknown. */
export function findUserByClerkUserId(clerkUserId: string): Promise<WorldGuardUser | null>;

/**
 * Insert a password-only account. Rejects with a unique-violation error when
 * `email` is taken; callers map that to HTTP 409.
 */
export function createPasswordUser(input: {
  name: string;
  email: string;
  passwordHash: string;
}): Promise<WorldGuardUser>;

/** Stamp `last_login_at` for a known account. No-op for an unknown id. */
export function touchLastLogin(userId: string): Promise<void>;

/** True for a Postgres 23505 unique-constraint violation. */
export function isUniqueViolation(err: unknown): boolean;

/**
 * Resolve a Clerk-authenticated identity to an account, linking on the verified
 * email when the address already has a password account, and refreshing in place
 * when the `clerkUserId` is already known.
 *
 * THROWS unless `emailVerified` is exactly `true`. Email ownership is what makes
 * linking safe, so the check is not optional and not a hint.
 */
export function upsertClerkUser(input: {
  clerkUserId: string;
  email: string;
  name?: string;
  picture?: string;
  emailVerified: boolean;
}): Promise<WorldGuardUser>;