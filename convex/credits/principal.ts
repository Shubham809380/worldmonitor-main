/**
 * Who a credit balance belongs to.
 *
 * ## Why this is not a bare user id
 *
 * WorldGuard has two unrelated account systems, and the credit engine sits
 * downstream of both:
 *
 * 1. **Clerk** — the platform identity in Convex `users`. Deletion webhooks,
 *    entitlements, and Pro all key off a Clerk subject.
 * 2. **WorldGuard custom auth** — a Neon Postgres `worldguard_users` table
 *    (`api/_worldguard-db.js`) with Google OAuth, password sign-in, and a
 *    user-bound HMAC session cookie (`api/_wg-session.js`). Deliberately
 *    separate: the schema comment on `worldguardUsers` says "there is
 *    deliberately no link between the two tables".
 *
 * A credit balance has to be owned by exactly one of them. Storing a raw id
 * makes that ambiguous in a way that fails quietly: `worldguard_users.id` is a
 * UUID and a Clerk subject looks like `user_2aBc…`, so they do not collide in
 * practice, but nothing at the type level says a column may only hold one
 * domain's ids. The failure mode is a credit wallet whose balance is invisible
 * to the account-deletion path that should have removed it.
 *
 * So the wire format is namespaced: `<kind>:<id>`. A caller cannot spend
 * `clerk:user_x` against a wallet belonging to `worldguard:<uuid>` because the
 * strings differ, and every consumer can route on the kind.
 *
 * ## Format
 *
 * ```
 * clerk:<clerk-subject>          e.g. clerk:user_2abcDEF
 * worldguard:<worldguard_users.id> e.g. worldguard:3f1c…-uuid
 * ```
 *
 * The kind is separated by the *first* colon, so an id containing a colon
 * cannot be silently reinterpreted as a different kind — the split happens once,
 * at the first colon, and the remainder is the id verbatim.
 *
 * ## The WorldGuard id is the Neon primary key
 *
 * `worldguard:<worldguard_users.id>`, not `googleSub`. The session cookie is
 * bound to that `id`, the password endpoints use it, and it is what
 * `upsertGoogleUser` returns. A Google `sub` is a property of the Google
 * account, not of the WorldGuard account: an address that first signs up with a
 * password and later signs in with Google resolves to ONE row, and a
 * per-provider id would mint that person a second, separate credit balance the
 * first time they used Google. `convex/worldguardUsers.ts` is a Convex mirror
 * keyed by `sub`, which is a further reason not to treat `sub` as the owner.
 */

/** Identity domains that may own a credit balance. */
export const PRINCIPAL_KINDS = ["clerk", "worldguard"] as const;

export type PrincipalKind = (typeof PRINCIPAL_KINDS)[number];

/** Longest id we will accept, to bound index keys and error messages. */
const MAX_PRINCIPAL_ID_LEN = 256;

const KIND_SET: ReadonlySet<string> = new Set(PRINCIPAL_KINDS);

export type ParsedPrincipal = {
  kind: PrincipalKind;
  id: string;
};

/**
 * True when `value` is a well-formed principal.
 *
 * Deliberately strict. A principal reaches Convex from a relay route, a
 * webhook, and internal mutations, and a malformed one that passed validation
 * would become a wallet nobody can ever spend from or delete.
 */
export function isPrincipal(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const parsed = parsePrincipal(value);
  return parsed !== null;
}

/**
 * Splits a principal into its kind and id, or returns null when malformed.
 *
 * An id is rejected when it is empty, longer than the cap, or contains
 * whitespace. Whitespace is the one that matters in practice: a principal
 * built by string-concatenating an unvalidated value (`"clerk:" + subject`)
 * would otherwise produce a *different, valid-looking* principal that silently
 * fails to match the wallet it was meant to reach.
 */
export function parsePrincipal(value: string): ParsedPrincipal | null {
  const separator = value.indexOf(":");
  if (separator <= 0) return null;

  const kind = value.slice(0, separator);
  if (!KIND_SET.has(kind)) return null;

  const id = value.slice(separator + 1);
  if (id.length === 0 || id.length > MAX_PRINCIPAL_ID_LEN) return null;
  if (/\s/.test(id)) return null;

  return { kind: kind as PrincipalKind, id };
}

function build(kind: PrincipalKind, id: string): string {
  const trimmed = id.trim();
  if (
    trimmed.length === 0 ||
    trimmed.length > MAX_PRINCIPAL_ID_LEN ||
    /\s/.test(trimmed)
  ) {
    throw new Error(
      `Invalid ${kind} id for a credit principal: length ${trimmed.length}, must be non-empty, whitespace-free, and at most ${MAX_PRINCIPAL_ID_LEN} characters`,
    );
  }
  return `${kind}:${trimmed}`;
}

/** Principal for a Clerk subject (the platform identity in Convex `users`). */
export function clerkPrincipal(clerkUserId: string): string {
  return build("clerk", clerkUserId);
}

/**
 * Principal for a WorldGuard custom-auth account (`worldguard_users.id`).
 */
export function worldguardPrincipal(worldguardUserId: string): string {
  return build("worldguard", worldguardUserId);
}

/**
 * The principal an erased account's credit rows are rewritten to.
 *
 * Account deletion tombstones the Clerk subject as `deleted:<sha256>` (see
 * `tombstoneUserId`). A credit row is keyed by principal rather than by subject,
 * so it needs the same tombstone *inside* the namespaced form: the `kind` is
 * preserved so the row is still recognisable as a clerk-owned balance for
 * financial reporting, while the id stops naming the person. Amounts, periods,
 * and `balanceAfter` survive, so a disputed charge still traces to its source.
 *
 * The result stays a well-formed principal, which matters because every credit
 * consumer validates the shape with {@link assertPrincipal} — a tombstone that
 * failed that check would be a row nothing could ever read or delete again.
 */
export function tombstonePrincipal(
  kind: PrincipalKind,
  userIdHash: string,
): string {
  return `${kind}:${TOMBSTONE_PREFIX}${userIdHash}`;
}

/** The id segment that marks a tombstoned, non-rejoinable principal. */
export const TOMBSTONE_PREFIX = "deleted:";

/**
 * Narrows an untrusted value to a principal of one expected kind.
 *
 * The kind check is the point: a relay route that is supposed to be writing a
 * WorldGuard principal must not be able to write a Clerk one, whatever the body
 * says.
 */
export function requirePrincipalOfKind(
  value: string,
  kind: PrincipalKind,
): string {
  const parsed = parsePrincipal(value);
  if (!parsed) {
    throw new Error(`Malformed credit principal: ${JSON.stringify(value)}`);
  }
  if (parsed.kind !== kind) {
    throw new Error(
      `Credit principal kind mismatch: expected ${kind}, got ${parsed.kind}`,
    );
  }
  return value;
}

/**
 * The guard every credit mutation calls on an untrusted `principalId`.
 *
 * The Convex validator is `v.string()` (see `creditPrincipalValidator` for why
 * it cannot be a pattern), so the shape check lives here. It runs before any
 * database read so a malformed principal fails as a bad request against an empty
 * result set rather than as a confusing "no wallet" further down.
 *
 * Throws a plain `Error`: by the time this runs the caller has not yet decided
 * whether the condition is the caller's fault, and the credit mutations convert
 * this into a structured `ConvexError` with a caller-safe message.
 */
export function assertPrincipal(value: string): ParsedPrincipal {
  const parsed = parsePrincipal(value);
  if (!parsed) {
    throw new Error(
      `Malformed credit principal ${JSON.stringify(value)}: expected "<kind>:<id>" ` +
        `where kind is one of ${PRINCIPAL_KINDS.join(", ")}`,
    );
  }
  return parsed;
}
