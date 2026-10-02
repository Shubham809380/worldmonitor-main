import { ConvexError } from "convex/values";
import type { MutationCtx, QueryCtx } from "../_generated/server";
import { isRole, type Role } from "../../server/securescan/identity";

/**
 * A SecureScan account is granted, not inherited.
 *
 * There is deliberately no default role. A World Monitor sign-up is a valid
 * account that has never been authorized for security assessments, and falling
 * back to `VIEWER` handed every such user the ability to read every assessment,
 * target, evidence record and finding in the deployment. Assessment results are
 * exactly the data that must not leak to an unaffiliated account, so the honest
 * answer for a missing row is no access, reported as a denial the caller can
 * audit rather than as an error.
 */
export async function resolveRole(
  ctx: QueryCtx | MutationCtx,
  userId: string,
): Promise<Role | null> {
  const member = await ctx.db
    .query("securescanMembers")
    .withIndex("by_userId", (q) => q.eq("userId", userId))
    .unique();
  if (!member || !isRole(member.role)) return null;
  return member.role;
}

/** Reason code reported when an account has no SecureScan grant at all. */
export const NO_SECURESCAN_MEMBER = "SECURESCAN_NO_MEMBERSHIP";

/**
 * Resolves a role for a caller who must be a member, or refuses the call.
 *
 * This throws rather than returning a denial value, and the difference matters.
 * A denial that names an assessment is normally returned so the refusal can be
 * written into that assessment's audit chain. A non-member has not established
 * any relationship to that assessment, so recording the attempt there would
 * both confirm the assessment exists to an unauthorized caller and write into a
 * chain it has no business touching. Refusing at the door, with a stable code
 * the UI can turn into a request-access prompt, leaks nothing and leaves the
 * chain intact.
 */
export async function requireMemberRole(
  ctx: QueryCtx | MutationCtx,
  userId: string,
): Promise<Role> {
  const role = await resolveRole(ctx, userId);
  if (role === null) throw new ConvexError(NO_SECURESCAN_MEMBER);
  return role;
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Sortable, collision-resistant public identifier.
 *
 * Time is encoded rather than appended so lexicographic order matches creation
 * order, which lets a paginated list sort by ID alone instead of carrying a
 * separate sort key through the query.
 */
function encodeTime(time: number): string {
  let remaining = Math.max(0, Math.trunc(time));
  let result = "";
  for (let i = 0; i < 10; i += 1) {
    result = CROCKFORD[remaining % 32] + result;
    remaining = Math.floor(remaining / 32);
  }
  return result;
}

export function publicId(
  kind: "target" | "assessment" | "run" | "finding",
  now = Date.now(),
): string {
  const random = new Uint8Array(16);
  crypto.getRandomValues(random);
  const suffix =
    encodeTime(now) + Array.from(random, (byte) => CROCKFORD[byte & 31]).join("");
  return `ss_${kind}_${suffix}`;
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

export interface AuditEntryContent {
  readonly seq: number;
  readonly assessmentId: string;
  readonly actorUserId: string;
  readonly actorRole: string;
  readonly action: string;
  readonly resourceType: string;
  readonly resourceId: string;
  readonly outcome: string;
  readonly reasonCode: string;
  readonly detail: string;
  readonly at: number;
  readonly sourceUserAgent: string;
  readonly sourceIp: string;
}

/**
 * The exact byte layout a digest is taken over.
 *
 * The verifier in `audit.ts` calls this too. It must be one function: if the
 * writer and the checker each built their own serialization, a formatting
 * difference would surface as "the log was tampered with", and the real cause
 * would never be found.
 */
export function canonicalAuditPayload(entry: AuditEntryContent): string {
  return JSON.stringify([
    entry.seq,
    entry.assessmentId,
    entry.actorUserId,
    entry.actorRole,
    entry.action,
    entry.resourceType,
    entry.resourceId,
    entry.outcome,
    entry.reasonCode,
    entry.detail,
    entry.at,
    entry.sourceUserAgent,
    entry.sourceIp,
  ]);
}

/** Chained digest for one entry. `previousHash` is part of the signed content. */
export function auditEntryHash(previousHash: string, entry: AuditEntryContent) {
  return sha256Hex(`${previousHash}\u0000${canonicalAuditPayload(entry)}`);
}

export const AUDIT_GENESIS = "0".repeat(64);

/** The minimum a stored chain row needs for verification, so callers can pass rows straight from the database. */
export interface ChainEntry {
  seq: number;
  assessmentId: string;
  actorUserId: string;
  actorRole: string;
  action: string;
  resourceType: string;
  resourceId: string;
  outcome: string;
  reasonCode: string;
  detail: string;
  at: number;
  sourceUserAgent: string;
  sourceIp: string;
  previousHash: string;
  hash: string;
}

export interface ChainVerification {
  entryCount: number;
  expectedEntryCount: number;
  headHash: string;
  recordedHeadHash: string;
  intact: boolean;
  problems: string[];
}

/**
 * Verifies an assessment's audit chain: every entry links to its predecessor,
 * every digest matches its content, the sequence is dense and ordered, and the
 * final entry matches the head recorded on the assessment.
 *
 * This lives here rather than in the audit query because two surfaces report on
 * integrity — the admin audit page and the assessment report — and two copies of
 * this logic would eventually disagree about whether a chain is intact. A report
 * that says "verified" while the audit page says "altered" is worse than no
 * integrity claim at all.
 */
export async function verifyAuditChain(
  entries: readonly ChainEntry[],
  expected: { auditEntryCount: number; auditHeadHash: string },
): Promise<ChainVerification> {
  const problems: string[] = [];
  if (entries.length !== expected.auditEntryCount) {
    problems.push(
      `Entry count mismatch: chain has ${entries.length}, assessment records ${expected.auditEntryCount}.`,
    );
  }

  let previousHash = AUDIT_GENESIS;
  for (const [index, entry] of entries.entries()) {
    if (entry.seq !== index) {
      problems.push(`Entry ${index} has out-of-order seq ${entry.seq}.`);
    }
    if (entry.previousHash !== previousHash) {
      problems.push(`Entry ${entry.seq} does not link to its predecessor.`);
    }
    const computed = await auditEntryHash(entry.previousHash, entry);
    if (computed !== entry.hash) {
      problems.push(`Entry ${entry.seq} has been altered: its content does not match its digest.`);
    }
    previousHash = entry.hash;
  }

  if (previousHash !== expected.auditHeadHash) {
    problems.push(
      "Chain head does not match the digest recorded on the assessment. Entries may have been added or removed after the fact.",
    );
  }

  return {
    entryCount: entries.length,
    expectedEntryCount: expected.auditEntryCount,
    headHash: previousHash,
    recordedHeadHash: expected.auditHeadHash,
    intact: problems.length === 0,
    problems,
  };
}

/**
 * Appends one entry to the per-assessment audit chain and returns it.
 *
 * `headHash` and `entryCount` are stored on the assessment so verification has
 * an anchored end. Without that anchor, deleting the tail of the chain would
 * still verify, which is the one attack a pure hash chain cannot detect.
 */
export async function appendAudit(
  ctx: MutationCtx,
  input: {
    assessmentId: string;
    actorUserId: string;
    actorRole: string;
    action: string;
    resourceType: string;
    resourceId: string;
    outcome: "ALLOWED" | "DENIED";
    reasonCode: string;
    detail: string;
    sourceUserAgent: string;
    sourceIp: string;
  },
  now = Date.now(),
): Promise<{ id: string; hash: string; seq: number }> {
  const assessment = await ctx.db
    .query("securescanAssessments")
    .withIndex("by_assessmentId", (q) => q.eq("assessmentId", input.assessmentId))
    .unique();
  if (!assessment) throw new ConvexError("SECURESCAN_ASSESSMENT_NOT_FOUND");

  const seq = assessment.auditEntryCount;
  const previousHash = assessment.auditHeadHash;
  const hash = await auditEntryHash(previousHash, {
    seq,
    assessmentId: input.assessmentId,
    actorUserId: input.actorUserId,
    actorRole: input.actorRole,
    action: input.action,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    outcome: input.outcome,
    reasonCode: input.reasonCode,
    detail: input.detail,
    at: now,
    sourceUserAgent: input.sourceUserAgent,
    sourceIp: input.sourceIp,
  });

  const id = await ctx.db.insert("securescanAuditLog", {
    assessmentId: input.assessmentId,
    seq,
    actorUserId: input.actorUserId,
    actorRole: input.actorRole,
    action: input.action,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    outcome: input.outcome,
    reasonCode: input.reasonCode,
    detail: input.detail,
    sourceUserAgent: input.sourceUserAgent,
    sourceIp: input.sourceIp,
    at: now,
    previousHash,
    hash,
  });

  await ctx.db.patch(assessment._id, {
    auditHeadHash: hash,
    auditEntryCount: seq + 1,
    updatedAt: now,
  });

  return { id, hash, seq };
}

export interface RequestSource {
  readonly userAgent: string;
  readonly ip: string;
}

/**
 * Sentinel recorded when a provenance field cannot be attested.
 *
 * Convex mutations and queries cannot see the originating request's IP or
 * User-Agent header, and `ctx.auth` exposes only the verified subject. Guessing
 * from a forwarded header would put attacker-controlled text into the audit
 * trail under the appearance of fact, so unknown is recorded as unknown.
 */
export const UNATTESTED = "unavailable" as const;

/**
 * Provenance for an audit entry.
 *
 * Callers supply this from something they can actually attest to. When no
 * trusted transport metadata is available, pass `UNATTESTED` rather than
 * passing a header value through.
 */
export function attestedSource(known?: Partial<RequestSource>): RequestSource {
  return {
    userAgent: known?.userAgent ?? UNATTESTED,
    ip: known?.ip ?? UNATTESTED,
  };
}
