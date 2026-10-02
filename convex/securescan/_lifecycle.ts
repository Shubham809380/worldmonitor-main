/**
 * WM SecureScan — shared assessment lifecycle.
 *
 * `assessments.create` is an `internalMutation`: a browser cannot call it. That
 * is deliberate, because an unvalidated public "start a scan" would let any
 * signed-in member point the engine at a host nobody authorized. It also means
 * the product needs a *guarded* public entry point rather than a widened
 * internal one.
 *
 * The split this file enforces:
 *
 *   - `createAssessment` is the one implementation of "register a target and
 *     open its first assessment". Both callers reach the same code, so there is
 *     no second version of the lifecycle to drift out of sync.
 *   - The **internal** caller (`assessments.create`) is trusted bootstrap and
 *     keeps exactly the validation it always had. Widening that path's rules
 *     would change verified behaviour to suit a UI.
 *   - The **public** caller (`console.startAssessment`) adds the checks a
 *     browser-supplied request needs and the internal one never did, because an
 *     internal caller is the server.
 */

import { ConvexError } from "convex/values";
import { publicId, appendAudit, attestedSource, AUDIT_GENESIS } from "./_shared";
import { ROLES } from "./validators";

export interface CreateAssessmentInput {
  name: string;
  targetName: string;
  targetKind: "REPOSITORY" | "DEPLOYED_APPLICATION" | "API";
  repositoryUrl?: string;
  baseUrl?: string;
  allowlistedPaths: string[];
  maxRuntimeRequests: number;
  authorizationNote?: string;
}

export interface CreateAssessmentResult {
  assessmentId: string;
  targetId: string;
  ownerUserId: string;
  state: "READY";
}

/**
 * Registers a target and opens its first assessment.
 *
 * The caller is responsible for authentication, membership, and the
 * `assessment:create` authorization decision. This function validates the
 * target's locatability and the request budget, then writes the target,
 * the assessment, and the opening audit entry.
 */
export async function createAssessment(
  ctx: Parameters<typeof appendAudit>[0],
  userId: string,
  role: (typeof ROLES)[number],
  args: CreateAssessmentInput,
): Promise<CreateAssessmentResult> {
  // A target has to be locatable. Without this the engine receives a kind and
  // a name and no address, and "which repository" silently becomes "the one in
  // the current directory" — which is how an assessment of production gets
  // aimed at whatever happens to be checked out.
  if (args.targetKind === "REPOSITORY" && !args.repositoryUrl?.trim()) {
    throw new ConvexError("SECURESCAN_TARGET_REQUIRES_REPOSITORY_URL");
  }
  if (args.targetKind !== "REPOSITORY" && !args.baseUrl?.trim()) {
    throw new ConvexError("SECURESCAN_TARGET_REQUIRES_BASE_URL");
  }
  // A negative budget would read as "no ceiling" to any comparison written as
  // `count <= budget`, so it is refused rather than clamped.
  if (!Number.isFinite(args.maxRuntimeRequests) || args.maxRuntimeRequests < 0) {
    throw new ConvexError("SECURESCAN_INVALID_REQUEST_BUDGET");
  }

  const now = Date.now();
  const targetId = publicId("target", now);
  const existing = await ctx.db
    .query("securescanTargets")
    .withIndex("by_targetId", (q) => q.eq("targetId", targetId))
    .unique();

  let targetDoc = existing;
  if (targetDoc) {
    // A target is re-registered rather than duplicated so the allowlist that
    // governs every future scan of it has exactly one definition.
    await ctx.db.patch(targetDoc._id, {
      name: args.targetName,
      allowlistedPaths: args.allowlistedPaths,
      maxRuntimeRequests: args.maxRuntimeRequests,
      state: "ACTIVE",
      updatedAt: now,
    });
  } else {
    const id = await ctx.db.insert("securescanTargets", {
      ownerUserId: userId,
      targetId,
      name: args.targetName,
      kind: args.targetKind,
      ...(args.repositoryUrl ? { repositoryUrl: args.repositoryUrl } : {}),
      ...(args.baseUrl ? { baseUrl: args.baseUrl } : {}),
      allowlistedPaths: args.allowlistedPaths,
      maxRuntimeRequests: args.maxRuntimeRequests,
      state: "ACTIVE",
      createdAt: now,
      updatedAt: now,
    });
    targetDoc = await ctx.db.get(id);
  }
  if (!targetDoc) throw new ConvexError("SECURESCAN_TARGET_NOT_FOUND");

  const assessmentId = publicId("assessment", now);
  await ctx.db.insert("securescanAssessments", {
    ownerUserId: userId,
    targetId,
    assessmentId,
    name: args.name,
    state: "READY",
    // The genesis anchor. A chain that has never been written still verifies,
    // so a new assessment is not indistinguishable from a tampered one.
    auditHeadHash: AUDIT_GENESIS,
    auditEntryCount: 0,
    createdAt: now,
    updatedAt: now,
  });

  const source = attestedSource();
  await appendAudit(ctx, {
    assessmentId,
    actorUserId: userId,
    actorRole: role,
    action: "assessment:create",
    resourceType: "assessment",
    resourceId: assessmentId,
    outcome: "ALLOWED",
    reasonCode: "ASSESSMENT_CREATED",
    detail: `Assessment "${args.name}" opened against ${args.targetName}. ${args.authorizationNote ?? ""}`.trim(),
    sourceUserAgent: source.userAgent,
    sourceIp: source.ip,
  }, now);

  return { assessmentId, targetId, ownerUserId: userId, state: "READY" };
}

/**
 * Input hardening applied only on the browser-reachable path.
 *
 * Each rule closes a specific way a client could otherwise aim the engine
 * somewhere it has no business being, or poison a later scan:
 *
 *  - **URLs are parsed, not pattern-matched.** A regex that accepts anything
 *    containing "https" also accepts `javascript:https` and
 *    `https://example.com\@evil.test`. `new URL` plus a scheme allowlist cannot
 *    be talked into that, and the console renders these values as links.
 *  - **Allowlisted paths are constrained to repo-relative, traversal-free
 *    prefixes.** A `../` entry would silently widen the scanned surface to
 *    whatever it can reach, and an absolute path would target the runner's
 *    filesystem rather than the checkout.
 *  - **The authorization note must be substantive.** A one-character note
 *    satisfies a `v.string()` and records nothing of evidentiary value in a
 *    chain that is supposed to prove who authorized what.
 *  - **The request budget is capped.** A member asking for 1e15 requests
 *    cannot be served, and persisting the number makes every later budget check
 *    meaningless.
 */

const MAX_REQUEST_BUDGET = 5_000;
const MIN_AUTHORIZATION_NOTE = 40;

export type CreateRequestRejection = {
  field: "name" | "targetName" | "repositoryUrl" | "baseUrl" | "allowlistedPaths" | "maxRuntimeRequests" | "authorizationNote";
  message: string;
};

function reject(field: CreateRequestRejection["field"], message: string): CreateRequestRejection {
  return { field, message };
}

/** Returns an http(s) URL, or null when the value is not one. */
function parseHttpUrl(value: string): URL | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  return url.protocol === "https:" || url.protocol === "http:" ? url : null;
}

/**
 * Validates a browser-supplied create request. Returns the rejections rather
 * than throwing, so a form can point at the offending field.
 */
export function validateCreateRequest(
  args: CreateAssessmentInput,
): CreateRequestRejection[] {
  const problems: CreateRequestRejection[] = [];

  if (!args.name.trim()) problems.push(reject("name", "Give the assessment a name."));
  else if (args.name.length > 200) problems.push(reject("name", "Keep the name under 200 characters."));

  if (!args.targetName.trim()) problems.push(reject("targetName", "Name the authorized target."));
  else if (args.targetName.length > 200) problems.push(reject("targetName", "Keep the target name under 200 characters."));

  if (args.targetKind === "REPOSITORY") {
    const raw = args.repositoryUrl?.trim() ?? "";
    if (!raw) {
      problems.push(reject("repositoryUrl", "A repository target needs its clone URL."));
    } else {
      const url = parseHttpUrl(raw);
      if (!url) {
        problems.push(reject("repositoryUrl", "Use an http(s) URL, for example https://github.com/org/repo."));
      } else if (url.username || url.password) {
        // Credentials in a URL end up in a stored target row and in the audit
        // chain. A target is referenced by name everywhere else, so they are
        // never needed.
        problems.push(reject("repositoryUrl", "Remove the username and password from the URL."));
      }
    }
  } else {
    const raw = args.baseUrl?.trim() ?? "";
    if (!raw) {
      problems.push(reject("baseUrl", "A deployed or API target needs its base URL."));
    } else {
      const url = parseHttpUrl(raw);
      if (!url) {
        problems.push(reject("baseUrl", "Use an http(s) URL, for example https://staging.example.com."));
      } else if (url.username || url.password) {
        problems.push(reject("baseUrl", "Remove the username and password from the URL."));
      }
    }
  }

  if (args.allowlistedPaths.length > 64) {
    problems.push(reject("allowlistedPaths", "At most 64 allowlisted paths."));
  }
  for (const entry of args.allowlistedPaths) {
    const path = entry.trim();
    if (!path) {
      problems.push(reject("allowlistedPaths", "An allowlisted path cannot be blank."));
      break;
    }
    if (path.includes("..")) {
      problems.push(reject("allowlistedPaths", `"${path}" traverses outside the checkout.`));
      break;
    }
    if (path.startsWith("/") || path.startsWith("\\") || /^[a-zA-Z]:/.test(path)) {
      problems.push(reject("allowlistedPaths", `"${path}" must be relative to the repository root.`));
      break;
    }
    if (path.startsWith("-")) {
      problems.push(reject("allowlistedPaths", `"${path}" looks like a command-line flag.`));
      break;
    }
  }

  if (!Number.isFinite(args.maxRuntimeRequests) || args.maxRuntimeRequests < 0) {
    problems.push(reject("maxRuntimeRequests", "Enter a request budget of 0 or more."));
  } else if (!Number.isInteger(args.maxRuntimeRequests)) {
    problems.push(reject("maxRuntimeRequests", "Enter a whole number of requests."));
  } else if (args.maxRuntimeRequests > MAX_REQUEST_BUDGET) {
    problems.push(reject("maxRuntimeRequests", `At most ${MAX_REQUEST_BUDGET} requests may be authorized.`));
  }

  const note = args.authorizationNote?.trim() ?? "";
  if (!note) {
    problems.push(reject("authorizationNote", "Record the authorization for this assessment."));
  } else if (note.length < MIN_AUTHORIZATION_NOTE) {
    problems.push(
      reject(
        "authorizationNote",
        `Describe who authorized this and on what basis (at least ${MIN_AUTHORIZATION_NOTE} characters).`,
      ),
    );
  } else if (note.length > 2000) {
    problems.push(reject("authorizationNote", "Keep the authorization note under 2000 characters."));
  }

  return problems;
}

/** Normalised allowlist written to the target: trimmed, deduped, order kept. */
export function normaliseAllowlist(paths: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const entry of paths) {
    const path = entry.trim();
    if (path !== "" && !seen.has(path)) {
      seen.add(path);
      out.push(path);
    }
  }
  return out;
}
