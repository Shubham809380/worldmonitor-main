import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";
import schema from "../schema";
import { api, internal } from "../_generated/api";
import { normaliseAllowlist, validateCreateRequest } from "../securescan/_lifecycle";

/**
 * The console's public "start an assessment" door.
 *
 * `assessments.create` is internal because an unguarded public "run a scan"
 * would let any signed-in member aim the engine at a host nobody authorized.
 * `console.startAssessment` is the guarded replacement, so these tests are
 * about the guard: what a browser is allowed to reach, and what it must not.
 *
 * Two properties matter most and are tested first:
 *   1. A VIEWER is refused, and the client cannot talk its way past that.
 *   2. A request that would aim the engine somewhere unowned, unreachable, or
 *      with an unevidenced authorization is refused before anything is written.
 */

const modules = import.meta.glob("../**/*.ts");

const ANALYST = { subject: "user-analyst", tokenIdentifier: "clerk|user-analyst" };
const VIEWER = { subject: "user-viewer", tokenIdentifier: "clerk|user-viewer" };
const OUTSIDER = { subject: "user-outsider", tokenIdentifier: "clerk|user-outsider" };
const ADMIN = { subject: "user-admin", tokenIdentifier: "clerk|user-admin" };

/** A note long enough to clear the substance check. */
const NOTE = "Owner of the repository; scanning authorized in writing by koala73 on 2026-09-01.";

function t() {
  return convexTest(schema, modules);
}

async function grantRole(
  t0: ReturnType<typeof convexTest>,
  userId: string,
  role: "ADMIN" | "SECURITY_ANALYST" | "VIEWER",
) {
  await t0.mutation(internal.securescan.findings.setRole, { userId, role });
}

function args(overrides: Record<string, unknown> = {}) {
  return {
    name: "Repository assessment",
    targetName: "worldmonitor",
    targetKind: "REPOSITORY" as const,
    repositoryUrl: "https://github.com/koala73/worldmonitor",
    allowlistedPaths: ["api/", "server/"],
    maxRuntimeRequests: 0,
    authorizationNote: NOTE,
    ...overrides,
  };
}

async function countAssessments(t0: ReturnType<typeof convexTest>): Promise<number> {
  return t0.run(async (ctx) => ctx.db.query("securescanAssessments").collect().then((r) => r.length));
}

describe("console startAssessment authorization", () => {
  test("refuses a VIEWER, who does not hold assessment:create", async () => {
    const t0 = t();
    await grantRole(t0, VIEWER.subject, "VIEWER");
    const asViewer = await t0.withIdentity(VIEWER);

    const result = await asViewer.mutation(api.securescan.console.startAssessment, args());

    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected a refusal");
    expect(result.code).toBe("ROLE_FORBIDDEN");
    // A viewer must not be able to open an assessment even with a well-formed,
    // fully authorized-looking request. The role is the gate, not the payload.
    expect(await countAssessments(t0)).toBe(0);
  });

  test("refuses an authenticated user with no membership at all", async () => {
    const t0 = t();
    // Deliberately no role granted: membership is separate from having a session.
    const asOutsider = await t0.withIdentity(OUTSIDER);

    await expect(
      asOutsider.mutation(api.securescan.console.startAssessment, args()),
    ).rejects.toThrow();
    expect(await countAssessments(t0)).toBe(0);
  });

  test("refuses an unauthenticated caller", async () => {
    const t0 = t();
    await expect(t0.mutation(api.securescan.console.startAssessment, args())).rejects.toThrow();
  });

  test("a client cannot escalate by sending a role in the payload", async () => {
    const t0 = t();
    await grantRole(t0, VIEWER.subject, "VIEWER");
    const asViewer = await t0.withIdentity(VIEWER);

    // Role is never read from the request, and the argument validator refuses
    // undeclared fields outright rather than ignoring them, so this request is
    // rejected before the handler runs at all.
    await expect(
      asViewer.mutation(
        api.securescan.console.startAssessment,
        args({ role: "ADMIN", ownerUserId: ADMIN.subject, actorRole: "ADMIN" }),
      ),
    ).rejects.toThrow();
    expect(await countAssessments(t0)).toBe(0);
  });

  test("the assessment is owned by whoever opened it, not by a client-supplied owner", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const asAnalyst = await t0.withIdentity(ANALYST);

    // There is no `ownerUserId` argument to supply. Ownership is taken from the
    // authenticated identity, so there is nothing for a client to override.
    const result = await asAnalyst.mutation(api.securescan.console.startAssessment, args());

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    expect(result.ownerUserId).toBe(ANALYST.subject);
  });

  test("lets an analyst open an assessment and records the authorization in the chain", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    await grantRole(t0, ADMIN.subject, "ADMIN");
    const asAnalyst = await t0.withIdentity(ANALYST);

    const result = await asAnalyst.mutation(api.securescan.console.startAssessment, args());

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected success");
    expect(result.state).toBe("READY");
    expect(result.ownerUserId).toBe(ANALYST.subject);

    // The new assessment opens its own verifiable chain, and the opening entry
    // carries the authorization rather than a bare "created".
    const asAdmin = await t0.withIdentity(ADMIN);
    const chain = await asAdmin.query(api.securescan.audit.verify, { assessmentId: result.assessmentId });
    expect(chain.intact).toBe(true);

    const entries = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanAuditLog")
        .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", result.assessmentId))
        .collect(),
    );
    const opening = entries.find((e) => e.reasonCode === "ASSESSMENT_CREATED");
    expect(opening?.detail).toContain("koala73");
  });
});

describe("console startAssessment input hardening", () => {
  test("requires a substantive authorization note", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const asAnalyst = await t0.withIdentity(ANALYST);

    // A note that satisfies `v.string()` but proves nothing. The opening audit
    // entry is permanent, so a token note is worse than no note.
    for (const note of ["", "   ", "test", "authorized"]) {
      const result = await asAnalyst.mutation(
        api.securescan.console.startAssessment,
        args({ authorizationNote: note }),
      );
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("expected a refusal");
      expect(result.code).toBe("SECURESCAN_INVALID_ASSESSMENT_REQUEST");
      expect(result.problems.map((p) => p.field)).toContain("authorizationNote");
    }
    expect(await countAssessments(t0)).toBe(0);
  });

  test("refuses a non-http target scheme", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const asAnalyst = await t0.withIdentity(ANALYST);

    // These are the values a console would render as a link. `javascript:` in a
    // stored target is a stored-XSS vector the moment anything links to it.
    for (const url of [
      "javascript:alert(1)",
      "file:///etc/passwd",
      "data:text/html,<script>alert(1)</script>",
      "ftp://example.com/repo",
      "not a url at all",
    ]) {
      const result = await asAnalyst.mutation(
        api.securescan.console.startAssessment,
        args({ repositoryUrl: url }),
      );
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("expected a refusal");
      expect(result.problems.map((p) => p.field)).toContain("repositoryUrl");
    }
    expect(await countAssessments(t0)).toBe(0);
  });

  test("refuses a url carrying embedded credentials", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const asAnalyst = await t0.withIdentity(ANALYST);

    // Credentials in a URL land in a target row and in the audit chain forever.
    const result = await asAnalyst.mutation(
      api.securescan.console.startAssessment,
      args({ repositoryUrl: "https://user:hunter2@github.com/koala73/worldmonitor" }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected a refusal");
    expect(result.problems.map((p) => p.field)).toContain("repositoryUrl");
  });

  test("refuses an allowlist that escapes the checkout", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const asAnalyst = await t0.withIdentity(ANALYST);

    // A `../` entry silently widens the scanned surface past what the operator
    // named; an absolute path targets the runner's filesystem instead.
    for (const paths of [["../secrets"], ["api/../../etc"], ["/etc/passwd"], ["C:\\Windows"], ["-rf"]]) {
      const result = await asAnalyst.mutation(
        api.securescan.console.startAssessment,
        args({ allowlistedPaths: paths }),
      );
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("expected a refusal");
      expect(result.problems.map((p) => p.field)).toContain("allowlistedPaths");
    }
    expect(await countAssessments(t0)).toBe(0);
  });

  test("refuses an unbounded or nonsensical request budget", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const asAnalyst = await t0.withIdentity(ANALYST);

    for (const budget of [-1, 1e15, 2.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      const result = await asAnalyst.mutation(
        api.securescan.console.startAssessment,
        args({ maxRuntimeRequests: budget }),
      );
      expect(result.ok).toBe(false);
      if (result.ok) throw new Error("expected a refusal");
      expect(result.problems.map((p) => p.field)).toContain("maxRuntimeRequests");
    }
  });

  test("a deployed or api target needs a locatable base url, not a repository url", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const asAnalyst = await t0.withIdentity(ANALYST);

    // Giving a deployed target only a repository url would leave the engine
    // with a kind and a name and no address.
    const result = await asAnalyst.mutation(
      api.securescan.console.startAssessment,
      args({ targetKind: "API", repositoryUrl: undefined, baseUrl: "" }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected a refusal");
    expect(result.problems.map((p) => p.field)).toContain("baseUrl");
  });

  test("reports every problem at once so a form is not a one-error-per-attempt loop", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const asAnalyst = await t0.withIdentity(ANALYST);

    const result = await asAnalyst.mutation(
      api.securescan.console.startAssessment,
      args({ name: "", repositoryUrl: "javascript:alert(1)", allowlistedPaths: ["../x"], authorizationNote: "x" }),
    );
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected a refusal");
    const fields = result.problems.map((p) => p.field);
    expect(fields).toContain("name");
    expect(fields).toContain("repositoryUrl");
    expect(fields).toContain("allowlistedPaths");
    expect(fields).toContain("authorizationNote");
  });

  test("normalises the allowlist it stores: trimmed, deduped, order kept", () => {
    expect(normaliseAllowlist([" api/ ", "api/", "", "server/", "api/"])).toEqual([
      "api/",
      "server/",
    ]);
  });

  test("a clean request produces no problems", () => {
    expect(validateCreateRequest(args())).toEqual([]);
    expect(
      validateCreateRequest(
        args({ targetKind: "DEPLOYED_APPLICATION", baseUrl: "https://staging.example.com", repositoryUrl: undefined }),
      ),
    ).toEqual([]);
  });
});
