// @vitest-environment node
/**
 * Deployment scope: SecureScan has exactly one tenant, and this file makes that an
 * executable claim instead of a comment someone can scroll past.
 *
 * ## Why this file exists
 *
 * The authorization engine is well built and well tested. `authorize()` scopes
 * mutations to the resource owner, and `securescan-authz.test.ts` plus
 * `securescan-console.test.ts` pin that behaviour, including the deliberate
 * decision that reads stay deployment-wide so peers can review each other's work.
 *
 * Those two facts together define the product's scope: the *deployment* is the
 * security boundary, and everybody with a membership row is a peer inside it.
 * That is a sound design for one organization running a console for itself. It is
 * not a design that survives being pointed at two organizations who must not see
 * each other's findings, and the difference is not a missing check somewhere - it
 * is that there is no tenant to check against.
 *
 * ## What a green run of this file means
 *
 * It means the deployment is still single-tenant. It does not mean SecureScan is
 * ready for multiple customers.
 *
 * ## The tripwire
 *
 * `no SecureScan table carries a tenant identifier` is the assertion to watch. It
 * fails the moment someone adds a `workspaceId` to one table. That failure is the
 * point: adding the column is the easy half and on its own it isolates *nothing*,
 * because every read path in `console.ts` still selects the whole table. Whoever
 * trips this test has to finish the read-path rewrite and the backfill at the same
 * time, or ship a column that looks like isolation and is not.
 */

import { describe, expect, test } from "vitest";
import schema from "../schema";
import {
  ACTIONS,
  authorize,
  can,
  isMutating,
  type Action,
  type Actor,
} from "../../server/securescan/identity";

/**
 * Field names a tenant boundary could plausibly be spelled. Deliberately
 * generous: the point is to catch the *idea*, including a first attempt under a
 * name this list does not anticipate, which is why the assertion below also
 * reports the full field list on failure.
 */
const TENANT_FIELD_NAMES: readonly string[] = [
  "workspaceId",
  "workspace_id",
  "orgId",
  "org_id",
  "organizationId",
  "tenantId",
  "tenant_id",
  "teamId",
  "accountId",
  "groupId",
];

const SECURESCAN_TABLES: readonly string[] = [
  "securescanMembers",
  "securescanTargets",
  "securescanAssessments",
  "securescanRuns",
  "securescanTests",
  "securescanEvidence",
  "securescanFindings",
  "securescanFindingEvents",
  "securescanAuditLog",
];

interface TableShape {
  readonly fields: readonly string[];
  readonly indexes: readonly (readonly string[])[];
}

/**
 * Reads the live schema rather than a checked-in list, so this file cannot drift
 * away from `convex/schema.ts` the way a copy of the field names would.
 */
function tableShape(name: string): TableShape {
  const table = (schema as unknown as { tables: Record<string, unknown> }).tables[name];
  if (table === undefined) {
    throw new Error(`schema has no table named ${name}`);
  }
  const typed = table as {
    validator: { json: { value: Record<string, unknown> } };
    indexes: Record<string, { fields: string[] }>;
  };
  const fields = Object.keys(typed.validator.json.value).sort();
  const indexes = Object.values(typed.indexes ?? {}).map((index) => index.fields);
  return { fields, indexes };
}

const READ_ACTIONS: readonly Action[] = ACTIONS.filter(
  (action): action is Action => action.endsWith(":read"),
);

const ANALYST: Actor = { userId: "user-analyst", role: "SECURITY_ANALYST" };
const FOREIGN_OWNER_RESOURCE = {
  id: "FND-1",
  kind: "finding" as const,
  ownerId: "user-somebody-else",
};

describe("SecureScan deployment scope", () => {
  test("membership is a flat, deployment-wide grant table", () => {
    const members = tableShape("securescanMembers");

    // Absence of a row is the denial (`requireMemberRole` throws
    // `SECURESCAN_NO_MEMBERSHIP`), so this table is the entire access-control
    // surface. Four columns, no scoping, and nothing that could partition it.
    expect(members.fields).toEqual([
      "grantedAt",
      "grantedByUserId",
      "role",
      "userId",
    ]);

    // Indexed by subject and by role only. A tenant index would be the first
    // structural sign of a boundary, and there is none.
    expect(members.indexes).toEqual([["userId"], ["role"]]);
  });

  test("no SecureScan table carries a tenant identifier", () => {
    const offenders: string[] = [];

    for (const name of SECURESCAN_TABLES) {
      for (const field of tableShape(name).fields) {
        if (TENANT_FIELD_NAMES.includes(field)) {
          offenders.push(`${name}.${field}`);
        }
      }
    }

    // On failure this names the exact column, because the failure is a prompt to
    // finish the isolation work rather than a defect to be silenced.
    expect(
      offenders,
      `SecureScan gained a tenant column (${offenders.join(", ")}) but reads are ` +
        "still deployment-wide, so this isolates nothing until every read path and " +
        "the backfill are done with it.",
    ).toEqual([]);
  });

  test("the only scope column is ownerUserId, so the boundary is a person", () => {
    // These four tables carry an owner. That is what makes `NOT_RESOURCE_OWNER`
    // mean "a different person" and never "a different organization".
    for (const name of [
      "securescanTargets",
      "securescanAssessments",
      "securescanRuns",
      "securescanFindings",
    ]) {
      expect(
        tableShape(name).fields,
        `${name} lost its owner column; the owner check depends on it.`,
      ).toContain("ownerUserId");
    }

    // Tests, evidence, lifecycle events and the audit log are reachable only
    // through their assessment, so they inherit whatever boundary the assessment
    // has. None of them re-asserts one, which is why an assessment-scoped read
    // reaches all of them.
    for (const name of [
      "securescanTests",
      "securescanEvidence",
      "securescanFindingEvents",
      "securescanAuditLog",
    ]) {
      expect(
        tableShape(name).fields,
        `${name} has no owner column; it inherits the assessment's boundary.`,
      ).not.toContain("ownerUserId");
    }
  });

  test("every read action is deliberately not owner-scoped, which is why the deployment is the boundary", () => {
    // This is the half that makes the missing tenant column load-bearing rather
    // than cosmetic. `authorize()` only applies the owner check to mutating
    // actions, so a member reads another member's finding - the behaviour
    // `securescan-console.test.ts` pins as intended for a peer team.
    for (const action of READ_ACTIONS) {
      expect(isMutating(action), `${action} became owner-scoped`).toBe(false);

      const decision = authorize(ANALYST, action, FOREIGN_OWNER_RESOURCE);
      expect(
        decision.allowed,
        `${action} started refusing a foreign owner's resource; that is an isolation ` +
          "change and needs the tenant work behind it, not a drive-by edit.",
      ).toBe(true);
    }
  });

  test("mutations stay owner-scoped, so the peer model does not extend to writes", () => {
    // The positive half of the same contract. An analyst is refused on a resource
    // they do not own, which is the property that keeps one analyst from rewriting
    // another's triage.
    //
    // `can()` filters to the actions this role actually holds, because `authorize`
    // runs the role gate first: for an action the analyst lacks, the correct code
    // is `ROLE_FORBIDDEN` and asserting an ownership failure there would be
    // asserting the wrong thing.
    const checked: Action[] = [];

    for (const action of ACTIONS) {
      if (!isMutating(action) || !can(ANALYST.role, action)) continue;

      const decision = authorize(ANALYST, action, FOREIGN_OWNER_RESOURCE);
      expect(
        decision.allowed,
        `${action} let an analyst act on another owner's resource.`,
      ).toBe(false);
      if (!decision.allowed) {
        expect(decision.code, `${action} refused for the wrong reason`).toBe("NOT_RESOURCE_OWNER");
      }
      checked.push(action);
    }

    // A test that silently iterates nothing is worse than no test.
    expect(checked.length).toBeGreaterThan(0);
  });

  test("ADMIN's ownership override is a deliberate, role-gated exception", () => {
    // `authorize` lets ADMIN act across owners because support needs it. That is
    // safe only while everyone with a membership row is inside the same
    // organization: with two tenants, an ADMIN of one would hold the keys to the
    // other. Recorded here so the blast radius of the exception is explicit.
    const admin: Actor = { userId: "user-admin", role: "ADMIN" };

    const decision = authorize(admin, "remediation:write", FOREIGN_OWNER_RESOURCE);
    expect(decision.allowed).toBe(true);
  });
});
