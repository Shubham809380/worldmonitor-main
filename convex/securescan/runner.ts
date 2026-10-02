import { internal } from "../_generated/api";

/**
 * WM SecureScan — runner bridge.
 *
 * The engine is a pure library that runs out of process: it reads a scoped
 * target, and it produces an `AssessmentResult`. `recordRun` is internal, which
 * is what keeps a browser client from posting findings it invented. But that
 * leaves a gap — the runner itself has no way to hand its result over, so a
 * completed scan would never reach the console.
 *
 * This closes that gap without opening the one it was protecting:
 *
 *  - The caller must present a shared secret that only the runner holds. It is
 *    compared in constant time, and an unset secret refuses every request rather
 *    than allowing every request.
 *  - The secret authorises *the runner*, not a *user*. The owner is taken from
 *    the payload and cross-checked against the assessment by `persistRun`, which
 *    refuses a run whose owner does not match. So a compromised runner key can
 *    write to assessments it is pointed at; it still cannot write to somebody
 *    else's.
 *  - The write itself goes through `internal.securescan.assessments.recordRun`,
 *    so there is one implementation of the persistence rules, not two.
 *
 * Every accepted run is written to the assessment's audit chain with the engine
 * as the actor. The engine is not a user and holds no role, so it is recorded as
 * `engine:<version>` rather than being given a fabricated `ADMIN`.
 */

const RUNNER_KEY_HEADER = "x-wm-securescan-runner-key";

/**
 * Constant-time string comparison.
 *
 * `===` on a secret leaks its length and a matching prefix through timing, and
 * the value being compared here is the whole authorisation for writing findings.
 * Both sides are hashed to a fixed-length digest first, so the loop below always
 * runs over 32 bytes: a caller cannot learn the secret's length by measuring the
 * response, and a length mismatch is a false rather than a throw.
 */
export async function secretMatches(provided: string, expected: string): Promise<boolean> {
  if (expected === "") return false;
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", new TextEncoder().encode(provided)),
    crypto.subtle.digest("SHA-256", new TextEncoder().encode(expected)),
  ]);
  const left = new Uint8Array(a);
  const right = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < left.length; i += 1) diff |= left[i]! ^ right[i]!;
  return diff === 0;
}

/**
 * The minimum surface of an action context this bridge needs.
 *
 * Declared structurally rather than taking Convex's `ActionCtx` so the handler
 * can be exercised directly in a test without standing up a deployment. The
 * route in `convex/http.ts` supplies it.
 */
export type RunnerContext = {
  request: Request;
  runMutation: (
    reference: unknown,
    args: Record<string, unknown>,
  ) => Promise<unknown>;
};

type RunnerPayload = { ownerUserId?: unknown; result?: unknown };

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/**
 * Handles one run submission. Exported so its authorization rules are testable
 * without a running deployment; `submitRun` is only a registration wrapper.
 */
export async function handleRunSubmission(
  ctx: RunnerContext,
  env: Record<string, string | undefined> = process.env,
): Promise<Response> {
  const expected = env.SECURESCAN_RUNNER_KEY ?? "";
  const provided = ctx.request.headers.get(RUNNER_KEY_HEADER) ?? "";

  // Fail closed. A deployment with no runner key configured accepts nothing,
  // because treating "not configured" as "allowed" is how an unauthenticated
  // write endpoint ships by accident.
  if (expected === "") {
    return jsonResponse(503, { error: "SECURESCAN_RUNNER_KEY_NOT_CONFIGURED" });
  }
  if (!(await secretMatches(provided, expected))) {
    // The refusal is not audited against an assessment: there is no assessment
    // to attach it to, and a caller who cannot present the key has not earned
    // a row in anyone's chain.
    return jsonResponse(401, { error: "SECURESCAN_RUNNER_UNAUTHORIZED" });
  }

  let payload: RunnerPayload;
  try {
    payload = (await ctx.request.json()) as RunnerPayload;
  } catch {
    return jsonResponse(400, { error: "SECURESCAN_RUNNER_BAD_PAYLOAD" });
  }

  const ownerUserId = typeof payload.ownerUserId === "string" ? payload.ownerUserId : "";
  const result = typeof payload.result === "string" ? payload.result : "";
  if (ownerUserId === "" || result === "") {
    return jsonResponse(400, {
      error: "SECURESCAN_RUNNER_BAD_PAYLOAD",
      detail: "ownerUserId and result are required.",
    });
  }

  try {
    const recorded = await ctx.runMutation(
      internal.securescan.assessments.recordRun,
      { ownerUserId, result },
    );
    return jsonResponse(200, recorded);
  } catch (error) {
    // The owner's own mismatch surfaces as a 409 rather than a 500: the runner
    // is pointed at an assessment it does not own, which is a caller error.
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("SECURESCAN_OWNER_MISMATCH")) {
      return jsonResponse(409, { error: "SECURESCAN_OWNER_MISMATCH" });
    }
    if (message.includes("SECURESCAN_ASSESSMENT_NOT_FOUND")) {
      return jsonResponse(404, { error: "SECURESCAN_ASSESSMENT_NOT_FOUND" });
    }
    return jsonResponse(500, { error: "SECURESCAN_RUNNER_PERSIST_FAILED" });
  }
}

/**
 * Handles one retest-result submission.
 *
 * The same shared secret, the same constant-time comparison, the same fail-closed
 * behaviour as a run submission. The payload is a `runId`, not a verdict: the
 * verdict is read out of the tests that run recorded, so even a runner that has
 * been fully compromised cannot assert that a fix worked. It can only point at a
 * run and let the server judge it.
 */
export async function handleRetestSubmission(
  ctx: RunnerContext,
  env: Record<string, string | undefined> = process.env,
): Promise<Response> {
  const expected = env.SECURESCAN_RUNNER_KEY ?? "";
  const provided = ctx.request.headers.get(RUNNER_KEY_HEADER) ?? "";

  if (expected === "") {
    return jsonResponse(503, { error: "SECURESCAN_RUNNER_KEY_NOT_CONFIGURED" });
  }
  if (!(await secretMatches(provided, expected))) {
    return jsonResponse(401, { error: "SECURESCAN_RUNNER_UNAUTHORIZED" });
  }

  let payload: { findingId?: unknown; runId?: unknown; notes?: unknown };
  try {
    payload = (await ctx.request.json()) as typeof payload;
  } catch {
    return jsonResponse(400, { error: "SECURESCAN_RUNNER_BAD_PAYLOAD" });
  }

  const findingId = typeof payload.findingId === "string" ? payload.findingId.trim() : "";
  const runId = typeof payload.runId === "string" ? payload.runId.trim() : "";
  if (findingId === "" || runId === "") {
    return jsonResponse(400, {
      error: "SECURESCAN_RUNNER_BAD_PAYLOAD",
      detail: "findingId and runId are required. A verdict is derived from the run, not submitted.",
    });
  }

  try {
    const recorded = await ctx.runMutation(
      internal.securescan.findings.recordRetestResult,
      { findingId, runId, notes: typeof payload.notes === "string" ? payload.notes : "" },
    );
    const result = recorded as { ok?: boolean; code?: string; reason?: string } | null;
    if (result && result.ok === false) {
      // A refusal the server reached deliberately is a 409, not a 500: the
      // runner did its job and the state machine said no.
      return jsonResponse(409, { error: result.code ?? "SECURESCAN_RETEST_REFUSED", reason: result.reason });
    }
    return jsonResponse(200, recorded);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("SECURESCAN_FINDING_NOT_FOUND")) {
      return jsonResponse(404, { error: "SECURESCAN_FINDING_NOT_FOUND" });
    }
    return jsonResponse(500, { error: "SECURESCAN_RETEST_PERSIST_FAILED" });
  }
}

// Registration lives in `convex/http.ts` at POST /securescan/runner/submit and
// POST /securescan/runner/retest. This module deliberately exports no
// `httpAction`: the object form (`httpAction({ method, handler })`) is not valid,
// and an unregistered export here is what let this whole bridge look wired while
// never being mounted - so no completed scan could ever reach the console.
