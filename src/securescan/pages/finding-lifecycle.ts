/**
 * Finding lifecycle render conveniences for the browser.
 *
 * One copy of which moves are *offered* lives here so the finding page and the
 * parity guard import the same table. It is a courtesy, not a gate: the server's
 * `findings.ts` transition table is the authority, and
 * `authorizeFindingTransition` is the role gate, applied on every call. This
 * module exists only to stop the UI from offering moves the engine would refuse,
 * and to keep the retest form's availability truthful for the current state.
 *
 * VERIFIED and FIXED are deliberately never offered as direct transitions: a
 * verified resolution can only come from the assessment engine
 * (`findings.recordRetestResult`, reached through the runner bridge), never from
 * a value typed into a browser. Every entry here is a strict subset of the
 * engine's `FINDING_TRANSITIONS`, pinned by
 * `tests/dom/securescan-server-parity.test.mts`.
 */

export const OFFERED_TRANSITIONS: Readonly<Record<string, readonly string[]>> = {
  CANDIDATE: ['VALIDATING', 'FALSE_POSITIVE', 'INCONCLUSIVE', 'ACCEPTED_RISK', 'INFORMATIONAL'],
  VALIDATING: ['VALIDATED', 'FALSE_POSITIVE', 'INCONCLUSIVE', 'ACCEPTED_RISK', 'CANDIDATE', 'INFORMATIONAL'],
  VALIDATED: ['REMEDIATION', 'ACCEPTED_RISK', 'INCONCLUSIVE', 'FALSE_POSITIVE', 'INFORMATIONAL', 'RETEST_REQUIRED'],
  REMEDIATION: ['RETEST_REQUIRED', 'ACCEPTED_RISK', 'VALIDATED'],
  RETEST_REQUIRED: [],
  VERIFIED: ['RETEST_REQUIRED'],
  REGRESSION: ['RETEST_REQUIRED', 'REMEDIATION', 'VALIDATED'],
  FALSE_POSITIVE: ['VALIDATING', 'CANDIDATE'],
  ACCEPTED_RISK: ['VALIDATING', 'REMEDIATION', 'CANDIDATE'],
  INCONCLUSIVE: ['VALIDATING', 'CANDIDATE', 'VALIDATED'],
  INFORMATIONAL: ['CANDIDATE', 'VALIDATING'],
  FIXED: ['RETEST_REQUIRED', 'REGRESSION'],
};

export function offeredTransitions(state: string): readonly string[] {
  return OFFERED_TRANSITIONS[state] ?? [];
}

/** States a scoring write is still legal for, mirroring the server's closed set. */
const CLOSED_STATES = ['FALSE_POSITIVE', 'ACCEPTED_RISK', 'INFORMATIONAL', 'FIXED'];

export function isScoreable(state: string): boolean {
  return !CLOSED_STATES.includes(state);
}

/** The states from which `recordRemediation` can move a finding to REMEDIATION. */
const REMEDIATION_PRECURSORS = ['VALIDATED', 'ACCEPTED_RISK', 'REGRESSION'];

export function remediationPrecursor(state: string): boolean {
  return REMEDIATION_PRECURSORS.includes(state);
}

/**
 * The states from which a retest can be *requested*.
 *
 * A retest is no longer something the analyst resolves, so there is no verdict
 * picker here at all: `requestRetest` only queues the finding, and
 * `recordRetestResult` on the server is the sole path to VERIFIED or REGRESSION,
 * deriving the outcome from the tests a run recorded. What is left here is
 * deciding whether to *offer* the request.
 *
 * RETEST_REQUIRED is the ordinary case. VERIFIED is included because a fix that
 * later regresses has to be re-checkable, and requesting a retest is how that is
 * started.
 */
const RETEST_REQUESTABLE_STATES = ['RETEST_REQUIRED', 'VERIFIED'];

export function retestEligible(state: string): boolean {
  return RETEST_REQUESTABLE_STATES.includes(state);
}

/**
 * The next step a reader of the lifecycle page should take, per state.
 *
 * `REMEDIATION` is the case that needed spelling out. Recording a remediation
 * moves a finding into `REMEDIATION`, and that state satisfies neither
 * `remediationPrecursor` nor `retestEligible`, so both forms disappear from the
 * page at exactly the moment the analyst needs to know what to do next. The
 * transition form still offers `RETEST_REQUIRED`, but nothing on screen said that
 * the fix is recorded and the retest is what resolves it -- so the page read as a
 * dead end at the exact point the workflow hands off from a human to the engine.
 *
 * `null` means there is genuinely no next step to name. Returning a string for a
 * state with no available move would be worse than silence.
 */
const NEXT_STEP: Readonly<Record<string, string>> = {
  REMEDIATION:
    'The remediation is recorded. Move this finding to RETEST_REQUIRED to have the assessment engine re-check it; only a recorded retest resolves it.',
  RETEST_REQUIRED:
    'Waiting for the assessment engine. This finding resolves when a run reports what it found: PASS to VERIFIED, FAIL to REGRESSION. Nothing here can shortcut that.',
};

export function nextLifecycleStep(state: string): string | null {
  return NEXT_STEP[state] ?? null;
}