/**
 * WM SecureScan — candidate findings from real test results.
 *
 * This is the bridge between "a test failed" and "there is a finding to work".
 * It exists as its own module because the transformation has rules that must not
 * be scattered across the orchestrator, and because every rule here is a rule
 * about *not overstating* what a static observation proves.
 *
 * The rules, in order of importance:
 *
 *  1. **A FAIL is a candidate, not a verdict.** Nothing here produces
 *     `VALIDATED`. A candidate says "a control did not do its job, here is what
 *     was looked at"; promoting it is a separate, human, audited step. A static
 *     FAIL is an observation about configuration or source, not proof that the
 *     weakness is reachable.
 *  2. **No severity is invented.** The engine's `RiskInput` needs impact,
 *     exposure, privilege and data-class judgements that a static module does
 *     not and cannot determine. Guessing them would produce a confident-looking
 *     band with nothing behind it, which is the exact failure this platform
 *     exists to prevent. Candidates therefore carry `NONE` and an explicit
 *     "not yet scored" rationale; severity is assigned by `assessRisk` when an
 *     analyst supplies the missing judgements.
 *  3. **Confidence is copied, never invented.** It comes from the failing test,
 *     which measured its own corroboration count.
 *  4. **Nothing is dropped silently.** Every FAIL reaches the output, every FAIL
 *     merged into a shared fingerprint is counted, and a FAIL that cannot be
 *     attributed to a detected component is reported as an anomaly instead of
 *     being assigned a component it does not belong to.
 */

import { buildCandidateFinding, deduplicateFindings, type FindingDraft } from './findings';
import { controlIdFor } from './ids';
import type { DetectedArchitecture } from './architecture';
import type {
  ArchitectureNodeId,
  Evidence,
  Finding,
  SecurityTestResult,
  TestId,
  TrustBoundaryId,
} from './types';

export interface CandidateOutcome {
  readonly findings: readonly Finding[];
  /** FAIL results that produced these findings. */
  readonly failedTestCount: number;
  /** Observations that collapsed into an existing fingerprint. */
  readonly mergedCount: number;
  /**
   * FAIL results that reached the output without evidence. Expected to be empty
   * because `Recorder` refuses to record such a test; surfaced so a module
   * regression is visible instead of silent.
   */
  readonly unbackedTestIds: readonly TestId[];
  /**
   * FAIL results whose control id did not resolve to a component detected in
   * this snapshot. `Finding.node` is a required, meaningful field, so these are
   * reported for the caller to record as untested rather than attributed to an
   * arbitrary component.
   */
  readonly unattributedTestIds: readonly TestId[];
}

/**
 * Recovers the architecture node from a control id.
 *
 * Tests store `controlIdFor(node, control)` and carry no other record of the
 * node, so the prefix is matched against the nodes actually detected in this
 * snapshot. Matching against detected nodes means a test can never be
 * attributed to a component that is not present.
 */
function nodeForControl(
  controlId: string,
  architecture: DetectedArchitecture,
): ArchitectureNodeId | null {
  for (const node of architecture.nodes) {
    if (controlId.startsWith(controlIdFor(node.id, ''))) return node.id;
  }
  return null;
}

/**
 * Derive endpoints from a test target, or nothing.
 *
 * A target is a file path far more often than it is a route, and it is sometimes
 * a *route pattern* rather than a route: `vercel.json` declares entries like
 * `/((?!docs|embed).*)`, and recording that as an affected endpoint would put a
 * regular expression in a list whose whole purpose is to name real request
 * paths. It would also feed the fingerprint, merging or splitting findings for
 * reasons unrelated to the target's security posture.
 *
 * So a target is only treated as an endpoint when it looks like one: it starts
 * with a single `/`, and it contains no regular-expression metacharacter.
 */
function endpointsFromTarget(target: string): readonly string[] {
  const trimmed = target.trim();
  if (trimmed === '') return [];
  if (!trimmed.startsWith('/')) {
    if (!/^https?:\/\//i.test(trimmed)) return [];
    try {
      return [new URL(trimmed).pathname];
    } catch {
      return [];
    }
  }
  if (/[?*+()[\]{}|\\^$]/.test(trimmed)) return [];
  return [trimmed.split(/[?#]/)[0] ?? trimmed];
}

/**
 * The control's readable half, recovered from `CTRL-<NODE>-<CONTROL>`.
 *
 * Used only to make the title legible. A control id is still what the finding
 * stores, so the title can never disagree with the machine-readable identity.
 */
function controlNameFrom(controlId: string): string | null {
  const withoutPrefix = controlId.startsWith('CTRL-') ? controlId.slice('CTRL-'.length) : controlId;
  const parts = withoutPrefix.split('-');
  return parts.length > 1 ? parts.slice(1).join('-') : null;
}

/**
 * A human-readable title built only from facts the engine recorded.
 *
 * Derived from the test's own control and target, so the title cannot claim
 * something the observation does not support. No severity word, no
 * "vulnerability", no "exploit" — the state is CANDIDATE and the title should
 * read like a question the analyst still has to answer.
 */
function titleFor(test: SecurityTestResult): string {
  const control = controlNameFrom(test.control) ?? test.control;
  const target = test.target.trim() === '' ? test.module : test.target.trim();
  return `${control} not satisfied on ${target}`;
}

/**
 * The root cause statement is the test's own observation, restated.
 *
 * `expected`/`observed` is the module's own account of the gap, so using it
 * verbatim keeps the finding traceable to the run instead of introducing a
 * fresh, unreferenced claim.
 */
function rootCauseFor(tests: readonly SecurityTestResult[]): string {
  return tests
    .map((test) => `${test.testId}: expected ${test.expected}; observed ${test.observed}`)
    .sort()
    .join(' | ');
}

export async function buildCandidateFindings(input: {
  readonly tests: readonly SecurityTestResult[];
  readonly evidence: readonly Evidence[];
  readonly architecture: DetectedArchitecture;
  readonly assessmentId: string;
  readonly now: () => string;
}): Promise<CandidateOutcome> {
  const failing = input.tests
    .filter((test) => test.status === 'FAIL')
    .sort((a, b) => a.testId.localeCompare(b.testId));

  const unbacked = failing.filter((test) => test.evidenceIds.length === 0).map((test) => test.testId);
  const nodesPresent = new Set(
    input.architecture.nodes.filter((node) => node.present).map((node) => node.id),
  );
  const createdAt = input.now();

  const attributable = failing.filter((test) => nodeForControl(test.control, input.architecture) !== null);
  const unattributed = failing.filter((test) => nodeForControl(test.control, input.architecture) === null);

  const drafts: FindingDraft[] = attributable.map((test) => {
    const node = nodeForControl(test.control, input.architecture) as ArchitectureNodeId;
    const boundary: TrustBoundaryId | null = test.boundary;
    return {
      category: test.category,
      title: titleFor(test),
      component: test.component,
      node,
      boundary,
      control: test.control,
      affectedEndpoints: endpointsFromTarget(test.target),
      description:
        `A failing check on the ${test.component} component of ${input.assessmentId}, recorded by the ${test.module} module. ` +
        `The engine expected ${test.expected} and observed ${test.observed}. ` +
        'This is a candidate produced by a static observation: it records that the control did not do its job, ' +
        'not that the weakness has been shown to be reachable. It must be validated before it is treated as a confirmed issue.',
      rootCause: rootCauseFor([test]),
      failingTestIds: [test.testId] as readonly TestId[],
      evidenceIds: test.evidenceIds,
      reproduction: [],
      controlledPoc: [],
      businessImpact: 'Not yet assessed. Business impact is recorded by an analyst during validation.',
      references: [],
      historicalStatus: 'CURRENTLY_OBSERVED',
      // Severity is deliberately omitted: `buildCandidateFinding` leaves it NONE
      // with an explicit "not yet scored" rationale. Confidence is the test's own
      // measured value, copied rather than invented.
      confidence: test.confidence,
      createdAt,
    };
  });

  const built: Finding[] = [];
  for (let index = 0; index < drafts.length; index += 1) {
    const draft = drafts[index];
    if (!draft) continue;
    built.push(
      await buildCandidateFinding(draft, { assessmentId: input.assessmentId, nodesPresent, ordinal: index }),
    );
  }

  const { findings, merged } = deduplicateFindings(built);

  return {
    findings,
    failedTestCount: failing.length,
    mergedCount: merged,
    unbackedTestIds: unbacked,
    unattributedTestIds: unattributed.map((test) => test.testId),
  };
}
