/**
 * WM SecureScan — finding construction, deduplication and root-cause
 * correlation.
 *
 * The lifecycle gate is the important part. A `FAIL` test result is a
 * *candidate*, never a validated finding. It becomes `VALIDATED` only when
 * `validateFinding` is given evidence that satisfies the checks below, and
 * those checks are the reason the platform does not manufacture alert fatigue:
 *
 *  - the failing test must name at least one concrete observation, not just a
 *    pattern;
 *  - the finding must be attached to an architecture node that actually exists
 *    in the assessed snapshot;
 *  - a historical classification must be declared, so a repository advisory
 *    that was already fixed cannot enter the current-findings count.
 *
 * Anything short of that stays `CANDIDATE` and is reported as such.
 */

import {
  controlIdFor,
  endpointShapeSet,
  findingIdFor,
  fingerprintFor,
  normalizeEndpoint,
  regressionTestIdFor,
  rootCauseIdFor,
  testIdFor,
} from './ids';
import { unscoredAssessment } from './cvss';
import { SEVERITY_METHODOLOGY } from './risk';
import type {
  ArchitectureNodeId,
  Confidence,
  ControlCoverage,
  CoverageStatus,
  Evidence,
  EvidenceId,
  Finding,
  FindingId,
  FindingState,
  FrameworkMapping,
  HistoricalStatus,
  RegressionTest,
  Remediation,
  RemediationId,
  SecurityControl,
  SecurityTestResult,
  Severity,
  TestId,
  TestStatus,
  TrustBoundaryId,
} from './types';

export interface FindingDraft {
  readonly category: string;
  readonly title: string;
  readonly component: string;
  readonly node: ArchitectureNodeId;
  readonly boundary: TrustBoundaryId | null;
  readonly control: string;
  readonly affectedEndpoints: readonly string[];
  readonly description: string;
  readonly rootCause: string;
  readonly failingTestIds: readonly TestId[];
  readonly evidenceIds: readonly EvidenceId[];
  readonly reproduction: readonly string[];
  readonly controlledPoc: readonly string[];
  readonly businessImpact: string;
  readonly references: readonly string[];
  readonly historicalStatus: HistoricalStatus;
  readonly severity?: Severity;
  readonly confidence?: Confidence;
  readonly mappings?: readonly FrameworkMapping[];
  readonly createdAt: string;
}

export interface FindingContext {
  readonly assessmentId: string;
  readonly nodesPresent: ReadonlySet<ArchitectureNodeId>;
  readonly ordinal: number;
}

export async function buildCandidateFinding(
  draft: FindingDraft,
  context: FindingContext,
): Promise<Finding> {
  const fingerprint = await fingerprintFor({
    category: draft.category,
    rootCause: draft.rootCause,
    component: draft.component,
    endpoints: draft.affectedEndpoints,
    control: draft.control,
    boundary: draft.boundary,
  });
  const rootCauseId = await rootCauseIdFor({
    category: draft.category,
    rootCause: draft.rootCause,
    component: draft.component,
  });

  return {
    id: await findingIdFor(fingerprint, context.ordinal),
    title: draft.title,
    category: draft.category,
    component: draft.component,
    node: draft.node,
    boundary: draft.boundary,
    control: draft.control,
    affectedEndpoints: [...new Set(draft.affectedEndpoints)].sort(),
    description: draft.description,
    rootCause: draft.rootCause,
    rootCauseId,
    severity: draft.severity ?? 'NONE',
    confidence: draft.confidence ?? 'LOW',
    risk: {
      // A candidate carries no analysed risk. Severity stays NONE and the CVSS
      // block is empty until an analyst scores it; `technicalSeverity` is
      // deliberately not upgraded on creation.
      technicalSeverity: draft.severity ?? 'NONE',
      businessImpact: draft.businessImpact,
      cvss: unscoredAssessment(),
      confidence: draft.confidence ?? 'LOW',
      // Placeholder rationale: the real banding happens in `assessRisk` when an
      // analyst scores the finding. Recording an empty-but-present list keeps
      // the field non-optional so a finding can never reach a report with
      // severity and no stated reason for it.
      severityRationale: draft.severity === undefined
        ? ['Not yet scored. Severity is assigned by an analyst or by the risk engine once impact and reachability are established.']
        : [`Severity ${draft.severity} was set by the detecting module and has not been independently reviewed.`],
      severityMethodologyVersion: SEVERITY_METHODOLOGY.version,
    },
    historicalStatus: draft.historicalStatus,
    state: 'CANDIDATE',
    evidenceIds: draft.evidenceIds,
    reproduction: draft.reproduction,
    controlledPoc: draft.controlledPoc,
    businessImpact: draft.businessImpact,
    remediation: null,
    retestResult: null,
    regressionTestId: null,
    references: draft.references,
    createdAt: draft.createdAt,
    updatedAt: draft.createdAt,
    fingerprint,
  };
}

export interface ValidationCheck {
  readonly satisfied: boolean;
  readonly reason: string;
}

/**
 * Can this candidate be promoted to `VALIDATED`?
 *
 * Every check is reported, not just the first failure: an analyst needs to see
 * the whole gap list to know what evidence to collect, and a validator that
 * returns a single boolean teaches nothing.
 */
export function validateFinding(
  finding: Finding,
  context: {
    readonly tests: readonly SecurityTestResult[];
    readonly evidence: readonly Evidence[];
    readonly nodesPresent: ReadonlySet<ArchitectureNodeId>;
  },
): readonly ValidationCheck[] {
  const evidenceById = new Map(context.evidence.map((item) => [item.evidenceId, item]));

  const observedEvidence = finding.evidenceIds
    .map((id) => evidenceById.get(id))
    .filter((item): item is Evidence => item !== undefined);

  /**
   * Only the tests that produced *this* finding count toward validating it.
   *
   * The linkage runs through the evidence this finding actually references, and
   * not through "any FAIL in the assessment". Counting every failure would let a
   * finding about a missing CSP be promoted on the strength of an unrelated CORS
   * failure elsewhere in the same run — the candidate would inherit a
   * justification that has nothing to do with it, which is precisely the
   * fabricated-evidence failure mode this engine exists to avoid.
   */
  const linkedTestIds = new Set(
    observedEvidence.map((item) => item.testId).filter((id): id is TestId => typeof id === 'string' && id !== ''),
  );
  const linkedTests = context.tests.filter((test) => linkedTestIds.has(test.testId));
  const failing = linkedTests.filter((test) => test.status === 'FAIL');

  return [
    {
      satisfied: finding.evidenceIds.length > 0,
      reason:
        finding.evidenceIds.length > 0
          ? `${finding.evidenceIds.length} evidence record(s) attached.`
          : 'No evidence attached. A finding without evidence is an assertion, not a result.',
    },
    {
      satisfied: observedEvidence.length === finding.evidenceIds.length,
      reason:
        observedEvidence.length === finding.evidenceIds.length
          ? 'Every referenced evidence id resolves to a stored record.'
          : `${finding.evidenceIds.length - observedEvidence.length} referenced evidence id(s) do not resolve. A dangling reference cannot support validation.`,
    },
    {
      satisfied: observedEvidence.some((item) => item.type !== 'ARTIFACT_HASH'),
      reason: observedEvidence.some((item) => item.type !== 'ARTIFACT_HASH')
        ? 'At least one substantive (non-digest-only) evidence record is attached.'
        : 'Only digest records are attached. A hash proves integrity, not behaviour.',
    },
    {
      satisfied: failing.length > 0 || finding.state === 'REGRESSION',
      reason:
        failing.length > 0 || finding.state === 'REGRESSION'
          ? `${failing.length} failing test result(s) among the ${linkedTests.length} test(s) linked to this finding's evidence produced it.`
          : linkedTests.length === 0
            ? 'No test result is linked to this finding through its evidence, so nothing produced it. Candidates arise from a FAIL of a test that collected their own evidence.'
            : `None of the ${linkedTests.length} test(s) linked to this finding's evidence failed, so a FAIL did not produce this candidate.`,
    },
    {
      satisfied: context.nodesPresent.has(finding.node),
      reason: context.nodesPresent.has(finding.node)
        ? `Attached to architecture node \`${finding.node}\`, which is present in the assessed snapshot.`
        : `Attached to \`${finding.node}\`, which was not found in the assessed snapshot. A finding cannot point at a component that does not exist.`,
    },
    {
      satisfied: finding.historicalStatus !== 'REQUIRES_VALIDATION',
      reason:
        finding.historicalStatus !== 'REQUIRES_VALIDATION'
          ? `Historical status resolved to ${finding.historicalStatus}.`
          : 'Historical status is still REQUIRES_VALIDATION. A repository advisory or past incident has not been classified as current or fixed.',
    },
    {
      satisfied: finding.description.trim().length >= 40,
      reason:
        finding.description.trim().length >= 40
          ? 'Description explains the observation rather than restating the control name.'
          : 'Description is too short to distinguish this observation from a sibling in the same category.',
    },
  ];
}

export function allChecksSatisfied(checks: readonly ValidationCheck[]): boolean {
  return checks.every((check) => check.satisfied);
}

export function unsatisfiedChecks(checks: readonly ValidationCheck[]): readonly string[] {
  return checks.filter((check) => !check.satisfied).map((check) => check.reason);
}

/**
 * Apply a lifecycle transition. Illegal transitions throw rather than
 * silently no-op, because a console that quietly drops a state change is worse
 * than one that reports it.
 */
/**
 * The finding lifecycle. This is the single source of truth for which state
 * changes are legal: `transitionFinding` enforces it, and `identity.ts` layers
 * the role gate on top of the same table so authorization and the state machine
 * can never disagree about what is reachable.
 *
 * A failed check enters as `CANDIDATE` and never becomes `VERIFIED` without
 * passing `validateFinding`, which requires evidence. `FALSE_POSITIVE` and
 * `ACCEPTED_RISK` remain reachable from every pre-verification state so a
 * reviewer can record a decision, and both can be reopened to `CANDIDATE`
 * because a wrong dismissal has to be correctable without editing history.
 */
export const FINDING_TRANSITIONS: Readonly<Record<FindingState, readonly FindingState[]>> = {
  CANDIDATE: ['VALIDATING', 'FALSE_POSITIVE', 'INCONCLUSIVE', 'ACCEPTED_RISK', 'INFORMATIONAL'],
  VALIDATING: ['VALIDATED', 'FALSE_POSITIVE', 'INCONCLUSIVE', 'ACCEPTED_RISK', 'CANDIDATE', 'INFORMATIONAL'],
  VALIDATED: ['REMEDIATION', 'ACCEPTED_RISK', 'INCONCLUSIVE', 'FALSE_POSITIVE', 'INFORMATIONAL', 'RETEST_REQUIRED'],
  REMEDIATION: ['RETEST_REQUIRED', 'ACCEPTED_RISK', 'VALIDATED', 'FIXED'],
  RETEST_REQUIRED: ['VERIFIED', 'REGRESSION', 'RETEST_REQUIRED', 'FIXED'],
  VERIFIED: ['REGRESSION', 'RETEST_REQUIRED'],
  REGRESSION: ['RETEST_REQUIRED', 'REMEDIATION', 'VALIDATED'],
  FALSE_POSITIVE: ['VALIDATING', 'CANDIDATE'],
  ACCEPTED_RISK: ['VALIDATING', 'REMEDIATION', 'CANDIDATE'],
  INCONCLUSIVE: ['VALIDATING', 'CANDIDATE', 'VALIDATED'],
  INFORMATIONAL: ['CANDIDATE', 'VALIDATING'],
  FIXED: ['RETEST_REQUIRED', 'REGRESSION'],
};

export function canTransitionFinding(from: FindingState, to: FindingState): boolean {
  return FINDING_TRANSITIONS[from]?.includes(to) ?? false;
}

/**
 * States that assert the problem is actually gone.
 *
 * `VERIFIED` and `FIXED` are the only two states in the lifecycle that claim a
 * defect no longer reproduces. Reaching either from the table alone is not
 * sufficient evidence of that, because `RETEST_REQUIRED -> VERIFIED` is a legal
 * edge that says only "a retest is due", not "a retest was run and passed". A
 * caller that reached for the edge without a passing retest would be asserting a
 * security outcome it never observed, which is the exact failure mode this
 * product exists to prevent. `recordRetest` supplies the proof; nothing else
 * does.
 */
export const RESOLUTION_STATES: readonly FindingState[] = ['VERIFIED', 'FIXED'];

export function assertsResolution(to: FindingState): boolean {
  return RESOLUTION_STATES.includes(to);
}

export function transitionFinding(
  finding: Finding,
  next: FindingState,
  now: string,
  patch: Partial<Finding> = {},
): Finding {
  if (finding.state === next) return { ...finding, ...patch, updatedAt: now };
  const allowed = FINDING_TRANSITIONS[finding.state] ?? [];
  if (!allowed.includes(next)) {
    throw new Error(
      `Illegal finding transition ${finding.state} -> ${next} for ${finding.id}. Allowed: ${allowed.join(', ') || 'none'}.`,
    );
  }
  return { ...finding, ...patch, state: next, updatedAt: now };
}

// ---------------------------------------------------------------------------
// Deduplication and correlation
// ---------------------------------------------------------------------------

export interface RootCauseGroup {
  readonly rootCauseId: string;
  readonly rootCause: string;
  readonly component: string;
  readonly category: string;
  readonly findingIds: readonly FindingId[];
  readonly affectedEndpoints: readonly string[];
  readonly endpointShapes: readonly string[];
  readonly maxSeverity: Severity;
}

/**
 * Group findings that share a root cause.
 *
 * This runs after dedup, so it collapses the *residual* duplicates that a
 * per-finding fingerprint cannot merge — for example the same authorization
 * defect reported against four separately-listed endpoints that normalise to
 * different shapes because one is a legacy `/api/*.js` path and three are
 * Sebuf RPCs.
 */
export function correlateRootCauses(findings: readonly Finding[]): readonly RootCauseGroup[] {
  const groups = new Map<string, RootCauseGroup>();
  for (const finding of findings) {
    const existing = groups.get(finding.rootCauseId);
    if (!existing) {
      groups.set(finding.rootCauseId, {
        rootCauseId: finding.rootCauseId,
        rootCause: finding.rootCause,
        component: finding.component,
        category: finding.category,
        findingIds: [finding.id],
        affectedEndpoints: [...finding.affectedEndpoints],
        endpointShapes: endpointShapeSet(finding.affectedEndpoints),
        maxSeverity: finding.severity,
      });
      continue;
    }
    groups.set(finding.rootCauseId, {
      ...existing,
      findingIds: [...existing.findingIds, finding.id].sort(),
      affectedEndpoints: [...new Set([...existing.affectedEndpoints, ...finding.affectedEndpoints])].sort(),
      endpointShapes: [...new Set([...existing.endpointShapes, ...endpointShapeSet(finding.affectedEndpoints)])].sort(),
      maxSeverity: maxSeverity(existing.maxSeverity, finding.severity),
    });
  }
  return [...groups.values()].sort((a, b) => b.findingIds.length - a.findingIds.length || a.rootCauseId.localeCompare(b.rootCauseId));
}

const SEVERITY_RANK: Record<Severity, number> = { NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_RANK[a] >= SEVERITY_RANK[b] ? a : b;
}

/**
 * Merge findings that share a fingerprint.
 *
 * Endpoint and evidence lists are unioned rather than taken from the first
 * occurrence, so two partial observations of the same defect produce one
 * finding covering the whole surface — which is the point of the fingerprint.
 */
export function deduplicateFindings(findings: readonly Finding[]): {
  readonly findings: readonly Finding[];
  readonly merged: number;
} {
  const byFingerprint = new Map<string, Finding>();
  let merged = 0;
  for (const finding of findings) {
    const existing = byFingerprint.get(finding.fingerprint);
    if (!existing) {
      byFingerprint.set(finding.fingerprint, finding);
      continue;
    }
    merged += 1;
    byFingerprint.set(finding.fingerprint, {
      ...existing,
      affectedEndpoints: [...new Set([...existing.affectedEndpoints, ...finding.affectedEndpoints])].sort(),
      evidenceIds: [...new Set([...existing.evidenceIds, ...finding.evidenceIds])].sort(),
      reproduction: dedupeStrings([...existing.reproduction, ...finding.reproduction]),
      controlledPoc: dedupeStrings([...existing.controlledPoc, ...finding.controlledPoc]),
      references: dedupeStrings([...existing.references, ...finding.references]),
      severity: maxSeverity(existing.severity, finding.severity),
      confidence: maxConfidence(existing.confidence, finding.confidence),
      updatedAt: existing.updatedAt > finding.updatedAt ? existing.updatedAt : finding.updatedAt,
    });
  }
  const ordered = [...byFingerprint.values()].sort((a, b) => a.id.localeCompare(b.id));
  return { findings: ordered, merged };
}

function dedupeStrings(values: readonly string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter((value) => value !== ''))].sort();
}

const CONFIDENCE_RANK: Record<Confidence, number> = { LOW: 0, MEDIUM: 1, HIGH: 2 };

export function maxConfidence(a: Confidence, b: Confidence): Confidence {
  return CONFIDENCE_RANK[a] >= CONFIDENCE_RANK[b] ? a : b;
}

// ---------------------------------------------------------------------------
// Remediation
// ---------------------------------------------------------------------------

export function buildRemediation(
  finding: Finding,
  input: {
    readonly rootCause: string;
    readonly technicalExplanation: string;
    readonly securityImpact: string;
    readonly recommendedFix: string;
    readonly mitigation: string;
    readonly owner: string;
    readonly now: string;
  },
): Remediation {
  const id: RemediationId = `REM-${finding.id.replace(/^F-/, '')}`;
  return {
    id,
    findingId: finding.id,
    rootCause: input.rootCause,
    technicalExplanation: input.technicalExplanation,
    affectedComponent: finding.component,
    securityImpact: input.securityImpact,
    recommendedFix: input.recommendedFix,
    mitigation: input.mitigation,
    priority: finding.severity,
    owner: input.owner,
    status: 'OPEN',
    createdAt: input.now,
    updatedAt: input.now,
  };
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

export function buildCoverage(
  controls: readonly SecurityControl[],
  tests: readonly SecurityTestResult[],
  now: string,
): readonly ControlCoverage[] {
  const byControl = new Map<string, TestId[]>();
  for (const test of tests) {
    if (test.status === 'SKIPPED_OUT_OF_SCOPE' || test.status === 'NOT_TESTED') continue;
    const list = byControl.get(test.control);
    if (list) list.push(test.testId);
    else byControl.set(test.control, [test.testId]);
  }

  return controls
    .map((control) => {
      const testIds = [...(byControl.get(control.id) ?? [])].sort();
      const related = tests.filter((test) => testIds.includes(test.testId));
      const status: CoverageStatus =
        testIds.length === 0
          ? 'NOT_TESTED'
          : related.some((test) => test.status === 'FAIL')
            ? 'TESTED_FAIL'
            : related.some((test) => test.status === 'INCONCLUSIVE')
              ? 'TESTED_INCONCLUSIVE'
              : 'TESTED_PASS';
      return {
        controlId: control.id,
        component: control.label,
        boundary: control.boundary,
        testIds,
        status,
        evidenceIds: [...new Set(related.flatMap((test) => test.evidenceIds))].sort(),
        lastTestedAt: testIds.length > 0 ? now : control.lastTestedAt,
        retestStatus: control.status === 'PRESENT' ? 'CONTROL_PRESENT' : 'CONTROL_DEGRADED',
      };
    })
    .sort((a, b) => a.controlId.localeCompare(b.controlId));
}

// ---------------------------------------------------------------------------
// Regression tests
// ---------------------------------------------------------------------------

/**
 * Convert a verified finding into a reusable regression test.
 *
 * The stored `probeTestId` is what makes this more than a bookmark: a later
 * assessment re-runs the *same* control and the baseline comparison reports
 * `REGRESSION` when that control starts failing again. A regression test whose
 * probe cannot be identified would silently never fire, so the caller is
 * required to name it.
 */
export function buildRegressionTest(
  finding: Finding,
  probeTestId: TestId,
  now: string,
): RegressionTest {
  return {
    id: regressionTestIdFor(finding.control, finding.node),
    control: finding.control,
    component: finding.component,
    node: finding.node,
    boundary: finding.boundary,
    description:
      `Regression guard for ${finding.control} on ${finding.component}. ` +
      `Derived from ${finding.id}; a future assessment that reports this control as FAIL raises a regression alert.`,
    sourceFindingId: finding.id,
    module: finding.category,
    probeTestId,
    createdAt: now,
    lastRunAt: null,
    lastOutcome: null,
    consecutivePasses: 0,
  };
}

export function updateRegressionOutcome(
  regression: RegressionTest,
  outcome: TestStatus,
  now: string,
): RegressionTest {
  return {
    ...regression,
    lastRunAt: now,
    lastOutcome: outcome,
    consecutivePasses: outcome === 'PASS' ? regression.consecutivePasses + 1 : 0,
  };
}

// ---------------------------------------------------------------------------
// Convenience re-exports so modules import from one place
// ---------------------------------------------------------------------------

export { controlIdFor, testIdFor, normalizeEndpoint };
