/**
 * WM SecureScan — domain model.
 *
 * The engine is pure: no I/O, no clock, no network. Everything time- and
 * environment-dependent arrives through the ports declared in `repo.ts` and the
 * caller-supplied `AssessmentContext`. That is what makes an assessment
 * reproducible — re-running the same snapshot against the same scope has to
 * produce byte-identical results, otherwise a retest cannot prove anything.
 *
 * The model is deliberately split into many small records rather than one
 * assessment blob. A finding that references a test, which references an
 * assessment, which references evidence, is what lets the console answer
 * "which control regressed" without loading an entire engagement into memory.
 */

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/**
 * Stable, human-readable identifiers (`F-014`, `EV-002`, `AUTHZ-001`).
 *
 * Deliberately *not* random: a fingerprint is derived from the observation, so
 * the same defect observed in two assessments produces the same id. A random
 * id would make the regression suite unable to recognise its own tests.
 */
export type FindingId = string;
export type EvidenceId = string;
export type TestId = string;
export type TestRunId = string;
export type AssessmentId = string;
export type RemediationId = string;
export type RetestId = string;
export type RegressionTestId = string;
export type SurfaceId = string;

// ---------------------------------------------------------------------------
// Authorization and scope
// ---------------------------------------------------------------------------

/**
 * An assessment may only run against something the operator has asserted they
 * are allowed to test. This is a *declaration*, not a verification — the
 * platform cannot prove a human owns a hostname, which is exactly why
 * `assertAuthorized` fails closed on anything weaker than `CONFIRMED`.
 */
export type AuthorizationStatus =
  | 'UNCONFIRMED'
  | 'PENDING_REVIEW'
  | 'CONFIRMED'
  | 'SELF_HOSTED'
  | 'LOCAL_ONLY';

export type EnvironmentKind = 'LOCAL' | 'SELF_HOSTED' | 'STAGING' | 'PRODUCTION';

export type TestIntensity = 'PASSIVE' | 'LOW' | 'MEDIUM' | 'HIGH';

/**
 * What a module is allowed to do. Enforced in `scope.ts`, never advisory.
 *
 * PASSIVE  — reads the repository and configuration only. No sockets.
 * LOW      — single non-destructive request per check against an in-scope host.
 * MEDIUM   — a bounded sequence of non-destructive requests (rate-limit probes).
 * HIGH     — reserved. Refused unless `ALLOW_HIGH_INTENSITY` is set explicitly,
 *            because no module in this repository requires it and the value
 *            exists so a future module can never be added without a
 *            deliberate configuration change.
 */
export type ProbeCapability = 'NONE' | 'SINGLE_REQUEST' | 'BOUNDED_SEQUENCE';

/** The declared authorization envelope. Everything not listed is out of scope. */
export interface AssessmentScope {
  readonly authorization: AuthorizationStatus;
  readonly environment: EnvironmentKind;
  readonly allowedDomains: readonly string[];
  /** Path prefixes. Empty means "no path-level restriction beyond the domain". */
  readonly allowedPaths: readonly string[];
  readonly allowedApiPaths: readonly string[];
  /** Test account the operator supplied. Never brute-forced. */
  readonly testAccountLabel: string;
  readonly intensity: TestIntensity;
  /** Hard ceiling on requests an entire assessment may issue. */
  readonly maxRequests: number;
  /** Collector must refuse to exceed this, and must not retry past it. */
  readonly requestTimeoutMs: number;
  readonly collectEvidence: boolean;
}

// ---------------------------------------------------------------------------
// Architecture
// ---------------------------------------------------------------------------

/**
 * The World Monitor components this engine knows how to reason about. A
 * `RepoSnapshot` that contains none of these is not a World Monitor target and
 * the assessment must say so rather than reporting vacuous passes.
 */
export type ArchitectureNodeId =
  | 'browser-spa'
  | 'vercel-edge'
  | 'edge-gateway'
  | 'sebuf-handlers'
  | 'legacy-api-js'
  | 'upstash-redis'
  | 'convex'
  | 'railway-relay'
  | 'external-providers'
  | 'rss-content'
  | 'mcp-interface'
  | 'oauth-server'
  | 'tauri-shell'
  | 'sidecar'
  | 'build-toolchain';

export type ArchitectureNodeKind =
  | 'CLIENT'
  | 'EDGE'
  | 'SERVERLESS'
  | 'CACHE'
  | 'DATABASE'
  | 'RELAY'
  | 'EXTERNAL'
  | 'DESKTOP'
  | 'BUILD';

export interface ArchitectureNode {
  readonly id: ArchitectureNodeId;
  readonly kind: ArchitectureNodeKind;
  readonly label: string;
  /** Repo paths that prove the node exists in this checkout. */
  readonly evidence: readonly string[];
  readonly present: boolean;
}

export type ArchitectureEdgeKind =
  | 'FETCHES'
  | 'AUTHENTICATES'
  | 'AUTHORIZES'
  | 'CACHES'
  | 'PROXIES'
  | 'CALLS'
  | 'TRUSTS'
  | 'RENDERS'
  | 'STORES'
  | 'PUBLISHES';

export interface ArchitectureEdge {
  readonly from: ArchitectureNodeId;
  readonly to: ArchitectureNodeId;
  readonly kind: ArchitectureEdgeKind;
  readonly label: string;
}

export type TrustBoundaryId =
  | 'TB-1-BROWSER-EDGE'
  | 'TB-2-EDGE-UPSTREAM'
  | 'TB-3-DESKTOP-TAURI'
  | 'TB-4-TAURI-SIDECAR'
  | 'TB-5-APP-REDIS'
  | 'TB-6-APP-CONVEX'
  | 'TB-7-APP-EXTERNAL-CONTENT'
  | 'TB-8-MCP-EXTERNAL-CLIENT';

export interface TrustBoundary {
  readonly id: TrustBoundaryId;
  readonly from: ArchitectureNodeId;
  readonly to: ArchitectureNodeId;
  readonly label: string;
  /** What an attacker controls on the `from` side. */
  readonly untrustedInput: string;
  /** The control that makes the crossing safe, if one exists. */
  readonly expectedControl: string;
}

// ---------------------------------------------------------------------------
// Attack surface
// ---------------------------------------------------------------------------

export type SurfaceType =
  | 'EDGE_ROUTE'
  | 'RPC_METHOD'
  | 'MCP_TOOL'
  | 'OAUTH_ENDPOINT'
  | 'EXTERNAL_FETCH'
  | 'TAURI_COMMAND'
  | 'SIDECAR_ROUTE'
  | 'REDIS_KEY_PATTERN'
  | 'CONVEX_FUNCTION'
  | 'ENV_SECRET';

export type AccessLevel = 'PUBLIC' | 'SESSION' | 'API_KEY' | 'INTERNAL' | 'UNKNOWN';

export interface AttackSurfaceEntry {
  readonly id: SurfaceId;
  readonly type: SurfaceType;
  /** HTTP path, RPC name, Tauri command name, sidecar route, or key prefix. */
  readonly location: string;
  readonly method: string;
  readonly node: ArchitectureNodeId;
  readonly boundary: TrustBoundaryId | null;
  readonly access: AccessLevel;
  readonly controls: readonly string[];
  /** Test ids that exercise this surface. */
  readonly testIds: readonly string[];
}

// ---------------------------------------------------------------------------
// Security controls
// ---------------------------------------------------------------------------

/**
 * `PRESENT`  — the control exists and its configuration satisfies the
 *               World Monitor policy the engine encodes.
 * `WEAK`     — present but below policy. Not a vulnerability on its own.
 * `ABSENT`   — the control is not implemented for this surface.
 * `NA`       — not applicable to this surface (e.g. frame protections on a
 *               non-HTML API response).
 *
 * `ABSENT` is deliberately *not* the same as a finding. Absence only becomes a
 * candidate finding when a test can show the absent control was load-bearing.
 */
export type ControlStatus = 'PRESENT' | 'WEAK' | 'ABSENT' | 'NOT_APPLICABLE';

export interface SecurityControl {
  readonly id: string;
  readonly label: string;
  readonly node: ArchitectureNodeId;
  readonly boundary: TrustBoundaryId | null;
  readonly status: ControlStatus;
  /** Why the engine assigned this status. Present for every non-PRESENT. */
  readonly rationale: string;
  readonly evidenceIds: readonly EvidenceId[];
  /** Framework references recorded verbatim with version. Never invented. */
  readonly mappings: readonly FrameworkMapping[];
  readonly lastTestedAt: string | null;
}

export interface FrameworkMapping {
  readonly framework: 'OWASP_ASVS' | 'OWASP_API_SECURITY_TOP_10' | 'OWASP_ASVS_5' | 'NIST_SSDF' | 'CVSS';
  readonly version: string;
  /** e.g. `V4.0.1` */
  readonly versionDetail: string;
  /** e.g. `V4.0.3-Authentication` */
  readonly reference: string;
  /** How the mapping was established. */
  readonly basis: 'DOCUMENTED_IN_REPO' | 'ANALYST_ASSIGNED';
}

// ---------------------------------------------------------------------------
// Tests and results
// ---------------------------------------------------------------------------

export type TestStatus = 'PASS' | 'FAIL' | 'INCONCLUSIVE' | 'NOT_TESTED' | 'SKIPPED_OUT_OF_SCOPE';

export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH';

/**
 * A test is a *question about a control*, not a vulnerability. It records what
 * it expected, what it observed, and how sure it is — the gap between those is
 * what a finding is later built from.
 */
export interface SecurityTestResult {
  readonly testId: TestId;
  readonly assessmentId: AssessmentId;
  readonly runId: TestRunId;
  readonly module: string;
  readonly category: string;
  readonly component: string;
  readonly control: string;
  readonly target: string;
  readonly boundary: TrustBoundaryId | null;
  readonly expected: string;
  readonly observed: string;
  readonly status: TestStatus;
  readonly confidence: Confidence;
  readonly evidenceIds: readonly EvidenceId[];
  readonly notes: readonly string[];
  /** Modules declare this so the orchestrator can skip work it cannot do. */
  readonly requiresCapability: ProbeCapability;
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

export type EvidenceType =
  | 'CONFIGURATION'
  | 'SOURCE_EXTRACTION'
  | 'HTTP_REQUEST'
  | 'HTTP_RESPONSE'
  | 'DEPENDENCY_ADVISORY'
  | 'CONTRACT_DECLARATION'
  | 'ATTACK_SURFACE'
  | 'CALCULATION'
  | 'ARTIFACT_HASH';

/**
 * Evidence is append-only and content-addressed. `sha256` covers
 * `JSON.stringify({ type, description, payload })` with sorted keys, so two
 * runs of the same test on the same snapshot produce the same digest — which is
 * what makes "the retest saw exactly the same thing" a checkable claim.
 */
export interface Evidence {
  readonly evidenceId: EvidenceId;
  readonly findingId: FindingId | null;
  readonly testId: TestId | null;
  readonly assessmentId: AssessmentId;
  readonly collectedAt: string;
  readonly type: EvidenceType;
  readonly description: string;
  readonly payload: EvidencePayload;
  readonly sha256: string;
  /** Who/what produced it. `human` is only set for analyst-uploaded evidence. */
  readonly producedBy: string;
  readonly targetEnvironment: EnvironmentKind;
  /** Set when the evidence came from a code path or file, for traceability. */
  readonly sourceLocation: string | null;
}

export type EvidencePayload =
  | { readonly kind: 'source-lines'; readonly path: string; readonly startLine: number; readonly endLine: number; readonly text: string }
  | { readonly kind: 'config-value'; readonly path: string; readonly pointer: string; readonly value: string }
  | { readonly kind: 'http-request'; readonly method: string; readonly url: string; readonly headers: Readonly<Record<string, string>>; readonly bodyPreview: string }
  | { readonly kind: 'http-response'; readonly status: number; readonly headers: Readonly<Record<string, string>>; readonly bodyPreview: string }
  | { readonly kind: 'advisory'; readonly packageName: string; readonly version: string; readonly advisoryId: string; readonly severity: string; readonly affectedRange: string }
  | { readonly kind: 'contract'; readonly protoFile: string; readonly message: string; readonly expectation: string; readonly observed: string }
  | { readonly kind: 'surface-list'; readonly entries: readonly { readonly id: string; readonly location: string; readonly type: string }[] }
  | { readonly kind: 'calculation'; readonly formula: string; readonly inputs: Readonly<Record<string, string>>; readonly result: string }
  | { readonly kind: 'hash'; readonly algorithm: string; readonly subject: string; readonly digest: string };

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export type FindingState =
  | 'CANDIDATE'
  | 'VALIDATING'
  | 'VALIDATED'
  | 'REMEDIATION'
  | 'RETEST_REQUIRED'
  | 'VERIFIED'
  | 'FALSE_POSITIVE'
  | 'ACCEPTED_RISK'
  | 'INCONCLUSIVE'
  | 'REGRESSION'
  /**
   * A recorded observation that is not a weakness. Deliberately a state rather
   * than a deleted row: "we checked, and this is by design" is an audit
   * statement, and losing it means the next reviewer repeats the work.
   */
  | 'INFORMATIONAL'
  /** Remediation landed and the regression test confirmed it still holds. */
  | 'FIXED';


export type Severity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * How a finding relates to World Monitor's own history. A repository advisory
 * that was already fixed is not a current finding, and the engine must be able
 * to say which it is looking at.
 */
export type HistoricalStatus =
  | 'CURRENTLY_OBSERVED'
  | 'FIXED_HISTORICAL'
  | 'NOT_REPRODUCED'
  | 'NOT_APPLICABLE'
  | 'REQUIRES_VALIDATION';

export interface CvssAssessment {
  /** Present only when a vector was actually scored. Never a default. */
  readonly version: '3.1' | '4.0' | null;
  readonly vector: string | null;
  readonly baseScore: number | null;
  readonly severity: Severity | null;
  readonly impact: string | null;
  readonly exploitability: string | null;
  /**
   * Why each chosen metric applies, keyed by metric name. A score without
   * justification is a guess, and a guess is not a risk assessment.
   */
  readonly metricRationale: Readonly<Record<string, string>>;
  /** 0-100. Reflects evidence strength, not impact. */
  readonly confidence: number;
  readonly environmentalContext: string | null;
}

export interface RiskAssessment {
  readonly technicalSeverity: Severity;
  readonly businessImpact: string;
  readonly cvss: CvssAssessment;
  /** Separation of technical severity, business impact and confidence. */
  readonly confidence: Confidence;
  /**
   * Why this band was chosen, one line per factor, in the order applied.
   *
   * Stored on the finding rather than recomputed on render, so a stored finding
   * stays interpretable after the methodology is revised, and so the report can
   * never show a severity the engine cannot justify.
   */
  readonly severityRationale: readonly string[];
  /** Version of the methodology that produced `severityRationale`. */
  readonly severityMethodologyVersion: string;
}

export interface Remediation {
  readonly id: RemediationId;
  readonly findingId: FindingId;
  readonly rootCause: string;
  readonly technicalExplanation: string;
  readonly affectedComponent: string;
  readonly securityImpact: string;
  readonly recommendedFix: string;
  readonly mitigation: string;
  readonly priority: Severity;
  readonly owner: string;
  readonly status: 'OPEN' | 'IN_PROGRESS' | 'FIXED' | 'RETEST_REQUIRED' | 'VERIFIED' | 'ACCEPTED_RISK';
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface Finding {
  readonly id: FindingId;
  readonly title: string;
  readonly category: string;
  readonly component: string;
  readonly node: ArchitectureNodeId;
  readonly boundary: TrustBoundaryId | null;
  /**
   * Id of the control whose test produced this finding. A finding always comes
   * from a control, so this is not optional — it is what lets a future
   * assessment recognise the same defect as a regression of a known control.
   */
  readonly control: string;
  readonly affectedEndpoints: readonly string[];
  readonly description: string;
  readonly rootCause: string;
  /** Shared across findings produced by the same underlying defect. */
  readonly rootCauseId: string;
  readonly severity: Severity;
  readonly confidence: Confidence;
  readonly risk: RiskAssessment;
  readonly historicalStatus: HistoricalStatus;
  readonly state: FindingState;
  readonly evidenceIds: readonly EvidenceId[];
  readonly reproduction: readonly string[];
  /** A non-destructive confirmation of behaviour. Empty when not attempted. */
  readonly controlledPoc: readonly string[];
  readonly businessImpact: string;
  readonly remediation: Remediation | null;
  readonly retestResult: RetestResult | null;
  readonly regressionTestId: RegressionTestId | null;
  readonly references: readonly string[];
  readonly createdAt: string;
  readonly updatedAt: string;
  /** Deterministic identity used for dedup and regression matching. */
  readonly fingerprint: string;
}

// ---------------------------------------------------------------------------
// Retest and regression
// ---------------------------------------------------------------------------

export type RetestOutcome = 'VERIFIED_FIXED' | 'STILL_FAILING' | 'REGRESSED' | 'INCONCLUSIVE' | 'NO_LONGER_REPRODUCIBLE';

export interface RetestResult {
  readonly id: RetestId;
  readonly findingId: FindingId;
  readonly originalTestId: TestId;
  readonly retestTestId: TestId;
  /** Same control, re-executed. A retest that used a different test proves nothing. */
  readonly control: string;
  readonly outcome: RetestOutcome;
  readonly comparison: string;
  readonly evidenceIds: readonly EvidenceId[];
  readonly performedAt: string;
}

export interface RegressionTest {
  readonly id: RegressionTestId;
  /** The control that produced the original finding. */
  readonly control: string;
  readonly component: string;
  readonly node: ArchitectureNodeId;
  readonly boundary: TrustBoundaryId | null;
  readonly description: string;
  readonly sourceFindingId: FindingId;
  readonly module: string;
  /** Minimum test id that exercises this control. */
  readonly probeTestId: TestId;
  readonly createdAt: string;
  readonly lastRunAt: string | null;
  readonly lastOutcome: TestStatus | null;
  readonly consecutivePasses: number;
}

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

export interface DependencyAdvisory {
  readonly packageName: string;
  readonly currentVersion: string;
  readonly advisoryId: string;
  readonly advisorySource: string;
  readonly severity: string;
  readonly affectedRange: string;
  readonly fixedVersion: string | null;
  /**
   * `UNKNOWN` until a human or a reachability analysis resolves it. An
   * advisory without reachability is not an exploitable dependency.
   */
  readonly reachability: 'REACHABLE' | 'NOT_REACHABLE' | 'UNKNOWN';
  readonly evidenceIds: readonly EvidenceId[];
}

// ---------------------------------------------------------------------------
// Coverage, baseline, differential
// ---------------------------------------------------------------------------

export type CoverageStatus = 'TESTED_PASS' | 'TESTED_FAIL' | 'TESTED_INCONCLUSIVE' | 'NOT_TESTED';

export interface ControlCoverage {
  readonly controlId: string;
  readonly component: string;
  readonly boundary: TrustBoundaryId | null;
  readonly testIds: readonly TestId[];
  readonly status: CoverageStatus;
  readonly evidenceIds: readonly EvidenceId[];
  readonly lastTestedAt: string | null;
  readonly retestStatus: string | null;
}

export type DifferentialVerdict = 'NEW' | 'RESOLVED' | 'UNCHANGED' | 'REGRESSION' | 'NOT_TESTED';

export interface DifferentialEntry {
  readonly subject: string;
  readonly verdict: DifferentialVerdict;
  readonly note: string;
}

export interface DifferentialReport {
  readonly baselineAssessmentId: AssessmentId;
  readonly comparisonAssessmentId: AssessmentId;
  readonly entries: readonly DifferentialEntry[];
  readonly controlsAdded: readonly string[];
  readonly controlsRemoved: readonly string[];
  readonly newFindings: readonly FindingId[];
  readonly resolvedFindings: readonly FindingId[];
  readonly regressions: readonly FindingId[];
  readonly generatedAt: string;
}

// ---------------------------------------------------------------------------
// Assessment
// ---------------------------------------------------------------------------

export type AssessmentState = 'DRAFT' | 'READY' | 'RUNNING' | 'PAUSED' | 'COMPLETED' | 'FAILED' | 'CANCELLED';

export type ModuleStatus = 'QUEUED' | 'RUNNING' | 'COMPLETE' | 'FAILED' | 'SKIPPED';

export interface ModuleProgress {
  readonly module: string;
  readonly status: ModuleStatus;
  readonly testsRun: number;
  readonly startedAt: string | null;
  readonly finishedAt: string | null;
  readonly error: string | null;
}

export interface Assessment {
  readonly id: AssessmentId;
  readonly name: string;
  readonly state: AssessmentState;
  readonly scope: AssessmentScope;
  readonly moduleNames: readonly string[];
  readonly createdBy: string;
  readonly createdAt: string;
  readonly startedAt: string | null;
  readonly finishedAt: string | null;
  /** Free-text justification recorded at authorization time. */
  readonly authorizationNote: string;
}

export interface AssessmentRun {
  readonly id: TestRunId;
  readonly assessmentId: AssessmentId;
  readonly startedAt: string;
  readonly finishedAt: string | null;
  readonly progress: readonly ModuleProgress[];
  readonly requestsIssued: number;
  readonly errorCount: number;
  readonly warningCount: number;
  readonly durationMs: number | null;
}

export interface AssessmentResult {
  readonly assessment: Assessment;
  readonly run: AssessmentRun;
  readonly architecture: {
    readonly nodes: readonly ArchitectureNode[];
    readonly edges: readonly ArchitectureEdge[];
    readonly boundaries: readonly TrustBoundary[];
  };
  readonly surface: readonly AttackSurfaceEntry[];
  readonly tests: readonly SecurityTestResult[];
  readonly controls: readonly SecurityControl[];
  readonly findings: readonly Finding[];
  readonly evidence: readonly Evidence[];
  readonly coverage: readonly ControlCoverage[];
  readonly dependencies: readonly DependencyAdvisory[];
  readonly regressionTests: readonly RegressionTest[];
  readonly remediations: readonly Remediation[];
  readonly retests: readonly RetestResult[];
  /** Modules that were selected but produced no test. Surfaced, never hidden. */
  readonly notTested: readonly { readonly module: string; readonly reason: string }[];
  readonly toolVersion: string;
  /** Commit the snapshot was taken from, when known. */
  readonly targetRevision: string | null;
}
