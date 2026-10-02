/**
 * WM SecureScan â€” browser data access.
 *
 * Three rules, each of which exists because this is a security product:
 *
 *  1. **No route, view, or button is an authorization decision.** The client
 *     sends the same call regardless of role and renders whatever the server
 *     says, including a refusal. Hiding a control is a courtesy, not a check;
 *     the server re-decides on every call.
 *  2. **A failure is a value, not an exception.** Every call resolves to a
 *     result union so a view can distinguish "not permitted", "no membership",
 *     "not found", and "the backend is unreachable", and say something honest
 *     about each. A generic try/catch that renders "something went wrong" is
 *     how a security console ends up implying a clean result after a failed
 *     read.
 *  3. **No token is ever stored here.** The shared Convex client owns the
 *     Clerk credential and refreshes it; this layer never sees a session token,
 *     never writes one to storage, and never puts one in a URL.
 *
 * The shared client (`@/services/convex-client`) is used rather than a private
 * one so SecureScan inherits the repository's single WebSocket, its
 * account-switch rebinding, and its sign-out invalidation. A second client
 * would be a second identity, and the two could disagree about who is signed
 * in â€” which in an access-controlled console is not a performance detail.
 */

import { getConvexClient, getConvexApi, waitForConvexAuth } from '@/services/convex-client';

import type { FunctionReference } from 'convex/server';

type ConvexClient = NonNullable<Awaited<ReturnType<typeof getConvexClient>>>;
type ConvexApi = NonNullable<Awaited<ReturnType<typeof getConvexApi>>>;

/** Mirrors the server role union. Duplicated, not imported: a browser bundle must not pull in a Convex server module. */
export type Role = 'ADMIN' | 'SECURITY_ANALYST' | 'VIEWER';

/**
 * Why a call did not produce data.
 *
 * `no_membership` is deliberately distinct from `forbidden`. The first means
 * "this account has no SecureScan membership at all" and needs an admin to grant
 * one; the second means "you are a member, but not permitted to do this".
 * Collapsing them into one "Access denied" leaves a user unable to tell whether
 * to ask an admin for access or to stop asking.
 */
export type FailureKind =
  | 'unauthenticated'
  | 'no_membership'
  | 'forbidden'
  | 'not_found'
  | 'unavailable'
  | 'unexpected';

export interface ResultOk<T> {
  readonly ok: true;
  readonly value: T;
}

export interface ResultFailure {
  readonly ok: false;
  readonly kind: FailureKind;
  readonly message: string;
}

export type Result<T> = ResultOk<T> | ResultFailure;

export function ok<T>(value: T): ResultOk<T> {
  return { ok: true, value };
}

export function fail(kind: FailureKind, message: string): ResultFailure {
  return { ok: false, kind, message };
}

/**
 * Read a refusal code out of whatever the transport handed back.
 *
 * Convex does not surface a bare `AUTH_REQUIRED`: it wraps a server throw in a
 * multi-line message that also carries a request id, the calling function, and
 * a stack (`[CONVEX Q(console:dashboard)] Server Error\n\nUncaught Error:
 * AUTH_REQUIRED\n    at ...`). Comparing that whole remainder for equality with
 * `AUTH_REQUIRED` can therefore never succeed, which is how every authorisation
 * refusal - being signed out, having no membership, having the wrong role -
 * collapsed into one generic "unexpected" card.
 *
 * The codes are matched as standalone tokens anywhere in the message instead.
 * They are distinctive enough that a coincidental substring is not a real
 * risk, and the reason is only used to pick a fixed, non-leaking message.
 */
function hasRefusalCode(message: string, code: string): boolean {
  return new RegExp(`\\b${code}\\b`).test(message);
}

function failureFor(error: unknown): ResultFailure {
  const raw = error instanceof Error ? error.message : String(error ?? '');
  const message = raw.replace(/^Error:\s*/, '').trim();

  if (hasRefusalCode(message, 'AUTH_REQUIRED')) {
    return { ok: false, kind: 'unauthenticated', message: 'Sign in to continue.' };
  }
  if (hasRefusalCode(message, 'SECURESCAN_NO_MEMBERSHIP')) {
    return { ok: false, kind: 'no_membership', message: 'This account has no SecureScan membership.' };
  }
  if (hasRefusalCode(message, 'ROLE_FORBIDDEN')) {
    return { ok: false, kind: 'forbidden', message: 'Your role does not permit this action.' };
  }
  if (message.includes('NOT_FOUND')) {
    return { ok: false, kind: 'not_found', message: 'That record no longer exists.' };
  }
  if (/CONVEX_UNCONFIGURED|fetch failed|network|WebSocket|Unauthorized|TypeError/i.test(raw)) {
    return { ok: false, kind: 'unavailable', message: 'The SecureScan backend is unreachable.' };
  }
  // Never surface a raw Convex error: it can carry internal ids, schema
  // fragments, or a server file path. The detail stays server-side.
  return { ok: false, kind: 'unexpected', message: 'The request could not be completed.' };
}

async function call<T>(work: (client: ConvexClient, api: ConvexApi) => Promise<T>): Promise<Result<T>> {
  try {
    // Wait for the shared client to finish its Clerk handshake so a signed-in
    // user is not refused as anonymous on first paint. A timeout here is not a
    // refusal: the call still runs, and the server decides.
    await waitForConvexAuth(10_000);
    const client = await getConvexClient();
    const api = await getConvexApi();
    if (!client || !api) return fail('unavailable', 'The SecureScan backend is not configured.');
    return ok(await work(client, api));
  } catch (error) {
    return failureFor(error);
  }
}

// The generated api is `anyApi` (a `FunctionReference` always reachable by
// string path) until codegen runs, so `ref` reaches in by module/name and
// casts. `_type: never` keeps the reference acceptable to both the `query`
// (FunctionReference<"query">) and `mutation` (FunctionReference<"mutation">)
// client methods without widening to `any`.
type QueryRef = FunctionReference<'query' | 'mutation'> & { _type: never };

/**
 * Resolve a function reference by its deployed path.
 *
 * Every SecureScan handler lives under the `securescan/` directory, so a deployed
 * query is `securescan/console:dashboard` - not `console:dashboard`. These
 * references were previously looked up one segment at a time, which silently
 * produced a *different, nonexistent* function path: the server answered
 * "Could not find public function for 'console:dashboard'", and because that is
 * neither a refusal code nor a network error the classifier reported it as a
 * generic unexpected failure on every view in the console.
 *
 * The module argument is walked segment by segment so `securescan/console`
 * resolves through the generated API's nested namespace, and the error keeps the
 * full path because that is the string an operator needs in order to fix it.
 */
function ref(api: ConvexApi, module: string, name: string): QueryRef {
  const segments = module.split('/');
  const owner = segments.reduce<unknown>((node, segment) => {
    if (node === null || typeof node !== 'object') return undefined;
    return (node as Record<string, unknown>)[segment];
  }, api) as Record<string, unknown> | undefined;
  const fn = owner?.[name];
  if (!fn) throw new Error(`SECURESCAN_UNAVAILABLE_REF:${module}.${name}`);
  return fn as unknown as QueryRef;
}

/* -------------------------------------------------------------------------
 * Read calls.
 *
 * One typed export per read model. The response types are declared locally
 * below to match the server shapes; a parity test pins them to the server.
 * ---------------------------------------------------------------------- */

export const getViewerIdentity = () =>
  call(
    async (client, api) => client.query(ref(api, 'securescan/console', 'viewer'), {}) as Promise<ViewerIdentityReadModel>,
  );

export const getDashboard = () =>
  call(async (client, api) => client.query(ref(api, 'securescan/console', 'dashboard'), {}) as Promise<DashboardReadModel>);

export const listFindings = (args: {
  limit?: number;
  state?: string;
  severity?: string;
  assessmentId?: string;
}) =>
  call(
    async (client, api) => client.query(ref(api, 'securescan/console', 'listFindings'), args) as Promise<FindingListReadModel>,
  );

export const getFindingDetail = (findingId: string) =>
  call(async (client, api) => client.query(ref(api, 'securescan/console', 'findingDetail'), { findingId }) as Promise<FindingDetailReadModel>);

export const getAssessmentDetail = (assessmentId: string) =>
  call(async (client, api) => client.query(ref(api, 'securescan/assessments', 'get'), { assessmentId }) as Promise<AssessmentDetailReadModel>);

export const listMyAssessments = () =>
  call(async (client, api) => client.query(ref(api, 'securescan/assessments', 'list'), {}) as Promise<AssessmentListReadModel>);

export const getReport = (assessmentId: string) =>
  call(async (client, api) => client.query(ref(api, 'securescan/console', 'report'), { assessmentId }) as Promise<ReportReadModel>);

export const getEvidence = (evidenceId: string) =>
  call(async (client, api) => client.query(ref(api, 'securescan/console', 'evidenceDetail'), { evidenceId }) as Promise<EvidenceReadModel>);

export const listMembers = () =>
  call(async (client, api) => client.query(ref(api, 'securescan/members', 'listMembers'), {}) as Promise<MemberReadModel[]>);

export const listAudit = (assessmentId: string, limit?: number) =>
  call(
    async (client, api) => client.query(ref(api, 'securescan/audit', 'list'), { assessmentId, ...(limit ? { limit } : {}) }) as Promise<AuditEntryReadModel[]>,
  );

export const verifyAudit = (assessmentId: string) =>
  call(
    async (client, api) => client.query(ref(api, 'securescan/audit', 'verify'), { assessmentId }) as Promise<AuditVerifyReadModel>,
  );

/* -------------------------------------------------------------------------
 * Mutations.
 * ---------------------------------------------------------------------- */

export interface StartAssessmentInput {
  name: string;
  targetName: string;
  targetKind: 'REPOSITORY' | 'DEPLOYED_APPLICATION' | 'API';
  repositoryUrl?: string;
  baseUrl?: string;
  allowlistedPaths: string[];
  maxRuntimeRequests: number;
  authorizationNote: string;
}

export type StartAssessmentResult =
  | { readonly ok: true; readonly assessmentId: string; readonly targetId: string; readonly ownerUserId: string; readonly state: string }
  | {
      readonly ok: false;
      readonly code: string;
      readonly reason: string;
      readonly problems: { field: string; message: string }[];
    };

export const startAssessment = (input: StartAssessmentInput) =>
  call(
    async (client, api) => client.mutation(ref(api, 'securescan/console', 'startAssessment'), input) as Promise<StartAssessmentResult>,
  );

/** Outcome of a lifecycle transition or a scoring write, per the server union. */
export type FindingWriteResult =
  | { readonly ok: true; readonly findingId: string; readonly state?: string; readonly severity?: string }
  | { readonly ok: false; readonly code: string; readonly reason: string };

export const transitionFinding = (findingId: string, to: string, reason: string) =>
  call(
    async (client, api) => client.mutation(ref(api, 'securescan/findings', 'transition'), { findingId, to, reason }) as Promise<FindingWriteResult>,
  );

export const scoreFinding = (args: ScoreFindingInput) =>
  call(async (client, api) => client.mutation(ref(api, 'securescan/findings', 'scoreRisk'), args) as Promise<FindingWriteResult>);

export const recordRemediation = (findingId: string, summary: string) =>
  call(
    async (client, api) => client.mutation(ref(api, 'securescan/findings', 'recordRemediation'), { findingId, summary }) as Promise<FindingWriteResult>,
  );

/**
 * Queues a retest. There is deliberately no `passed` argument.
 *
 * The console used to send a verdict it typed, and the server accepted it. The
 * verdict now belongs to the assessment engine: an analyst can ask for a retest,
 * and only a run's recorded checks can resolve one. See
 * `convex/securescan/findings.ts` `requestRetest` / `recordRetestResult`.
 */
export const requestRetest = (findingId: string, notes: string) =>
  call(
    async (client, api) => client.mutation(ref(api, 'securescan/findings', 'requestRetest'), { findingId, notes }) as Promise<FindingWriteResult>,
  );

export const setMemberRole = (args: { userId: string; role: Role; assessmentId: string; reason: string; revoke?: boolean }) =>
  call(async (client, api) => client.mutation(ref(api, 'securescan/members', 'setMemberRole'), args) as Promise<MemberWriteResult>);

export type MemberWriteResult =
  | { readonly ok: true; readonly userId: string; readonly role: Role; readonly action: 'granted' | 'changed' | 'revoked' }
  | { readonly ok: false; readonly code: string; readonly reason: string };

export interface ScoreFindingInput {
  findingId: string;
  exposure: string;
  privilegesRequired: string;
  userInteraction: string;
  dataClass: string;
  boundaryCrossed: boolean;
  confidentiality: string;
  integrity: string;
  availability: string;
  runtimeValidated: boolean;
  evidenceStrength: string;
  correlatedSources: number;
  justification: string;
}

/* -------------------------------------------------------------------------
 * Read-model types.
 *
 * These are declared here to mirror the handlers in `convex/securescan/`, and
 * are pinned to them by `tests/dom/securescan-server-parity.test.mts`, which
 * imports the actual server modules. The browser bundle must not import a
 * Convex server module, and the generated `api.d.ts` cannot be relied on until
 * codegen runs, so the mirror lives here â€” audited, not automatic.
 * ---------------------------------------------------------------------- */

/**
 * The caller's own session and SecureScan grant.
 *
 * `signedIn` is authoritative and separate from `role`: a signed-in caller with
 * no grant has `role === null` but `signedIn === true`, and the shell has to be
 * able to say that rather than claim the caller is anonymous.
 */
export interface ViewerIdentityReadModel {
  signedIn: boolean;
  userId: string | null;
  role: Role | null;
}

export interface DashboardReadModel {
  role: Role;
  userId: string;
  totals: {
    assessments: number;
    assessmentsByState: Record<string, number>;
    openFindings: number;
    closedFindings: number;
    findingsByState: Record<string, number>;
    findingsBySeverity: Record<string, number>;
    unscoredCandidates: number;
    runs: number;
    evidence: number;
    tests: number;
    members: number;
  };
  lastRun: {
    runId: string;
    assessmentId: string;
    state: string;
    finishedAt: number | null;
    counts: RunCounts;
    toolVersion: string;
  } | null;
  recentAssessments: AssessmentSummaryReadModel[];
  recentFindings: FindingSummaryReadModel[];
}

export interface AssessmentSummaryReadModel {
  assessmentId: string;
  name: string;
  state: string;
  ownerUserId: string;
  latestRunId: string | null;
  abortReason: string | null;
  updatedAt: number;
  createdAt: number;
}

export interface FindingSummaryReadModel {
  findingId: string;
  assessmentId: string;
  title: string;
  state: string;
  stateLabel: string;
  severity: Severity;
  severityLabel: string;
  confidence: Confidence;
  updatedAt: number;
}

export interface RunCounts {
  total: number;
  pass: number;
  fail: number;
  inconclusive: number;
  notTested: number;
  skippedOutOfScope: number;
  error?: number;
}

export type Severity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Confidence = 'LOW' | 'MEDIUM' | 'HIGH';

export interface FindingListReadModel {
  role: Role;
  total: number;
  findings: FindingRowReadModel[];
}

export interface FindingRowReadModel {
  findingId: string;
  assessmentId: string;
  title: string;
  state: string;
  stateLabel: string;
  severity: Severity;
  severityLabel: string;
  confidence: Confidence;
  component: string | null;
  node: string | null;
  boundary: string | null;
  control: string | null;
  category: string;
  evidenceCount: number;
  affectedEndpoints: string[];
  fingerprint: string;
  updatedAt: number;
}

export interface FindingDetailReadModel {
  role: Role;
  finding: FindingDetailRow;
  evidence: EvidenceSummaryReadModel[];
  tests: TestSummaryReadModel[];
  events: FindingEventReadModel[];
}

export interface FindingDetailRow {
  findingId: string;
  assessmentId: string;
  runId: string;
  title: string;
  category: string;
  component: string | null;
  node: string | null;
  boundary: string | null;
  control: string | null;
  severity: Severity;
  severityLabel: string;
  confidence: Confidence;
  state: string;
  stateLabel: string;
  description: string;
  rootCause: string;
  rootCauseId: string;
  businessImpact: string;
  risk: unknown;
  affectedEndpoints: string[];
  fingerprint: string;
  historicalStatus: string;
  remediationSummary: string | null;
  remediatedAt: number | null;
  lastRetestState: string | null;
  lastRetestedAt: number | null;
  regressionTestId: string | null;
  createdAt: number;
  updatedAt: number;
}

export interface EvidenceSummaryReadModel {
  evidenceId: string;
  testId: string | null;
  type: string;
  description: string;
  payload: string;
  sha256: string;
  producedBy: string;
  sourceLocation: string | null;
  targetEnvironment: string;
  collectedAt: number;
}

export interface TestSummaryReadModel {
  testId: string;
  module: string;
  category: string;
  component: string;
  control: string;
  target: string;
  expected: string;
  observed: string;
  status: string;
  confidence: Confidence;
  notes: string[];
}

export interface FindingEventReadModel {
  kind: string;
  fromState: string | null;
  toState: string | null;
  actorUserId: string;
  note: string;
  at: number;
}

export interface EvidenceReadModel {
  role: Role;
  evidence: EvidenceSummaryReadModel;
  test: {
    testId: string;
    module: string;
    target: string;
    expected: string;
    observed: string;
    status: string;
    confidence: Confidence;
  } | null;
  citedBy: {
    findingId: string;
    title: string;
    state: string;
    stateLabel: string;
    severity: Severity;
  }[];
}

export interface AssessmentListReadModel {
  role: Role;
  assessments: AssessmentSummaryReadModel[];
}

export interface AssessmentDetailReadModel {
  role: Role;
  assessment: {
    assessmentId: string;
    name: string;
    state: string;
    targetId: string;
    ownerUserId: string;
    latestRunId: string | null;
    abortReason: string | null;
    auditHeadHash: string;
    auditEntryCount: number;
    createdAt: number;
    updatedAt: number;
  };
  target: {
    targetId: string;
    name: string;
    kind: string;
    state: string;
    repositoryUrl: string | null;
    baseUrl: string | null;
    allowlistedPaths: string[];
    maxRuntimeRequests: number;
    createdAt: number;
    updatedAt: number;
  } | null;
  runs: {
    runId: string;
    state: string;
    startedAt: number;
    finishedAt: number | null;
    modulesRun: string[];
    counts: RunCounts;
    abortReason: string | null;
    targetRevision: string | null;
    toolVersion: string;
  }[];
  findings: FindingRowReadModel[];
  testCounts: {
    total: number;
    pass: number;
    fail: number;
    inconclusive: number;
    notTested: number;
  };
  findingCountsByState: Record<string, number>;
}

export interface ReportReadModel {
  role: Role;
  assessment: {
    assessmentId: string;
    name: string;
    state: string;
    ownerUserId: string;
    targetId: string;
    createdAt: number;
    updatedAt: number;
    abortReason: string | null;
  };
  hasRun: boolean;
  run: {
    runId: string;
    state: string;
    startedAt: number;
    finishedAt: number | null;
    modulesRun: string[];
    targetRevision: string | null;
    toolVersion: string;
    abortReason: string | null;
    runCount: number;
  } | null;
  coverage: {
    recorded: RunCounts | null;
    observedTests: number;
    notTestedTests: number;
    evidenceCount: number;
    notTested: {
      testId: string;
      module: string;
      control: string;
      target: string;
      expected: string;
      reason: string;
    }[];
  };
  severityMix: Record<string, number>;
  stateMix: Record<string, number>;
  unscoredCandidates: {
    findingId: string;
    title: string;
    state: string;
    stateLabel: string;
    confidence: Confidence;
    control: string | null;
    evidenceIds: string[];
  }[];
  outstanding: OutstandingFindingReadModel[];
  findings: ReportFindingReadModel[];
  integrity: {
    intact: boolean;
    problems: string[];
    entryCount: number;
    headHash: string;
  };
  basis: {
    evidenceRecords: number;
    testsObserved: number;
    testsNotTested: number;
    findingsScored: number;
    findingsUnscored: number;
  };
}

export interface OutstandingFindingReadModel {
  findingId: string;
  title: string;
  severity: Severity;
  severityLabel: string;
  state: string;
  stateLabel: string;
  confidence: Confidence;
  control: string | null;
  component: string | null;
  evidenceIds: string[];
  remediatedAt: number | null;
  lastRetestState: string | null;
  lastRetestedAt: number | null;
  regressionTestId: string | null;
}

export interface ReportFindingReadModel {
  findingId: string;
  title: string;
  severity: Severity;
  severityLabel: string;
  state: string;
  stateLabel: string;
  confidence: Confidence;
  category: string;
  component: string | null;
  boundary: string | null;
  control: string | null;
  description: string;
  rootCause: string;
  businessImpact: string;
  evidenceIds: string[];
  affectedEndpoints: string[];
  remediationSummary: string | null;
  remediatedAt: number | null;
  lastRetestState: string | null;
  lastRetestedAt: number | null;
}

export interface MemberReadModel {
  userId: string;
  role: Role;
  grantedByUserId: string | null;
  grantedAt: number;
}

export interface AuditEntryReadModel {
  seq: number;
  actorUserId: string;
  actorRole: Role;
  action: string;
  resourceType: string;
  resourceId: string;
  outcome: string;
  reasonCode: string;
  detail: string;
  sourceUserAgent: string;
  sourceIp: string;
  at: number;
  hash: string;
}

export interface AuditVerifyReadModel {
  assessmentId: string;
  intact: boolean;
  problems: string[];
  entryCount: number;
  headHash: string;
}