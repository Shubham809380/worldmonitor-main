/**
 * WM SecureScan — assessment orchestrator.
 *
 * This is the only place that runs modules. Its job is not to be clever; it is
 * to make the engine's promises structurally true:
 *
 *  1. **Authorization is a gate, not a check.** `authorize()` is consulted here
 *     before any module is dispatched, and a refusal aborts the run rather than
 *     downgrading it. A UI that forgets to call the gate still cannot start an
 *     unauthorized assessment.
 *  2. **Determinism.** The same snapshot + scope + clock yields byte-identical
 *     output. Nothing here reads `Date.now()`, iterates an unsorted map, or
 *     depends on module completion order for identifiers.
 *  3. **Nothing is silently dropped.** A module that throws is recorded as
 *     `FAILED` in the run and in the result's `notTested` list. A module that is
 *     skipped for lack of capability is recorded with the reason. A target that
 *     is not World Monitor is reported as such rather than scored as a wall of
 *     vacuous passes.
 *
 * The engine produces tests, evidence, controls and candidate findings here;
 * promotion to `VALIDATED` happens in `findings.ts` and is deliberately a
 * separate, auditable step that a human performs with the evidence in hand.
 */

import { detectArchitecture, absentNodes, type DetectedArchitecture } from './architecture';
import { discoverAttackSurface, type SurfaceDiscovery } from './attack-surface';
import { buildCandidateFindings } from './candidates';
import { buildCoverage, deduplicateFindings } from './findings';
import { BUILT_IN_MODULES, resolveModules } from './modules';
import { ScopeEnforcer, type AuthorizationDecision } from './scope';
import {
  RepoView,
  type ModuleContext,
  type ModuleOutput,
  type ProbeClient,
  type SecurityModule,
} from './repo';
import type {
  Assessment,
  AssessmentId,
  AssessmentResult,
  AssessmentRun,
  Evidence,
  ModuleProgress,
  SecurityControl,
  SecurityTestResult,
  TestRunId,
} from './types';

export const SECURESCAN_ENGINE_VERSION = '0.1.0';

/** What the caller supplies. Nothing here is read from global state. */
export interface AssessmentRequest {
  readonly assessment: Assessment;
  readonly snapshot: {
    readonly rootLabel: string;
    readonly revision: string | null;
    readonly files: ReadonlyMap<string, string>;
    readonly unreadable?: readonly { readonly path: string; readonly reason: string }[];
  };
  /** Only non-null when the scope authorizes active work. The enforcer still gates it. */
  readonly probe?: ProbeClient | null;
  readonly modules?: readonly SecurityModule[];
  readonly now: () => string;
  /** Injectable so a test can assert failure paths without a real network. */
  readonly makeProbe?: (enforcer: ScopeEnforcer) => ProbeClient | null;
}

export interface OrchestratorOutcome {
  readonly result: AssessmentResult | null;
  readonly authorization: AuthorizationDecision;
  /** Set when the run aborted before producing a result. */
  readonly abortReason: string | null;
}

/**
 * The minimum number of World Monitor components that must be present for the
 * assessment to be about World Monitor at all. Below this the run is refused
 * rather than reported, because "no findings" against a target the engine does
 * not recognise is a false negative with a professional-looking report.
 */
const MINIMUM_RECOGNISED_NODES = 3;

export async function runAssessment(request: AssessmentRequest): Promise<OrchestratorOutcome> {
  const { assessment } = request;
  const repo = new RepoView({
    rootLabel: request.snapshot.rootLabel,
    revision: request.snapshot.revision,
    files: request.snapshot.files,
    unreadable: request.snapshot.unreadable ?? [],
  });

  const enforcer = new ScopeEnforcer(assessment.scope, request.now);
  const authorization = enforcer.authorize();
  if (!authorization.allowed) {
    return { result: null, authorization, abortReason: authorization.reason };
  }

  const architecture = detectArchitecture(repo);
  if (architecture.presentNodeIds.size < MINIMUM_RECOGNISED_NODES) {
    // Name both what was found and what was looked for. An operator who
    // pointed the engine at the wrong directory needs to see which components
    // were recognised before they can work out what they actually handed over.
    const found = architecture.nodes.filter((node) => node.present).map((node) => node.id);
    return {
      result: null,
      authorization,
      abortReason:
        `The snapshot at ${request.snapshot.rootLabel} matched only ${architecture.presentNodeIds.size} recognised World Monitor components ` +
        `(minimum ${MINIMUM_RECOGNISED_NODES}). It is not a World Monitor target, so an assessment of it would report nothing meaningful. ` +
        `Recognised: ${found.length > 0 ? found.join(', ') : 'none'}. ` +
        'Components looked for: ' +
        absentNodes(architecture)
          .map((node) => node.id)
          .join(', ') +
        '.',
    };
  }

  const surface = discoverAttackSurface(repo, architecture);
  const available = request.modules ?? BUILT_IN_MODULES;
  const { resolved, unknown } = resolveModules(assessment.moduleNames, available);
  const notTested: { module: string; reason: string }[] = [];
  for (const name of unknown) {
    notTested.push({ module: name, reason: 'No module with this name is registered in this build.' });
  }

  const probe = request.probe ?? request.makeProbe?.(enforcer) ?? null;
  const runId = `RUN-${request.now().replace(/[^0-9]/g, '')}-${assessment.id}`;
  const startedAt = request.now();

  const progress: ModuleProgress[] = [];
  const tests: SecurityTestResult[] = [];
  const controls: SecurityControl[] = [];
  const evidence: Evidence[] = [];

  for (const module of resolved) {
    const moduleStartedAt = request.now();
    const granted = enforcer.resolveCapability(module.requires);

    if (module.requires !== 'NONE' && !enforcer.admits(module.requires)) {
      progress.push({
        module: module.name,
        status: 'SKIPPED',
        testsRun: 0,
        startedAt: null,
        finishedAt: null,
        error: null,
      });
      notTested.push({
        module: module.name,
        reason:
          `Requires ${module.requires} but the assessment's intensity (${assessment.scope.intensity}) grants ${enforcer.capability}. ` +
          'The module was not run, and no conclusion is drawn from its absence.',
      });
      continue;
    }

    const context: ModuleContext = {
      assessmentId: assessment.id,
      runId,
      repo,
      probe,
      now: request.now,
      moduleCapability: granted,
      architecture,
      surface,
      environment: assessment.scope.environment,
    };

    let output: ModuleOutput;
    try {
      output = await module.run(context);
    } catch (error) {
      // A module that throws is a defect in the module, not in the target.
      // Recording it keeps the failure visible instead of quietly shrinking
      // the assessment's apparent coverage.
      const message = error instanceof Error ? error.message : String(error);
      progress.push({
        module: module.name,
        status: 'FAILED',
        testsRun: 0,
        startedAt: moduleStartedAt,
        finishedAt: request.now(),
        error: message,
      });
      notTested.push({ module: module.name, reason: `The module threw during execution: ${message}` });
      continue;
    }

    tests.push(...output.tests);
    controls.push(...output.controls);
    evidence.push(...output.evidence);
    for (const note of output.coverageNotes) {
      notTested.push({ module: module.name, reason: `Coverage note for ${note.controlId}: ${note.note}` });
    }

    progress.push({
      module: module.name,
      status: 'COMPLETE',
      testsRun: output.tests.length,
      startedAt: moduleStartedAt,
      finishedAt: request.now(),
      error: null,
    });
  }

  // Components that are absent are reported with the reason. A reader must be
  // able to tell "checked and clean" from "not present, never checked".
  for (const node of absentNodes(architecture)) {
    notTested.push({ module: `architecture:${node.id}`, reason: node.reason });
  }
  for (const entry of repo.unreadable) {
    notTested.push({ module: 'snapshot', reason: `${entry.path} could not be read: ${entry.reason}` });
  }

  // A FAIL is a question, not a conclusion. Candidates are derived here from the
  // real failing tests, and stay CANDIDATE: promoting one to VALIDATED is a
  // human, audited step in `findings.ts`/`convex/securescan/findings.ts`, not
  // something a static observation may do on its own.
  const candidates = await buildCandidateFindings({
    tests,
    evidence,
    architecture,
    assessmentId: assessment.id,
    now: request.now,
  });
  for (const testId of candidates.unbackedTestIds) {
    notTested.push({
      module: 'candidate-derivation',
      reason:
        `Test ${testId} failed without attaching evidence, so no candidate finding could be built from it. ` +
        'A module defect is the likely cause; the failure is reported rather than dropped.',
    });
  }
  for (const testId of candidates.unattributedTestIds) {
    notTested.push({
      module: 'candidate-derivation',
      reason:
        `Test ${testId} failed but its control id does not resolve to a component detected in this snapshot, ` +
        'so it could not be attributed to an architecture node. Reporting rather than guessing an owner.',
    });
  }

  const now = request.now();
  const coverage = buildCoverage(controls, tests, now);
  const { findings } = deduplicateFindings(candidates.findings);

  const run: AssessmentRun = {
    id: runId,
    assessmentId: assessment.id,
    startedAt,
    finishedAt: now,
    progress,
    requestsIssued: enforcer.issued,
    errorCount: progress.filter((entry) => entry.status === 'FAILED').length,
    warningCount: tests.filter((test) => test.status === 'INCONCLUSIVE').length,
    durationMs: null,
  };

  const result: AssessmentResult = {
    assessment,
    run,
    architecture: {
      nodes: architecture.nodes,
      edges: architecture.edges,
      boundaries: architecture.boundaries,
    },
    surface: surface.entries,
    tests: sortById(tests, (test) => test.testId),
    controls: sortById(controls, (control) => control.id),
    findings,
    evidence: sortById(evidence, (item) => item.evidenceId),
    coverage,
    dependencies: [],
    regressionTests: [],
    remediations: [],
    retests: [],
    notTested: notTested.sort((a, b) => a.module.localeCompare(b.module) || a.reason.localeCompare(b.reason)),
    toolVersion: SECURESCAN_ENGINE_VERSION,
    targetRevision: request.snapshot.revision,
  };

  return { result, authorization, abortReason: null };
}

/** Stable ordering so a report diff does not show spurious changes. */
function sortById<T>(items: readonly T[], key: (item: T) => string): T[] {
  return [...items].sort((a, b) => key(a).localeCompare(key(b)));
}

export type { DetectedArchitecture, SurfaceDiscovery, AssessmentId, TestRunId };
