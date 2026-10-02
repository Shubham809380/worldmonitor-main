/**
 * WM SecureScan — module authoring helpers.
 *
 * Every security module answers the same shape of question — "is this control
 * doing its job, and what did you actually look at?" — so the boilerplate for
 * recording that is centralised here. A module that hand-rolls its own evidence
 * records drifts in shape, and a coverage view over drifting shapes is a
 * coverage view nobody trusts.
 *
 * The `TestRecorder` is also where the PASS/FAIL/INCONCLUSIVE discipline is
 * enforced mechanically:
 *
 *  - A `fail()` with no evidence is impossible — the recorder refuses.
 *  - A `pass()` requires a stated observation, so "PASS" always says what was
 *    seen, not just that nothing tripped.
 *  - Anything the module could not decide is `inconclusive()`, never `pass()`.
 */

import { buildEvidence, staticObservationConfidence, type EvidenceDraft, type ModuleContext } from '../repo';
import { controlIdFor, testIdFor } from '../ids';
import type { SurfaceDiscovery } from '../attack-surface';
import type {
  ArchitectureNodeId,
  Confidence,
  ControlStatus,
  Evidence,
  EvidenceId,
  FrameworkMapping,
  SecurityControl,
  SecurityTestResult,
  TestId,
  TestStatus,
  TrustBoundaryId,
} from '../types';

export class Recorder {
  private readonly tests: SecurityTestResult[] = [];
  private readonly evidence: Evidence[] = [];
  private readonly controls: SecurityControl[] = [];
  private readonly seenSlugs = new Set<string>();
  private evidenceIndex = new Map<string, Evidence>();

  constructor(
    private readonly context: ModuleContext,
    readonly module: string,
    readonly category: string,
    readonly boundary: TrustBoundaryId | null,
  ) {}

  get now(): string {
    return this.context.now();
  }

  get repo(): ModuleContext['repo'] {
    return this.context.repo;
  }

  get runId(): string {
    return this.context.runId;
  }

  get assessmentId(): string {
    return this.context.assessmentId;
  }

  private async record(draft: EvidenceDraft): Promise<EvidenceId> {
    const evidence = await buildEvidence(
      this.context.assessmentId,
      this.context.now(),
      this.context.environment,
      draft,
    );
    // The same observation collected twice in one run collapses to one record.
    const existing = this.evidenceIndex.get(evidence.sha256);
    if (existing) return existing.evidenceId;
    this.evidenceIndex.set(evidence.sha256, evidence);
    this.evidence.push(evidence);
    return evidence.evidenceId;
  }

  /**
   * Record one test result. `evidenceIds` must be non-empty for `FAIL`; the
   * check is here rather than in review because an evidence-free failure is
   * exactly the failure mode this platform exists to eliminate.
   */
  async test(input: {
    readonly slug: string;
    readonly component: string;
    readonly control: string;
    readonly node: ArchitectureNodeId;
    readonly boundary?: TrustBoundaryId | null;
    readonly target: string;
    readonly expected: string;
    readonly observed: string;
    readonly status: TestStatus;
    readonly confidence?: Confidence;
    readonly corroborations?: number;
    readonly notes?: readonly string[];
    readonly evidence?: readonly EvidenceDraft[];
  }): Promise<TestId> {
    const evidenceIds: EvidenceId[] = [];
    for (const draft of input.evidence ?? []) {
      evidenceIds.push(await this.record(draft));
    }
    if (input.status === 'FAIL' && evidenceIds.length === 0) {
      throw new Error(
        `Module ${this.module} tried to record FAIL for ${input.slug} with no evidence. A failure must be evidence-backed.`,
      );
    }
    const testId = testIdFor(this.module, input.slug);
    if (this.seenSlugs.has(input.slug)) {
      throw new Error(
        `Module ${this.module} recorded two tests with the slug "${input.slug}". Test ids must be unique within a module because they are what a retest refers to.`,
      );
    }
    this.seenSlugs.add(input.slug);
    this.tests.push({
      testId,
      assessmentId: this.context.assessmentId,
      runId: this.context.runId,
      module: this.module,
      category: this.category,
      component: input.component,
      // Stored as the control *id*, not the control name, so `buildCoverage`
      // can join a test to its control without a second lookup table.
      control: controlIdFor(input.node, input.control),
      target: input.target,
      boundary: input.boundary ?? this.boundary,
      expected: input.expected,
      observed: input.observed,
      status: input.status,
      confidence: input.confidence ?? staticObservationConfidence(input.corroborations ?? 1),
      evidenceIds,
      notes: input.notes ?? [],
      requiresCapability: this.context.moduleCapability,
    });
    return testId;
  }

  /** Record a control's status, attaching the evidence that determined it. */
  async control(input: {
    readonly control: string;
    readonly node: ArchitectureNodeId;
    readonly label: string;
    readonly boundary?: TrustBoundaryId | null;
    readonly status: ControlStatus;
    readonly rationale: string;
    readonly evidence?: readonly EvidenceDraft[];
    readonly mappings?: readonly FrameworkMapping[];
  }): Promise<string> {
    const evidenceIds: EvidenceId[] = [];
    for (const draft of input.evidence ?? []) {
      evidenceIds.push(await this.record(draft));
    }
    const id = controlIdFor(input.node, input.control);
    this.controls.push({
      id,
      label: input.label,
      node: input.node,
      boundary: input.boundary ?? this.boundary,
      status: input.status,
      rationale: input.rationale,
      evidenceIds,
      mappings: input.mappings ?? [],
      lastTestedAt: this.context.now(),
    });
    return id;
  }

  output(): { tests: SecurityTestResult[]; evidence: Evidence[]; controls: SecurityControl[] } {
    return { tests: this.tests, evidence: this.evidence, controls: this.controls };
  }

  get testCount(): number {
    return this.tests.length;
  }
}

export function srcEvidence(
  path: string,
  startLine: number,
  endLine: number,
  text: string,
  description: string,
): EvidenceDraft {
  return {
    type: 'SOURCE_EXTRACTION',
    description,
    payload: { kind: 'source-lines', path, startLine, endLine, text },
    producedBy: `wm-securescan:${path}`,
    sourceLocation: `${path}:${startLine}`,
  };
}

export function configEvidence(
  path: string,
  pointer: string,
  value: string,
  description: string,
): EvidenceDraft {
  return {
    type: 'CONFIGURATION',
    description,
    payload: { kind: 'config-value', path, pointer, value },
    producedBy: `wm-securescan:${path}`,
    sourceLocation: pointer === '' ? path : `${path}#${pointer}`,
  };
}

export function contractEvidence(
  protoFile: string,
  message: string,
  expectation: string,
  observed: string,
  description: string,
): EvidenceDraft {
  return {
    type: 'CONTRACT_DECLARATION',
    description,
    payload: { kind: 'contract', protoFile, message, expectation, observed },
    producedBy: `wm-securescan:${protoFile}`,
    sourceLocation: protoFile,
  };
}

export function calcEvidence(
  formula: string,
  inputs: Readonly<Record<string, string>>,
  result: string,
  description: string,
): EvidenceDraft {
  return {
    type: 'CALCULATION',
    description,
    payload: { kind: 'calculation', formula, inputs, result },
    producedBy: 'wm-securescan:calculation',
  };
}

export function hashEvidence(
  subject: string,
  digest: string,
  description: string,
): EvidenceDraft {
  return {
    type: 'ARTIFACT_HASH',
    description,
    payload: { kind: 'hash', algorithm: 'SHA-256', subject, digest },
    producedBy: 'wm-securescan:hash',
    sourceLocation: subject,
  };
}

export function surfaceEvidence(
  discovery: SurfaceDiscovery,
  description: string,
  predicate: (location: string) => boolean = () => true,
): EvidenceDraft | null {
  const matched = discovery.entries
    .filter((item) => predicate(item.location))
    .map((item) => ({ id: item.id, location: item.location, type: item.type }));
  if (matched.length === 0) return null;
  return {
    type: 'ATTACK_SURFACE',
    description,
    payload: { kind: 'surface-list', entries: matched.slice(0, 200) },
    producedBy: 'wm-securescan:attack-surface',
  };
}

/** OWASP ASVS 4.0.3 reference for a verification requirement, by id. */
export function asvs(reference: string): FrameworkMapping {
  return { framework: 'OWASP_ASVS', version: '4.0.3', versionDetail: 'OWASP ASVS 4.0.3', reference, basis: 'ANALYST_ASSIGNED' };
}

export function asvsV5(reference: string): FrameworkMapping {
  return { framework: 'OWASP_ASVS_5', version: '5.0.0', versionDetail: 'OWASP ASVS 5.0.0 (draft)', reference, basis: 'ANALYST_ASSIGNED' };
}

export function apiTop10(reference: string): FrameworkMapping {
  return {
    framework: 'OWASP_API_SECURITY_TOP_10',
    version: '2023',
    versionDetail: 'OWASP API Security Top 10 2023',
    reference,
    basis: 'ANALYST_ASSIGNED',
  };
}

export function nistSsdf(reference: string): FrameworkMapping {
  return {
    framework: 'NIST_SSDF',
    version: '1.1',
    versionDetail: 'NIST SP 800-218 SSDF 1.1',
    reference,
    basis: 'ANALYST_ASSIGNED',
  };
}

export function cvssMapping(reference: string): FrameworkMapping {
  return { framework: 'CVSS', version: '3.1', versionDetail: 'CVSS v3.1 (base) / v4.0 (vector)', reference, basis: 'ANALYST_ASSIGNED' };
}

/** Concise, sortable rendering of a control for the coverage table. */
export function describeStatus(status: ControlStatus): string {
  switch (status) {
    case 'PRESENT':
      return 'PRESENT';
    case 'WEAK':
      return 'WEAK';
    case 'ABSENT':
      return 'ABSENT';
    default:
      return 'NOT_APPLICABLE';
  }
}
