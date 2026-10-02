/**
 * WM SecureScan risk engine: severity, confidence, and the explanation for both.
 *
 * The design rule is that **severity and confidence are independent axes** and
 * are computed by separate functions that cannot see each other's inputs beyond
 * what is explicitly passed. A HIGH-severity / LOW-confidence finding is a
 * normal, expected output; it is the honest description of "this would be bad,
 * and we have not shown it is reachable".
 *
 * Why this is not CVSS:
 *
 *  - CVSS produces a number. A number on a report reads as a measurement, and
 *    this engine is frequently reasoning from a static observation. Publishing
 *    "9.8" for a missing header on one route would be a fabricated measurement.
 *  - So severity here is a **banded, explainable** judgement with the reasoning
 *    attached, and CVSS metadata is only populated when a real vector has been
 *    scored through `cvss.ts`. `baseScore` stays `null` otherwise, and the UI
 *    must render that as "not scored" rather than as zero.
 *
 * The methodology below is exported so the report generator can print it, and so
 * a reviewer can see exactly why a band was chosen. An unexplainable severity is
 * indistinguishable from a made-up one.
 */

import type { Confidence, CvssAssessment, RiskAssessment, Severity } from './types';

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/** How far an attacker must reach the affected code to exercise it. */
export type Exposure = 'PUBLIC_INTERNET' | 'UNAUTHENTICATED_REMOTE' | 'AUTHENTICATED_REMOTE' | 'SAME_ORIGIN' | 'INTERNAL_ONLY' | 'BUILD_TIME';

export type PrivilegeLevel = 'NONE' | 'USER' | 'PRIVILEGED';

export type InteractionRequirement = 'NONE' | 'REQUIRED';

export type DataClass = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'REGULATED';

export type ImpactLevel = 'NONE' | 'LOW' | 'HIGH';

/**
 * Where the evidence came from. Ordered by strength: runtime observation beats
 * a configuration read, which beats a source-level inference.
 */
export type EvidenceStrength = 'INFERENCE' | 'SOURCE' | 'CONFIGURATION' | 'RUNTIME';

export interface RiskInput {
  readonly exposure: Exposure;
  readonly privilegesRequired: PrivilegeLevel;
  readonly userInteraction: InteractionRequirement;
  readonly dataClass: DataClass;
  /** Does exploitation cross a trust boundary, or stay inside one component? */
  readonly boundaryCrossed: boolean;
  readonly confidentiality: ImpactLevel;
  readonly integrity: ImpactLevel;
  readonly availability: ImpactLevel;
  /** True only when a runtime test actually demonstrated the behaviour. */
  readonly runtimeValidated: boolean;
  readonly evidenceStrength: EvidenceStrength;
  /** Number of independent sources agreeing. Used for confidence only. */
  readonly correlatedSources: number;
}

// ---------------------------------------------------------------------------
// Published methodology
// ---------------------------------------------------------------------------

export interface MethodologyFactor {
  readonly name: string;
  readonly effect: string;
}

export interface MethodologyRule {
  readonly id: string;
  readonly text: string;
}

/**
 * Printed verbatim into generated reports. Versioned so a stored finding can be
 * interpreted against the rules that produced its band.
 */
export const SEVERITY_METHODOLOGY = {
  version: '1.0.0',
  name: 'WM SecureScan evidence-banded severity',
  disclaimer:
    'Severity is a heuristic classification, not a measurement of application security. ' +
    'It expresses the assessed impact of a weakness if that weakness is real, given the ' +
    'evidence available. It is not a CVSS score, and two assessments by different analysts ' +
    'of the same code may reasonably differ. Confidence is reported separately and is the ' +
    'field that indicates how strongly the finding is evidenced.',
  factors: [
    { name: 'Impact', effect: 'Confidentiality, integrity and availability consequences of the weakness, each banded NONE/LOW/HIGH.' },
    { name: 'Exposure', effect: 'How far an attacker must reach the code. PUBLIC_INTERNET outranks INTERNAL_ONLY and BUILD_TIME.' },
    { name: 'Privileges required', effect: 'NONE is worse than USER, which is worse than PRIVILEGED. A weakness an attacker already owns is not a boundary crossing.' },
    { name: 'User interaction', effect: 'REQUIRED interaction raises the bar to exploitation and lowers the band by one step.' },
    { name: 'Trust boundary', effect: 'Exploitation that stays within one component cannot outrank MEDIUM, however severe the impact would be if reached.' },
    { name: 'Validation state', effect: 'A weakness demonstrated by a runtime test may outrank one inferred statically. This is the difference between a proven and a suspected issue.' },
    { name: 'Data class', effect: 'REGULATED data raises the band; PUBLIC data lowers it. Applies to impact, not to exploitability.' },
  ] as readonly MethodologyFactor[],
  rules: [
    { id: 'MS-1', text: 'CRITICAL is reserved for an unauthenticated remote weakness with HIGH impact on at least two of CIA, crossing a trust boundary, and demonstrated by runtime validation. No other combination reaches CRITICAL.' },
    { id: 'MS-2', text: 'A weakness that has not been runtime-validated is capped below the top band, because reachability is the part static analysis cannot establish.' },
    { id: 'MS-3', text: 'A weakness that does not cross a trust boundary is capped at MEDIUM.' },
    { id: 'MS-4', text: 'A weakness with no confidentiality, integrity or availability impact is NONE, not LOW. Low impact is not a vulnerability.' },
    { id: 'MS-5', text: 'Severity is never raised by the number of places the same root cause appears. Repetition is reported as scope, not as higher severity.' },
    { id: 'MS-6', text: 'Confidence is computed independently of severity and can never be raised by it.' },
  ] as readonly MethodologyRule[],
} as const;

// ---------------------------------------------------------------------------
// Ordinals
// ---------------------------------------------------------------------------

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  NONE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

const CONFIDENCE_RANK: Readonly<Record<Confidence, number>> = { LOW: 0, MEDIUM: 1, HIGH: 2 };

const EXPOSURE_RANK: Readonly<Record<Exposure, number>> = {
  PUBLIC_INTERNET: 5,
  UNAUTHENTICATED_REMOTE: 4,
  AUTHENTICATED_REMOTE: 3,
  SAME_ORIGIN: 2,
  INTERNAL_ONLY: 1,
  BUILD_TIME: 0,
};

const PRIVILEGE_RANK: Readonly<Record<PrivilegeLevel, number>> = { NONE: 2, USER: 1, PRIVILEGED: 0 };

const DATA_CLASS_RANK: Readonly<Record<DataClass, number>> = {
  PUBLIC: 0,
  INTERNAL: 1,
  CONFIDENTIAL: 2,
  REGULATED: 3,
};

const EVIDENCE_RANK: Readonly<Record<EvidenceStrength, number>> = {
  INFERENCE: 0,
  SOURCE: 1,
  CONFIGURATION: 2,
  RUNTIME: 3,
};

function highestImpact(inputs: readonly ImpactLevel[]): ImpactLevel {
  return inputs.reduce<ImpactLevel>((worst, level) => (IMPACT_RANK[level] > IMPACT_RANK[worst] ? level : worst), 'NONE');
}

const IMPACT_RANK: Readonly<Record<ImpactLevel, number>> = { NONE: 0, LOW: 1, HIGH: 2 };

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

export interface SeverityExplanation {
  readonly severity: Severity;
  readonly impact: ImpactLevel;
  readonly lines: readonly string[];
}

/**
 * Banded severity with the reasoning kept alongside it.
 *
 * The base band comes from impact, then reachability adjusts it, then hard caps
 * are applied. The caps are the important part: they exist so that no
 * combination of loud-sounding factors can produce a top-band severity for a
 * weakness that has not been shown to be reachable.
 */
export function explainSeverity(input: RiskInput): SeverityExplanation {
  const impact = highestImpact([input.confidentiality, input.integrity, input.availability]);
  const lines: string[] = [];

  if (impact === 'NONE') {
    lines.push('Impact: none. No confidentiality, integrity or availability consequence is in scope, so this is not a vulnerability.');
    return { severity: 'NONE', impact, lines };
  }

  // Base band from impact alone.
  let band: Severity = impact === 'HIGH' ? 'HIGH' : 'LOW';
  lines.push(`Impact: ${impact} (confidentiality=${input.confidentiality}, integrity=${input.integrity}, availability=${input.availability}). Base band ${band}.`);

  // Reachability adjustments.
  const exposure = EXPOSURE_RANK[input.exposure];
  if (input.exposure === 'UNAUTHENTICATED_REMOTE' || input.exposure === 'PUBLIC_INTERNET') {
    band = promote(band, 1);
    lines.push(`Exposure: ${input.exposure}. Unauthenticated reach raises the band by one step.`);
  } else if (input.exposure === 'INTERNAL_ONLY' || input.exposure === 'BUILD_TIME') {
    band = demote(band, 1);
    lines.push(`Exposure: ${input.exposure}. Not reachable by a remote attacker; the band is lowered.`);
  } else {
    lines.push(`Exposure: ${input.exposure}. No band change.`);
  }

  if (input.privilegesRequired !== 'NONE') {
    // The gap encodes the distance an attacker must already be past the
    // boundary: PRIVILEGED is the furthest, so it is demoted hardest.
    const steps = PRIVILEGE_RANK[input.privilegesRequired] === 0 ? 2 : 1;
    band = demote(band, steps);
    lines.push(`Privileges: ${input.privilegesRequired} required. An attacker who already holds these gains nothing new, so the band is lowered.`);
  } else {
    lines.push('Privileges: none required.');
  }

  if (input.userInteraction === 'REQUIRED') {
    band = demote(band, 1);
    lines.push('User interaction: required. The victim must act, so the band is lowered.');
  } else {
    lines.push('User interaction: none required.');
  }

  if (DATA_CLASS_RANK[input.dataClass] >= DATA_CLASS_RANK.CONFIDENTIAL) {
    band = promote(band, 1);
    lines.push(`Data class: ${input.dataClass}. Sensitive data is in scope, so the band is raised.`);
  } else {
    lines.push(`Data class: ${input.dataClass}. No band change.`);
  }

  // Hard caps. These override every adjustment above.
  if (!input.boundaryCrossed) {
    band = cap(band, 'MEDIUM');
    lines.push('Trust boundary: not crossed. The weakness stays within one component, which caps severity at MEDIUM regardless of impact.');
  } else {
    lines.push('Trust boundary: crossed.');
  }

  if (!input.runtimeValidated) {
    // The single most important cap. Reachability is exactly what a static
    // observation cannot establish, so an unvalidated weakness never reaches
    // CRITICAL. This is what stops a missing header on one route from being
    // reported as a critical vulnerability.
    band = cap(band, 'HIGH');
    lines.push('Validation: static or configuration evidence only. Reachability is unproven, which caps severity below CRITICAL. Reported as a potential weakness, not a confirmed vulnerability.');
  } else {
    lines.push('Validation: demonstrated by a runtime test.');
  }

  if (impact === 'HIGH' && countHighImpacts(input) < 2) {
    band = cap(band, 'HIGH');
    lines.push('Impact breadth: only one of CIA is HIGH, so the band is capped at HIGH.');
  }

  if (exposure === EXPOSURE_RANK.BUILD_TIME) {
    band = cap(band, 'LOW');
  }

  return { severity: band, impact, lines };
}

function countHighImpacts(input: RiskInput): number {
  return [input.confidentiality, input.integrity, input.availability].filter((level) => level === 'HIGH').length;
}

function promote(severity: Severity, steps: number): Severity {
  const order: readonly Severity[] = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  return order[Math.min(order.length - 1, SEVERITY_RANK[severity] + steps)] as Severity;
}

function demote(severity: Severity, steps: number): Severity {
  const order: readonly Severity[] = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  return order[Math.max(0, SEVERITY_RANK[severity] - steps)] as Severity;
}

function cap(severity: Severity, ceiling: Severity): Severity {
  return SEVERITY_RANK[severity] > SEVERITY_RANK[ceiling] ? ceiling : severity;
}

// ---------------------------------------------------------------------------
// Confidence
// ---------------------------------------------------------------------------

/**
 * Confidence in *existence*, not in impact.
 *
 * Kept deliberately blind to severity: a finding can be severe and still
 * weakly evidenced, and letting the severity number leak in here is how a
 * console ends up presenting a suspicion as a certainty.
 */
export function scoreConfidence(input: RiskInput): Confidence {
  const evidence = EVIDENCE_RANK[input.evidenceStrength];
  const sources = Math.max(1, input.correlatedSources);

  if (evidence >= EVIDENCE_RANK.RUNTIME && input.runtimeValidated) {
    return sources >= 2 ? 'HIGH' : 'MEDIUM';
  }
  if (evidence >= EVIDENCE_RANK.CONFIGURATION) {
    return sources >= 2 ? 'MEDIUM' : 'LOW';
  }
  if (evidence >= EVIDENCE_RANK.SOURCE) {
    // Static analysis corroborates but never proves reachability, so the ceiling
    // is MEDIUM however many files agree.
    return sources >= 3 ? 'MEDIUM' : 'LOW';
  }
  return 'LOW';
}

// ---------------------------------------------------------------------------
// Combined assessment
// ---------------------------------------------------------------------------

function unscoredCvss(): CvssAssessment {
  return {
    version: null,
    vector: null,
    baseScore: null,
    severity: null,
    impact: null,
    exploitability: null,
    metricRationale: {},
    confidence: 0,
    environmentalContext: null,
  };
}

export function assessRisk(input: RiskInput): RiskAssessment {
  const explanation = explainSeverity(input);
  return {
    technicalSeverity: explanation.severity,
    businessImpact: businessImpactFor(explanation.impact, input.dataClass),
    cvss: unscoredCvss(),
    confidence: scoreConfidence(input),
    severityRationale: explanation.lines,
    severityMethodologyVersion: SEVERITY_METHODOLOGY.version,
  };
}

function businessImpactFor(impact: ImpactLevel, dataClass: DataClass): string {
  if (impact === 'NONE') {
    return 'No confidentiality, integrity or availability consequence was identified for this observation.';
  }
  const data =
    dataClass === 'REGULATED'
      ? 'regulated data'
      : dataClass === 'CONFIDENTIAL'
        ? 'confidential data'
        : dataClass === 'INTERNAL'
          ? 'internal data'
          : 'public data';
  if (impact === 'HIGH') {
    return `If exploitable, this would affect the ${data} handled by the affected component in a way an external party could observe.`;
  }
  return `If exploitable, the effect on the ${data} handled by the affected component would be limited.`;
}

export { SEVERITY_RANK, CONFIDENCE_RANK };
