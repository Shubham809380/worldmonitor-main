/**
 * WM SecureScan — CVSS scoring.
 *
 * Two rules govern this file.
 *
 * 1. **A score is computed or it is absent.** `baseScore` is `null` when no
 *    vector was declared, and `severity` is `null` when no score exists. There
 *    is no default severity, no "assume medium", no placeholder. A finding with
 *    `severity: null` renders as NOT SCORED in the console, which is a
 *    legitimate and useful state: it means the analyst has not established risk
 *    yet, which is different from risk being low.
 *
 * 2. **A vector needs a justification.** `metricRationale` records why each
 *    metric was chosen, keyed by metric name. A vector with an empty rationale
 *    is a guess expressed in vector notation.
 *
 * CVSS v3.1 base scoring is implemented in full from the specification
 * (including the `roundup` definition, which is not ordinary rounding and is
 * the usual source of off-by-one errors in reimplementations). CVSS v4.0
 * vectors are parsed and validated against the official metric grammar, but
 * scoring is not attempted: v4.0 scoring requires the published MacroVector
 * lookup table, and a hand-rolled approximation would produce a number that
 * looks authoritative and is not. When a v4.0 score is available from a
 * documented tool, it is recorded with its source.
 */

// ---------------------------------------------------------------------------
// v3.1
// ---------------------------------------------------------------------------

const V31_ATTACK_VECTOR: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const V31_ATTACK_COMPLEXITY: Record<string, number> = { L: 0.77, H: 0.44 };
const V31_PRIVILEGES_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const V31_PRIVILEGES_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
const V31_USER_INTERACTION: Record<string, number> = { N: 0.85, R: 0.62 };
const V31_CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };

export interface Cvss31Metrics {
  readonly AV: 'N' | 'A' | 'L' | 'P';
  readonly AC: 'L' | 'H';
  readonly PR: 'N' | 'L' | 'H';
  readonly UI: 'N' | 'R';
  readonly S: 'U' | 'C';
  readonly C: 'H' | 'L' | 'N';
  readonly I: 'H' | 'L' | 'N';
  readonly A: 'H' | 'L' | 'N';
}

const V31_METRIC_NAMES = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'] as const;

/**
 * The specification's `Roundup`, reproduced exactly.
 *
 * It is not `Math.ceil`. A value whose scaled form is an exact multiple of
 * 10000 is returned unchanged; otherwise it is incremented to the next
 * multiple. Plain ceiling pushes 4.02 to 5.0 and misclassifies a whole band of
 * scores, so the branch is load-bearing rather than defensive.
 */
export function cvssRoundup(input: number): number {
  const scaled = Math.round(input * 100000);
  if (scaled % 10000 === 0) return scaled / 100000;
  return (Math.floor(scaled / 10000) + 1) / 10;
}

export function parseCvss31Vector(vector: string): Cvss31Metrics | null {
  const trimmed = vector.trim();
  if (!trimmed.startsWith('CVSS:3.1/')) return null;
  const parts = trimmed.slice('CVSS:3.1/'.length).split('/');
  const seen = new Map<string, string>();
  for (const part of parts) {
    const separator = part.indexOf(':');
    if (separator <= 0) return null;
    const name = part.slice(0, separator);
    const value = part.slice(separator + 1);
    if (!V31_METRIC_NAMES.includes(name as (typeof V31_METRIC_NAMES)[number])) return null;
    if (seen.has(name)) return null;
    seen.set(name, value);
  }
  for (const name of V31_METRIC_NAMES) {
    if (!seen.has(name)) return null;
  }
  const get = (name: string): string => seen.get(name) ?? '';
  const metrics = {
    AV: get('AV'),
    AC: get('AC'),
    PR: get('PR'),
    UI: get('UI'),
    S: get('S'),
    C: get('C'),
    I: get('I'),
    A: get('A'),
  };
  if (!(metrics.AV in V31_ATTACK_VECTOR)) return null;
  if (!(metrics.AC in V31_ATTACK_COMPLEXITY)) return null;
  if (!(metrics.PR in V31_PRIVILEGES_UNCHANGED)) return null;
  if (!(metrics.UI in V31_USER_INTERACTION)) return null;
  if (metrics.S !== 'U' && metrics.S !== 'C') return null;
  for (const key of ['C', 'I', 'A'] as const) {
    if (!(metrics[key] in V31_CIA)) return null;
  }
  return metrics as unknown as Cvss31Metrics;
}

/** Reject non-canonical vectors so two spellings of one risk cannot coexist. */
export function formatCvss31Vector(metrics: Cvss31Metrics): string {
  return `CVSS:3.1/${V31_METRIC_NAMES.map((name) => `${name}:${metrics[name]}`).join('/')}`;
}

export interface Cvss31Result {
  readonly baseScore: number;
  readonly impactSubScore: number;
  readonly exploitabilitySubScore: number;
  readonly impact: number;
  readonly scopeUnchanged: boolean;
}

export function scoreCvss31(metrics: Cvss31Metrics): Cvss31Result {
  const scopeUnchanged = metrics.S === 'U';
  const confidentiality = V31_CIA[metrics.C] ?? 0;
  const integrity = V31_CIA[metrics.I] ?? 0;
  const availability = V31_CIA[metrics.A] ?? 0;

  const iss = 1 - (1 - confidentiality) * (1 - integrity) * (1 - availability);
  const impact = scopeUnchanged
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;

  const privileges = scopeUnchanged ? V31_PRIVILEGES_UNCHANGED : V31_PRIVILEGES_CHANGED;
  const exploitability =
    8.22 *
    (V31_ATTACK_VECTOR[metrics.AV] ?? 0) *
    (V31_ATTACK_COMPLEXITY[metrics.AC] ?? 0) *
    (privileges[metrics.PR] ?? 0) *
    (V31_USER_INTERACTION[metrics.UI] ?? 0);

  let baseScore: number;
  if (impact <= 0) {
    baseScore = 0;
  } else if (scopeUnchanged) {
    baseScore = cvssRoundup(Math.min(impact + exploitability, 10));
  } else {
    baseScore = cvssRoundup(Math.min(1.08 * (impact + exploitability), 10));
  }

  return {
    baseScore,
    impactSubScore: cvssRoundup(iss),
    exploitabilitySubScore: cvssRoundup(exploitability),
    impact,
    scopeUnchanged,
  };
}

// ---------------------------------------------------------------------------
// v4.0 — parse and validate only
// ---------------------------------------------------------------------------

/**
 * The official CVSS v4.0 base-metric grammar. Order is not significant to
 * validity; order is normalised on output so two equivalent vectors compare
 * equal as strings.
 */
const V40_BASE_METRICS: Readonly<Record<string, readonly string[]>> = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  AT: ['N', 'P'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'P', 'A'],
  VC: ['H', 'L', 'N'],
  VI: ['H', 'L', 'N'],
  VA: ['H', 'L', 'N'],
  SC: ['H', 'L', 'N'],
  SI: ['H', 'L', 'N'],
  SA: ['H', 'L', 'N'],
};

const V40_THREAT_METRICS: Readonly<Record<string, readonly string[]>> = {
  E: ['X', 'A', 'P', 'U'],
  CR: ['X', 'H', 'M', 'L'],
  IR: ['X', 'H', 'M', 'L'],
  AR: ['X', 'H', 'M', 'L'],
};

const V40_ENVIRONMENTAL_METRICS: Readonly<Record<string, readonly string[]>> = {
  MAV: ['X', 'N', 'A', 'L', 'P'],
  MAC: ['X', 'L', 'H'],
  MAT: ['X', 'N', 'P'],
  MPR: ['X', 'N', 'L', 'H'],
  MUI: ['X', 'N', 'P', 'A'],
  MVC: ['X', 'H', 'L', 'N'],
  MVI: ['X', 'H', 'L', 'N'],
  MVA: ['X', 'H', 'L', 'N'],
  MSC: ['X', 'H', 'L', 'N'],
  MSI: ['X', 'S', 'H', 'L', 'N'],
  MSA: ['X', 'S', 'H', 'L', 'N'],
  S: ['X', 'N', 'P'],
  AU: ['X', 'N', 'Y'],
  R: ['X', 'A', 'U', 'I'],
  V: ['X', 'D', 'C'],
  RE: ['X', 'L', 'M', 'H'],
  U: ['X', 'Clear', 'Green', 'Amber', 'Red'],
};

export interface Cvss40Vector {
  readonly metrics: Readonly<Record<string, string>>;
  readonly baseMetrics: Readonly<Record<string, string>>;
  /** `true` when every base metric is present and no `X` modifier applies. */
  readonly isCompleteBase: boolean;
  readonly normalized: string;
}

export function parseCvss40Vector(vector: string): Cvss40Vector | null {
  const trimmed = vector.trim();
  if (!trimmed.startsWith('CVSS:4.0/')) return null;
  const parts = trimmed.slice('CVSS:4.0/'.length).split('/');
  const metrics = new Map<string, string>();
  for (const part of parts) {
    const separator = part.indexOf(':');
    if (separator <= 0) return null;
    const name = part.slice(0, separator);
    const value = part.slice(separator + 1);
    if (metrics.has(name)) return null;
    const allowed =
      V40_BASE_METRICS[name] ?? V40_THREAT_METRICS[name] ?? V40_ENVIRONMENTAL_METRICS[name];
    if (!allowed || !allowed.includes(value)) return null;
    metrics.set(name, value);
  }

  const baseMetrics: Record<string, string> = {};
  let complete = true;
  for (const [name, allowed] of Object.entries(V40_BASE_METRICS)) {
    const value = metrics.get(name);
    if (value === undefined) {
      complete = false;
      continue;
    }
    // An `X` on a base metric means "not modified", which is a complete vector
    // in v4.0 — but only when the metric is actually stated.
    baseMetrics[name] = value;
    if (value === 'X') {
      if (!allowed.includes('X')) complete = false;
    }
  }
  if (Object.keys(baseMetrics).length !== Object.keys(V40_BASE_METRICS).length) complete = false;

  const normalized = `CVSS:4.0/${[...metrics.keys()].sort().map((k) => `${k}:${metrics.get(k)}`).join('/')}`;
  return { metrics: Object.fromEntries(metrics), baseMetrics, isCompleteBase: complete, normalized };
}

// ---------------------------------------------------------------------------
// Severity banding
// ---------------------------------------------------------------------------

export type CvssSeverity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export function severityForScore(score: number): CvssSeverity {
  if (score === 0) return 'NONE';
  if (score < 4) return 'LOW';
  if (score < 7) return 'MEDIUM';
  if (score < 9) return 'HIGH';
  return 'CRITICAL';
}

/**
 * An empty risk record. The single source of "not yet assessed".
 *
 * `baseScore: null` and `severity: null` are the honest representation of a
 * finding that has evidence but no analysed risk; a consumer that treats null
 * as zero would be making a decision the analyst never made, so the types make
 * that impossible to do by accident.
 */
export function unscoredAssessment(): import('./types').CvssAssessment {
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

export interface ScoreRequest {
  readonly vector: string;
  /** Required. A vector without a justification is not accepted. */
  readonly metricRationale: Readonly<Record<string, string>>;
  /** 0-100. Evidence strength. */
  readonly confidence: number;
  readonly environmentalContext?: string | null;
  /**
   * Externally computed v4.0 score plus where it came from. Required for any
   * v4.0 vector to carry a score, because this engine does not compute one.
   */
  readonly externalV40?: { readonly score: number; readonly source: string } | null;
}

export type ScoreOutcome =
  | { readonly kind: 'scored'; readonly assessment: import('./types').CvssAssessment }
  | { readonly kind: 'rejected'; readonly reason: string };

/**
 * Score a declared vector, or explain why it could not be scored.
 *
 * Rejecting (rather than defaulting) is the whole point: a malformed vector
 * must not silently become a low-severity finding, because "we could not parse
 * it" and "it is not very serious" look identical in a dashboard otherwise.
 */
export function scoreDeclaredVector(request: ScoreRequest): ScoreOutcome {
  const rationaleEntries = Object.entries(request.metricRationale);
  if (rationaleEntries.length === 0) {
    return {
      kind: 'rejected',
      reason: 'A vector was declared without a per-metric justification. WM SecureScan will not emit an unjustified score.',
    };
  }
  const missing = rationaleEntries.filter(([, reason]) => reason.trim() === '');
  if (missing.length > 0) {
    return {
      kind: 'rejected',
      reason: `Empty justification for metric(s): ${missing.map(([name]) => name).join(', ')}.`,
    };
  }

  if (request.vector.startsWith('CVSS:3.1/')) {
    const metrics = parseCvss31Vector(request.vector);
    if (!metrics) {
      return { kind: 'rejected', reason: 'CVSS v3.1 vector failed validation against the base metric grammar.' };
    }
    const scored = scoreCvss31(metrics);
    return {
      kind: 'scored',
      assessment: {
        version: '3.1',
        vector: formatCvss31Vector(metrics),
        baseScore: scored.baseScore,
        severity: severityForScore(scored.baseScore),
        impact: scored.impact.toFixed(4),
        exploitability: scored.exploitabilitySubScore.toFixed(1),
        metricRationale: { ...request.metricRationale },
        confidence: clampConfidence(request.confidence),
        environmentalContext: request.environmentalContext ?? null,
      },
    };
  }

  if (request.vector.startsWith('CVSS:4.0/')) {
    const parsed = parseCvss40Vector(request.vector);
    if (!parsed) {
      return { kind: 'rejected', reason: 'CVSS v4.0 vector failed validation against the v4.0 metric grammar.' };
    }
    if (!parsed.isCompleteBase) {
      return {
        kind: 'rejected',
        reason: 'CVSS v4.0 base metrics are incomplete or carry an undefined `X` modifier. A base score cannot be derived.',
      };
    }
    if (!request.externalV40) {
      return {
        kind: 'rejected',
        reason:
          'CVSS v4.0 scoring requires the published MacroVector lookup. WM SecureScan validates v4.0 vectors but does not compute a score from them; supply the score from a documented source to record one.',
      };
    }
    const score = request.externalV40.score;
    if (!Number.isFinite(score) || score < 0 || score > 10) {
      return { kind: 'rejected', reason: 'Supplied CVSS v4.0 score is outside the 0.0-10.0 range.' };
    }
    return {
      kind: 'scored',
      assessment: {
        version: '4.0',
        vector: parsed.normalized,
        baseScore: score,
        severity: severityForScore(score),
        impact: null,
        exploitability: null,
        metricRationale: {
          ...request.metricRationale,
          __scoreSource: `CVSS v4.0 base score computed externally (${request.externalV40.source}); validated, not computed, by WM SecureScan.`,
        },
        confidence: clampConfidence(request.confidence),
        environmentalContext: request.environmentalContext ?? null,
      },
    };
  }

  return { kind: 'rejected', reason: 'Vector is not a recognised CVSS version prefix (`CVSS:3.1/` or `CVSS:4.0/`).' };
}

function clampConfidence(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

/**
 * Suggest a metric baseline from the observed evidence — a *starting point* for
 * an analyst, not a decision.
 *
 * This deliberately returns `null` for the metrics it cannot infer. An analyst
 * who accepts the suggestion still has to justify it; the engine will not
 * manufacture a rationale.
 */
export function suggestVectorMetrics(observation: {
  readonly requiresUserInteraction: boolean;
  readonly privilegesRequired: 'NONE' | 'LOW' | 'HIGH';
  readonly scopeChanged: boolean;
  readonly affectsConfidentiality: 'NONE' | 'LOW' | 'HIGH';
  readonly affectsIntegrity: 'NONE' | 'LOW' | 'HIGH';
  readonly affectsAvailability: 'NONE' | 'LOW' | 'HIGH';
}): { readonly metrics: Record<string, string>; readonly rationale: Record<string, string> } {
  const metrics: Record<string, string> = {};
  const rationale: Record<string, string> = {};

  // Attack Vector and Attack Complexity are deliberately absent. Neither is
  // inferable from an internal observation: how an attacker reaches the
  // component, and what an exploitation race costs, are analyst judgements.
  // Guessing them is the single most common way a scanner inflates its own
  // numbers, so the suggestion is incomplete and `scoreDeclaredVector` will
  // reject it until the analyst fills them in and justifies them.
  const pr = observation.privilegesRequired;
  metrics['PR'] = pr === 'NONE' ? 'N' : pr === 'LOW' ? 'L' : 'H';
  rationale['PR'] = `Attacker requires ${pr.toLowerCase()} privileges to reach the affected component.`;

  metrics['UI'] = observation.requiresUserInteraction ? 'R' : 'N';
  rationale['UI'] = observation.requiresUserInteraction
    ? 'Exploitation requires a second party to act, for example by following an attacker-supplied link.'
    : 'Exploitation requires no interaction from any other party.';

  metrics['S'] = observation.scopeChanged ? 'C' : 'U';
  rationale['S'] = observation.scopeChanged
    ? 'Successful exploitation crosses a security authority boundary and reaches data the attacker did not already control.'
    : 'Impact is confined to resources the attacker already holds the authority to affect.';

  const cia = { NONE: 'N', LOW: 'L', HIGH: 'H' } as const;
  const ciaLabel = { C: 'confidentiality', I: 'integrity', A: 'availability' } as const;
  for (const [key, value] of [
    ['C', observation.affectsConfidentiality],
    ['I', observation.affectsIntegrity],
    ['A', observation.affectsAvailability],
  ] as const) {
    metrics[key] = cia[value];
    rationale[key] =
      value === 'NONE'
        ? `No observed impact to ${ciaLabel[key]}.`
        : `Observed impact to ${ciaLabel[key]} is ${value.toLowerCase()}.`;
  }

  return { metrics, rationale };
}
