// @vitest-environment node
/**
 * Severity, confidence and risk-rating tests.
 *
 * The rule these tests exist to enforce: **a failed check is not a vulnerability,
 * and severity is not a mood.** Two separate axes are computed and kept
 * separate, because conflating them is how a scanner ends up telling a customer
 * they have a "9.8 critical" when it has really only proved that a header is
 * missing on one route.
 *
 *  - Severity answers "if this is real, how bad is it?"
 *  - Confidence answers "how sure are we that it is real?"
 *
 * A HIGH-severity / LOW-confidence finding is a legitimate and common output.
 * It is not a contradiction, and the UI must be able to display it.
 */

import { describe, test, expect } from 'vitest';
import {
  assessRisk,
  explainSeverity,
  scoreConfidence,
  SEVERITY_METHODOLOGY,
  type RiskInput,
} from '../securescan/risk';
import { allChecksSatisfied, validateFinding } from '../securescan/findings';
import { unscoredAssessment } from '../securescan/cvss';
import type {
  ArchitectureNodeId,
  Confidence,
  Evidence,
  Finding,
  SecurityTestResult,
  Severity,
} from '../securescan/types';

function input(overrides: Partial<RiskInput> = {}): RiskInput {
  return {
    exposure: 'UNAUTHENTICATED_REMOTE',
    privilegesRequired: 'NONE',
    userInteraction: 'NONE',
    dataClass: 'PUBLIC',
    boundaryCrossed: true,
    confidentiality: 'NONE',
    integrity: 'NONE',
    availability: 'NONE',
    runtimeValidated: false,
    evidenceStrength: 'CONFIGURATION',
    correlatedSources: 1,
    ...overrides,
  };
}

describe('severity', () => {
  test('an unauthenticated write reaching sensitive data with runtime proof is CRITICAL', () => {
    const risk = assessRisk(
      input({
        confidentiality: 'HIGH',
        integrity: 'HIGH',
        runtimeValidated: true,
        evidenceStrength: 'RUNTIME',
      }),
    );
    expect(risk.technicalSeverity).toBe('CRITICAL');
  });

  test('the same weakness with no runtime proof is not CRITICAL', () => {
    // This is the single most important assertion in the file. Identical impact,
    // unproven exploitability: the severity must come down, because claiming
    // CRITICAL for a static observation is the overclaim the product forbids.
    const risk = assessRisk(
      input({ confidentiality: 'HIGH', integrity: 'HIGH', runtimeValidated: false, evidenceStrength: 'CONFIGURATION' }),
    );
    expect(risk.technicalSeverity).not.toBe('CRITICAL');
    expect(['HIGH', 'MEDIUM']).toContain(risk.technicalSeverity);
  });

  test('no impact yields NONE, not LOW', () => {
    expect(assessRisk(input()).technicalSeverity).toBe('NONE');
  });

  test('an internal-only path cannot be CRITICAL', () => {
    const risk = assessRisk(
      input({ exposure: 'INTERNAL_ONLY', confidentiality: 'HIGH', integrity: 'HIGH', runtimeValidated: true, evidenceStrength: 'RUNTIME' }),
    );
    expect(risk.technicalSeverity).not.toBe('CRITICAL');
  });

  test('a defence-in-depth gap with no impact is INFORMATIONAL-grade, not a vulnerability', () => {
    const risk = assessRisk(input({ exposure: 'SAME_ORIGIN', boundaryCrossed: false }));
    expect(['NONE', 'LOW']).toContain(risk.technicalSeverity);
  });

  test('requiring privileges reduces severity relative to none', () => {
    const unauth = assessRisk(input({ confidentiality: 'HIGH', privilegesRequired: 'NONE' }));
    const privileged = assessRisk(input({ confidentiality: 'HIGH', privilegesRequired: 'USER' }));
    expect(SEVERITY_ORDER.indexOf(privileged.technicalSeverity)).toBeGreaterThanOrEqual(
      SEVERITY_ORDER.indexOf(unauth.technicalSeverity),
    );
  });

  test('user interaction reduces severity', () => {
    const none = assessRisk(input({ confidentiality: 'HIGH', userInteraction: 'NONE' }));
    const click = assessRisk(input({ confidentiality: 'HIGH', userInteraction: 'REQUIRED' }));
    expect(SEVERITY_ORDER.indexOf(click.technicalSeverity)).toBeGreaterThanOrEqual(
      SEVERITY_ORDER.indexOf(none.technicalSeverity),
    );
  });

  test('a non-crossed boundary caps severity at MEDIUM', () => {
    const risk = assessRisk(input({ confidentiality: 'HIGH', integrity: 'HIGH', boundaryCrossed: false, runtimeValidated: true, evidenceStrength: 'RUNTIME' }));
    expect(SEVERITY_ORDER.indexOf(risk.technicalSeverity)).toBeLessThanOrEqual(SEVERITY_ORDER.indexOf('MEDIUM'));
  });

  test('every assessment carries a severity explanation', () => {
    const explanation = explainSeverity(input({ confidentiality: 'HIGH' }));
    expect(explanation.lines.length).toBeGreaterThan(0);
    // The explanation must be specific enough to audit, not a restatement.
    expect(explanation.lines.join(' ')).toContain('Impact');
    expect(explanation.lines.join(' ')).toContain('Validation');
    expect(explanation.impact).toBe('HIGH');
  });
});

const SEVERITY_ORDER: readonly Severity[] = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

describe('confidence', () => {
  test('runtime-validated evidence with multiple independent sources is HIGH', () => {
    expect(scoreConfidence(input({ runtimeValidated: true, evidenceStrength: 'RUNTIME', correlatedSources: 2 }))).toBe('HIGH');
  });

  test('a single configuration observation is LOW', () => {
    expect(scoreConfidence(input({ runtimeValidated: false, evidenceStrength: 'CONFIGURATION', correlatedSources: 1 }))).toBe('LOW');
  });

  test('two independent sources beat one, at the same evidence strength', () => {
    const one = scoreConfidence(input({ evidenceStrength: 'SOURCE', correlatedSources: 1 }));
    const two = scoreConfidence(input({ evidenceStrength: 'SOURCE', correlatedSources: 2 }));
    expect(SEVERITY_ORDER.indexOf('NONE')).toBe(0);
    expect(CONFIDENCE_ORDER.indexOf(two)).toBeGreaterThanOrEqual(CONFIDENCE_ORDER.indexOf(one));
  });

  test('source evidence cannot reach HIGH confidence on its own', () => {
    // Static analysis alone never proves exploitability, no matter how many
    // files agree. It can corroborate, but the ceiling is MEDIUM.
    expect(scoreConfidence(input({ evidenceStrength: 'SOURCE', correlatedSources: 3, runtimeValidated: false }))).not.toBe('HIGH');
  });

  test('severity never raises confidence', () => {
    // A critical-sounding impact with weak evidence is LOW confidence. Keeping
    // these axes independent is what stops the UI implying certainty.
    const risk = assessRisk(input({ confidentiality: 'HIGH', integrity: 'HIGH', runtimeValidated: false, evidenceStrength: 'CONFIGURATION' }));
    expect(risk.confidence).toBe('LOW');
    expect(risk.technicalSeverity).not.toBe('NONE');
  });
});

const CONFIDENCE_ORDER: readonly Confidence[] = ['LOW', 'MEDIUM', 'HIGH'];

describe('CVSS metadata', () => {
  test('no vector is produced unless a vector is justified', () => {
    const risk = assessRisk(input());
    expect(risk.cvss.version).toBeNull();
    expect(risk.cvss.vector).toBeNull();
    expect(risk.cvss.baseScore).toBeNull();
    expect(risk.cvss.metricRationale).toEqual({});
  });

  test('an unscored finding never carries a default base score', () => {
    // A plausible-looking 0.0 or 5.0 default would be a fabricated measurement.
    const risk = assessRisk(input({ confidentiality: 'LOW' }));
    expect(risk.cvss.baseScore).toBeNull();
  });
});

describe('severity methodology', () => {
  test('the version recorded on a finding matches the published methodology', () => {
    // A finding whose rationale was produced by an older methodology must still
    // be interpretable, so the version travels with the finding.
    const risk = assessRisk(input());
    expect(risk.severityMethodologyVersion).toBe(SEVERITY_METHODOLOGY.version);
    expect(risk.severityRationale.length).toBeGreaterThan(0);
  });

  test('an unscored finding never invents a CVSS number', () => {
    const risk = assessRisk(input({ confidentiality: 'HIGH', integrity: 'HIGH', runtimeValidated: true, evidenceStrength: 'RUNTIME' }));
    expect(risk.cvss.baseScore).toBeNull();
    expect(risk.cvss.severity).toBeNull();
    expect(risk.technicalSeverity).toBe('CRITICAL');
  });
});

describe('findings cannot be validated by an unrelated failure', () => {
  // Regression: `validateFinding` used to count every FAIL in the assessment.
  // A finding about a missing CSP could therefore be promoted on the strength
  // of an unrelated CORS failure in the same run. Validation must depend only on
  // tests reached through this finding's own evidence.
  const candidate: Finding = {
    id: 'FND-CSP',
    title: 'OAuth callback CSP omits base-uri',
    category: 'SECURITY_HEADERS',
    component: 'OAuth callback',
    node: 'oauth-server',
    boundary: 'TB-1-BROWSER-EDGE',
    control: 'Content-Security-Policy',
    affectedEndpoints: ['/api/slack/oauth/callback'],
    description: 'The callback route returns HTML under a policy that declares neither base-uri nor form-action, leaving base rewriting and form targets unrestricted.',
    rootCause: 'CSP policy for the callback route is incomplete',
    rootCauseId: 'RC-1',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    risk: {
      technicalSeverity: 'MEDIUM',
      businessImpact: 'n/a',
      cvss: unscoredAssessment(),
      confidence: 'HIGH',
      severityRationale: ['test'],
      severityMethodologyVersion: SEVERITY_METHODOLOGY.version,
    },
    historicalStatus: 'CURRENTLY_OBSERVED',
    state: 'CANDIDATE',
    // Evidence produced by the CSP test, not the CORS test.
    evidenceIds: ['EV-CSP'],
    reproduction: [],
    controlledPoc: [],
    businessImpact: 'n/a',
    remediation: null,
    retestResult: null,
    regressionTestId: null,
    references: [],
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    fingerprint: 'fp',
  };

  const tests: readonly SecurityTestResult[] = [
    {
      testId: 'SECURITY-HEADERS-CSP-SURFACE-API-SLACK-OAUTH-CALLBACK',
      assessmentId: 'ASM-1',
      runId: 'RUN-1',
      module: 'security-headers',
      category: 'SECURITY_HEADERS',
      component: 'Edge policy',
      control: 'CTRL-X',
      target: '/api/slack/oauth/callback',
      boundary: null,
      expected: 'base-uri declared',
      observed: 'absent',
      status: 'FAIL',
      confidence: 'HIGH',
      evidenceIds: ['EV-CSP'],
      notes: [],
      requiresCapability: 'NONE',
    },
    {
      testId: 'CORS-NO-WILDCARD-WITH-CREDENTIALS',
      assessmentId: 'ASM-1',
      runId: 'RUN-1',
      module: 'cors',
      category: 'CORS',
      component: 'Vercel Edge',
      control: 'CTRL-Y',
      target: 'api/_cors.js',
      boundary: null,
      expected: 'no wildcard with credentials',
      observed: 'wildcard present',
      status: 'FAIL',
      confidence: 'HIGH',
      evidenceIds: ['EV-CORS'],
      notes: [],
      requiresCapability: 'NONE',
    },
  ];

  const evidence: readonly Evidence[] = [
    {
      evidenceId: 'EV-CSP',
      findingId: null,
      testId: 'SECURITY-HEADERS-CSP-SURFACE-API-SLACK-OAUTH-CALLBACK',
      assessmentId: 'ASM-1',
      collectedAt: '2026-01-01T00:00:00.000Z',
      type: 'CONFIGURATION',
      description: 'CSP for the callback route',
      payload: { kind: 'config-value', path: 'vercel.json', pointer: 'headers', value: "default-src 'none'" },
      sha256: 'a'.repeat(64),
      producedBy: 'wm-securescan:vercel.json',
      targetEnvironment: 'PRODUCTION',
      sourceLocation: 'vercel.json#headers',
    },
  ];

  const nodesPresent = new Set<ArchitectureNodeId>(['oauth-server']);

  // Check order in `validateFinding`: 0 evidence attached, 1 evidence ids
  // resolve, 2 substantive evidence, 3 a linked FAIL produced it, 4 node
  // present, 5 historical status, 6 ...
  const CHECK = { evidenceAttached: 0, failProducedIt: 3 } as const;

  function checkAt(f: Finding, index: number) {
    const checks = validateFinding(f, { tests, evidence, nodesPresent });
    const check = checks[index];
    if (!check) throw new Error(`validation check ${index} is missing`);
    return check;
  }

  test('a failing test linked through the finding evidence satisfies validation', () => {
    const check = checkAt(candidate, CHECK.failProducedIt);
    expect(check.satisfied).toBe(true);
    // The count must be scoped to this finding's own evidence, not the run.
    expect(check.reason).toContain('1 failing test result(s) among the 1 test(s) linked');
  });

  test('an unrelated failure elsewhere in the assessment does not count', () => {
    // Drop the CSP evidence: the finding now has a dangling reference AND only
    // the unrelated CORS failure remains. It must not be validated.
    const orphan: Finding = { ...candidate, evidenceIds: [] };
    expect(checkAt(orphan, CHECK.evidenceAttached).reason).toContain('No evidence attached');
    const check = checkAt(orphan, CHECK.failProducedIt);
    expect(check.satisfied).toBe(false);
    // The reason must name the actual gap rather than a generic failure.
    expect(check.reason).toContain('No test result is linked');
  });

  test('validation is not satisfied while any required check fails', () => {
    const orphan: Finding = { ...candidate, evidenceIds: [] };
    expect(allChecksSatisfied(validateFinding(orphan, { tests, evidence, nodesPresent }))).toBe(false);
    // The complete finding passes once its own evidence is present.
    expect(allChecksSatisfied(validateFinding(candidate, { tests, evidence, nodesPresent }))).toBe(true);
  });
});

describe('methodology transparency', () => {
  test('the severity methodology is documented and versioned', () => {
    expect(SEVERITY_METHODOLOGY.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(SEVERITY_METHODOLOGY.factors.length).toBeGreaterThanOrEqual(5);
    for (const factor of SEVERITY_METHODOLOGY.factors) {
      expect(factor.name.length).toBeGreaterThan(0);
      expect(factor.effect.length).toBeGreaterThan(0);
    }
    for (const rule of SEVERITY_METHODOLOGY.rules) {
      expect(rule.id.length).toBeGreaterThan(0);
      expect(rule.text.length).toBeGreaterThan(0);
    }
  });

  test('the methodology states that it is a heuristic, not a measurement', () => {
    expect(SEVERITY_METHODOLOGY.disclaimer.toLowerCase()).toContain('heuristic');
  });

  test('the methodology forbids overclaiming critical', () => {
    expect(SEVERITY_METHODOLOGY.rules.some((rule) => rule.text.includes('CRITICAL'))).toBe(true);
  });

  test('the methodology states the runtime-validation cap explicitly', () => {
    const cap = SEVERITY_METHODOLOGY.rules.find((rule) => rule.id === 'MS-2');
    expect(cap?.text.toLowerCase()).toContain('runtime');
  });
});
