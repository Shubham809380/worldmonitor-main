// @vitest-environment node

/**
 * WM SecureScan — CVSS scoring.
 *
 * A scanner that reports a wrong severity is worse than one that reports none,
 * because the number gets quoted into a ticket and outlives the report. So the
 * arithmetic is pinned against the published CVSS v3.1 specification's worked
 * examples, and — just as important — the *refusal* paths are pinned: an
 * unjustified vector, a malformed vector, and a v4.0 vector without an external
 * score must all be rejected rather than defaulted.
 *
 * The v3.1 examples below are the ones from the FIRST specification appendix,
 * which is the only reason to trust them: they are the values the spec's own
 * worked example table produces.
 */

import { describe, test, expect } from 'vitest';
import {
  cvssRoundup,
  formatCvss31Vector,
  parseCvss31Vector,
  parseCvss40Vector,
  scoreCvss31,
  scoreDeclaredVector,
  severityForScore,
  unscoredAssessment,
} from '../securescan/cvss';

describe('CVSS v3.1 base scoring', () => {
  // (vector, expected base score) — the worked examples from the v3.1 spec.
  const cases: readonly (readonly [string, number])[] = [
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 10.0],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 7.5],
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 8.8],
    ['CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N', 3.7],
    ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1],
    ['CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H', 5.9],
  ];

  for (const [vector, expected] of cases) {
    test(`${vector} scores ${expected.toFixed(1)}`, () => {
      const metrics = parseCvss31Vector(vector);
      expect(metrics).not.toBeNull();
      const scored = scoreCvss31(metrics!);
      expect(scored.baseScore).toBeCloseTo(expected, 1);
    });
  }

  // The scope-changed case above is the one most implementations get wrong, so
  // it is worth writing the derivation out rather than trusting a fixture:
  //   ISS  = 1 - (1-0.22)(1-0.22)(1-0)   = 0.3916
  //   S:C  -> Impact = 7.52*(0.3916-0.029) - 3.25*(0.3916-0.02)^15 = 2.72675
  //   PR:H under S:C is 0.50 (NOT the 0.27 used when scope is unchanged), so
  //   Exploitability = 8.22*0.55*0.44*0.50*0.62 = 0.61666
  //   Base  = roundup(min(1.08*(2.72675+0.61666), 10)) = roundup(3.61088) = 3.7
  // Using the unchanged-scope PR weighting here yields 3.4, so this case really
  // does distinguish a correct scope-changed implementation from a plausible one.
  test('scope-changed weighting differs from scope-unchanged for the same privilege level', () => {
    const changed = scoreCvss31(parseCvss31Vector('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:N')!);
    const unchanged = scoreCvss31(parseCvss31Vector('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N')!);
    expect(changed.baseScore).toBeCloseTo(3.7, 1);
    expect(unchanged.baseScore).not.toBeCloseTo(changed.baseScore, 1);
  });

  test('a zero-impact vector scores 0.0 and is NONE, not LOW', () => {
    const metrics = parseCvss31Vector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N');
    expect(metrics).not.toBeNull();
    const scored = scoreCvss31(metrics!);
    expect(scored.baseScore).toBe(0);
    expect(severityForScore(scored.baseScore)).toBe('NONE');
  });

  test('reformatting a parsed vector round-trips', () => {
    const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    const metrics = parseCvss31Vector(vector);
    expect(metrics).not.toBeNull();
    expect(formatCvss31Vector(metrics!)).toBe(vector);
  });

  test('the roundup helper matches the specified one-decimal behaviour', () => {
    expect(cvssRoundup(4.02)).toBe(4.1);
    expect(cvssRoundup(4.0)).toBe(4.0);
    expect(cvssRoundup(0.0)).toBe(0.0);
  });
});

describe('CVSS v3.1 vector validation', () => {
  const invalid: readonly string[] = [
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H',
    'CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:Z',
    'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    '',
  ];

  for (const vector of invalid) {
    test(`rejects ${vector === '' ? '<empty>' : vector}`, () => {
      expect(parseCvss31Vector(vector)).toBeNull();
    });
  }

  test('rejects a v3.0 vector from being scored as v3.1', () => {
    expect(parseCvss31Vector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBeNull();
  });
});

describe('severity banding', () => {
  test('matches the v3.1 qualitative severity rating scale', () => {
    expect(severityForScore(0)).toBe('NONE');
    expect(severityForScore(0.1)).toBe('LOW');
    expect(severityForScore(3.9)).toBe('LOW');
    expect(severityForScore(4.0)).toBe('MEDIUM');
    expect(severityForScore(6.9)).toBe('MEDIUM');
    expect(severityForScore(7.0)).toBe('HIGH');
    expect(severityForScore(8.9)).toBe('HIGH');
    expect(severityForScore(9.0)).toBe('CRITICAL');
    expect(severityForScore(10.0)).toBe('CRITICAL');
  });
});

describe('scoreDeclaredVector', () => {
  const rationale = { AV: 'Reachable over the network without a local foothold.', C: 'Reads cached dashboard state.' };

  test('refuses a vector with no justification', () => {
    const outcome = scoreDeclaredVector({
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      metricRationale: {},
      confidence: 80,
    });
    expect(outcome.kind).toBe('rejected');
  });

  test('refuses a vector with a blank justification', () => {
    const outcome = scoreDeclaredVector({
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      metricRationale: { AV: '   ' },
      confidence: 80,
    });
    expect(outcome.kind).toBe('rejected');
    if (outcome.kind === 'rejected') expect(outcome.reason).toContain('AV');
  });

  test('scores a justified v3.1 vector', () => {
    const outcome = scoreDeclaredVector({
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      metricRationale: rationale,
      confidence: 80,
    });
    expect(outcome.kind).toBe('scored');
    if (outcome.kind !== 'scored') return;
    expect(outcome.assessment.baseScore).toBeCloseTo(9.8, 1);
    expect(outcome.assessment.severity).toBe('CRITICAL');
    expect(outcome.assessment.version).toBe('3.1');
    expect(outcome.assessment.metricRationale.AV).toBe(rationale.AV);
    expect(outcome.assessment.impact).not.toBeNull();
    expect(outcome.assessment.exploitability).not.toBeNull();
  });

  test('clamps a confidence value outside 0-100', () => {
    const outcome = scoreDeclaredVector({
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      metricRationale: rationale,
      confidence: 999,
    });
    expect(outcome.kind).toBe('scored');
    if (outcome.kind === 'scored') expect(outcome.assessment.confidence).toBe(100);
  });

  test('rejects a malformed vector instead of defaulting it to something low', () => {
    const outcome = scoreDeclaredVector({
      vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H',
      metricRationale: rationale,
      confidence: 50,
    });
    expect(outcome.kind).toBe('rejected');
    if (outcome.kind === 'rejected') expect(outcome.reason).toContain('validation');
  });

  test('rejects an unrecognised vector version', () => {
    const outcome = scoreDeclaredVector({
      vector: 'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P',
      metricRationale: rationale,
      confidence: 50,
    });
    expect(outcome.kind).toBe('rejected');
  });
});

describe('CVSS v4.0', () => {
  const V4 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H';

  test('accepts a well-formed v4.0 vector', () => {
    const parsed = parseCvss40Vector(V4);
    expect(parsed).not.toBeNull();
    expect(parsed?.isCompleteBase).toBe(true);
  });

  test('a well-formed vector with a missing base metric parses but is flagged incomplete', () => {
    // Deliberately not `null`: "syntactically invalid" and "well-formed but
    // not enough to score" are different diagnoses, and `scoreDeclaredVector`
    // reports them differently. Collapsing them to null would lose the reason.
    const parsed = parseCvss40Vector('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H');
    expect(parsed).not.toBeNull();
    expect(parsed?.isCompleteBase).toBe(false);
  });

  test('a syntactically invalid v4.0 vector is rejected outright', () => {
    expect(parseCvss40Vector('CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H')).toBeNull();
  });

  test('will not compute a v4.0 score, and says so', () => {
    const outcome = scoreDeclaredVector({
      vector: V4,
      metricRationale: { AV: 'Network reachable.' },
      confidence: 60,
    });
    expect(outcome.kind).toBe('rejected');
    if (outcome.kind !== 'rejected') return;
    expect(outcome.reason).toContain('MacroVector');
    // The refusal must be specific about what the operator can do about it.
    expect(outcome.reason).toContain('documented source');
  });

  test('records an externally computed v4.0 score with its provenance', () => {
    const outcome = scoreDeclaredVector({
      vector: V4,
      metricRationale: { AV: 'Network reachable.' },
      confidence: 60,
      externalV40: { score: 9.3, source: 'https://example.invalid/cvss-calculator' },
    });
    expect(outcome.kind).toBe('scored');
    if (outcome.kind !== 'scored') return;
    expect(outcome.assessment.version).toBe('4.0');
    expect(outcome.assessment.baseScore).toBe(9.3);
    expect(outcome.assessment.severity).toBe('CRITICAL');
  });

  test('rejects an out-of-range external v4.0 score', () => {
    const outcome = scoreDeclaredVector({
      vector: V4,
      metricRationale: { AV: 'Network reachable.' },
      confidence: 60,
      externalV40: { score: 12, source: 'calculator' },
    });
    expect(outcome.kind).toBe('rejected');
  });
});

describe('unscoredAssessment', () => {
  test('represents "not yet assessed" with nulls rather than zeroes', () => {
    const assessment = unscoredAssessment();
    expect(assessment.baseScore).toBeNull();
    expect(assessment.severity).toBeNull();
    expect(assessment.version).toBeNull();
    expect(assessment.vector).toBeNull();
    expect(assessment.confidence).toBe(0);
  });
});
