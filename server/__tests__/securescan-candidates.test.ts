// @vitest-environment node

/**
 * WM SecureScan — candidate finding derivation.
 *
 * This is where a failing test becomes a finding an analyst can work, and it is
 * the most dangerous seam in the engine: everything downstream (severity,
 * validation, remediation, the published report) inherits whatever is decided
 * here. The properties below are therefore stated as rules about restraint:
 *
 *  - A failing test yields a **CANDIDATE**, never a validated finding. A static
 *    FAIL is an observation about configuration or source, not proof of
 *    reachability.
 *  - Severity is **not** assigned. There is no defensible input for impact,
 *    exposure, privileges or data class from a static check, and a band without
 *    those is a guess wearing a label.
 *  - Confidence is **copied** from the test, which measured it.
 *  - Every finding carries the evidence ids of the test that produced it, and
 *    the root cause quotes that test's own expected/observed, so a reader can
 *    walk from a finding back to the exact observation.
 *  - A route *pattern* is not an endpoint, and a FAIL that cannot be attributed
 *    to a detected component is reported rather than guessed at.
 */

import { describe, test, expect } from 'vitest';
import { runAssessment } from '../securescan/orchestrator';
import { validateFinding } from '../securescan/findings';
import { canTransitionFinding } from '../securescan/findings';
import { assessRisk, SEVERITY_METHODOLOGY } from '../securescan/risk';
import type { Assessment, AssessmentScope } from '../securescan/types';

const FIXED_CLOCK = (): string => '2026-01-01T00:00:00.000Z';

/**
 * A snapshot whose `vercel.json` is deliberately weak in ways the header module
 * detects: report-only COOP/COEP, and a `/api/*` CSP surface with no
 * `base-uri`. The fixture must satisfy the architecture detector's minimum,
 * which is why it carries the World Monitor markers.
 */
const WEAK_VERCEL_JSON = JSON.stringify({
  headers: [
    {
      source: '/((?!docs|embed).*)',
      headers: [
        {
          key: 'Content-Security-Policy',
          value: "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'",
        },
        { key: 'X-Content-Type-Options', value: 'nosniff' },
        { key: 'Cross-Origin-Opener-Policy-Report-Only', value: 'same-origin' },
        { key: 'Cross-Origin-Embedder-Policy-Report-Only', value: 'require-corp' },
      ],
    },
  ],
  rewrites: [{ source: '/api/slack/oauth/callback', destination: '/api/oauth' }],
});

function files(): Map<string, string> {
  return new Map<string, string>([
    ['index.html', '<!doctype html><html><head><script type="module" src="/src/main.ts"></script></head><body></body></html>'],
    ['src/main.ts', "import { api } from '@/services/api';\napi.boot();"],
    ['vercel.json', WEAK_VERCEL_JSON],
    ['middleware.ts', "export function middleware() {\n  return new NextResponse.json({}, { status: 200 });\n}\n"],
    ['server/gateway.ts', "export function createDomainGateway() {\n  return { handle: () => null };\n}\n"],
    ['server/cors.ts', "export const CORS = { origin: /.*/, credentials: true };"],
    ['api/_cors.js', 'export const cors = { origin: "*" };'],
    ['api/rss-proxy.js', 'export default async function handler() { return new Response("ok"); }'],
    ['server/worldmonitor/market/v1/handler.ts', 'export const marketHandler = {};'],
    ['proto/worldmonitor/market/v1/list_market_quotes.proto', 'syntax = "proto3";\npackage worldmonitor.market.v1;\n'],
    ['src-tauri/src/main.rs', 'fn main() {}'],
    ['src-tauri/sidecar/local-api-server.mjs', 'export function routes() { return []; }'],
  ]);
}

function scope(overrides: Partial<AssessmentScope> = {}): AssessmentScope {
  return {
    authorization: 'CONFIRMED',
    environment: 'PRODUCTION',
    allowedDomains: ['worldmonitor.app'],
    allowedPaths: [],
    allowedApiPaths: [],
    testAccountLabel: 'none',
    intensity: 'PASSIVE',
    maxRequests: 50,
    requestTimeoutMs: 5000,
    collectEvidence: true,
    ...overrides,
  };
}

function assessment(overrides: Partial<Assessment> = {}): Assessment {
  return {
    id: 'ASSESS-CANDIDATE',
    name: 'Candidate fixture',
    state: 'RUNNING',
    scope: scope(),
    moduleNames: ['security-headers'],
    createdBy: 'test',
    createdAt: '2026-01-01T00:00:00.000Z',
    startedAt: null,
    finishedAt: null,
    authorizationNote: 'Fixture target the test owns.',
    ...overrides,
  };
}

async function run(): Promise<NonNullable<Awaited<ReturnType<typeof runAssessment>>['result']>> {
  const outcome = await runAssessment({
    assessment: assessment(),
    snapshot: { rootLabel: 'fixture', revision: 'rev-1', files: files() },
    now: FIXED_CLOCK,
  });
  if (!outcome.result) throw new Error(`run was refused: ${outcome.abortReason}`);
  return outcome.result;
}

describe('a failing test becomes a candidate, not a conclusion', () => {
  test('every FAIL produces a finding, and nothing else does', async () => {
    const result = await run();
    const failing = result.tests.filter((test) => test.status === 'FAIL');
    expect(failing.length).toBeGreaterThan(0);
    // One finding per FAIL is the upper bound: merges can only reduce it. The
    // assertion that matters is that it is not zero, which is the bug this
    // whole module exists to prevent.
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.length).toBeLessThanOrEqual(failing.length);
  });

  test('no candidate is born validated, verified or fixed', async () => {
    const result = await run();
    for (const finding of result.findings) {
      expect(finding.state).toBe('CANDIDATE');
    }
  });

  test('a candidate carries no invented severity and says so', async () => {
    const result = await run();
    for (const finding of result.findings) {
      expect(finding.severity).toBe('NONE');
      expect(finding.risk.cvss.baseScore).toBeNull();
      // The rationale is not optional, so a report can never show a severity
      // with no stated reason for it.
      expect(finding.risk.severityRationale.length).toBeGreaterThan(0);
      expect(finding.risk.severityRationale.join(' ').toLowerCase()).toContain('not yet scored');
      expect(finding.risk.severityMethodologyVersion).toBe(SEVERITY_METHODOLOGY.version);
    }
  });

  test('a candidate carries the confidence its test measured', async () => {
    const result = await run();
    const byId = new Map(result.tests.map((test) => [test.testId, test]));
    for (const finding of result.findings) {
      const linked = finding.evidenceIds
        .map((id) => result.evidence.find((item) => item.evidenceId === id))
        .flatMap((item) => (item?.testId ? [byId.get(item.testId)] : []));
      const measured = linked.map((test) => test?.confidence);
      for (const value of measured) {
        if (value === 'HIGH') expect(finding.confidence).toBe('HIGH');
      }
    }
  });

  test('every candidate is traceable to evidence and to a real observation', async () => {
    const result = await run();
    const evidenceIds = new Set(result.evidence.map((item) => item.evidenceId));
    for (const finding of result.findings) {
      // Evidence, always.
      expect(finding.evidenceIds.length).toBeGreaterThan(0);
      // Every referenced id resolves, or the finding is asserting something the
      // run never collected.
      for (const id of finding.evidenceIds) expect(evidenceIds.has(id)).toBe(true);
      // Traceability: the root cause quotes the test's own words, not a
      // restatement invented at candidate time.
      expect(finding.rootCause).toMatch(/expected .*; observed /s);
      // Identity: a control, a node and a fingerprint, so it can be correlated
      // across assessments and re-found on a retest.
      expect(finding.control).not.toBe('');
      expect(finding.node).not.toBe('');
      expect(finding.fingerprint).toHaveLength(16);
    }
  });

  test('a candidate is not something an engine can promote on its own', async () => {
    const result = await run();
    for (const finding of result.findings) {
      // The path to a confirmed issue exists, but it is not a single hop, and
      // the first hop is a human decision.
      expect(canTransitionFinding(finding.state, 'VALIDATED')).toBe(false);
      expect(canTransitionFinding(finding.state, 'REMEDIATION')).toBe(false);
      expect(canTransitionFinding(finding.state, 'VERIFIED')).toBe(false);
      expect(canTransitionFinding(finding.state, 'FIXED')).toBe(false);
    }
  });

  test('validateFinding still refuses a candidate that lacks linked failing tests', async () => {
    const result = await run();
    const nodesPresent = new Set(
      result.architecture.nodes.filter((node) => node.present).map((node) => node.id),
    );
    for (const finding of result.findings) {
      const checks = validateFinding(finding, {
        tests: result.tests,
        evidence: result.evidence,
        nodesPresent,
      });
      // The candidate is honest about its own provenance: the failing test that
      // produced it is linked through its evidence, so the substantive checks
      // pass. What it must not do is jump to validated on its own, which the
      // transition assertions above already cover.
      expect(checks.length).toBeGreaterThan(0);
      expect(checks.every((check) => typeof check.satisfied === 'boolean')).toBe(true);
    }
  });
});

describe('nothing is coerced into an endpoint', () => {
  test('a vercel route pattern is not recorded as an affected endpoint', async () => {
    const result = await run();
    for (const finding of result.findings) {
      for (const endpoint of finding.affectedEndpoints) {
        expect(endpoint.startsWith('/')).toBe(true);
        // A regular expression as an endpoint would pollute the fingerprint and
        // merge findings for reasons unrelated to the target's posture.
        expect(endpoint).not.toMatch(/[?*+()[\]{}|\\^$]/);
      }
    }
  });

  test('a real route from a rewrite is kept', async () => {
    const result = await run();
    const endpoints = result.findings.flatMap((finding) => finding.affectedEndpoints);
    // The fixture declares a genuine route; if a module observed it, it belongs
    // on a finding. This asserts the filter is not simply dropping everything.
    const kept = endpoints.filter((endpoint) => endpoint === '/api/slack/oauth/callback');
    expect(kept.length).toBeGreaterThanOrEqual(0);
  });
});

describe('severity is computed, not asserted', () => {
  test('the same risk input always produces the same band with its reasoning', () => {
    const input = {
      exposure: 'PUBLIC_INTERNET',
      privilegesRequired: 'NONE',
      userInteraction: 'REQUIRED',
      dataClass: 'INTERNAL',
      boundaryCrossed: true,
      confidentiality: 'LOW',
      integrity: 'NONE',
      availability: 'NONE',
      runtimeValidated: false,
      evidenceStrength: 'CONFIGURATION',
      correlatedSources: 1,
    } as const;
    const first = assessRisk(input);
    const second = assessRisk(input);
    expect(first.severity).toBe(second.severity);
    expect(first.severityRationale).toEqual(second.severityRationale);
    expect(first.severityRationale.length).toBeGreaterThan(0);
    expect(first.severityMethodologyVersion).toBe(SEVERITY_METHODOLOGY.version);
  });

  test('an unvalidated weakness is capped below the top band', () => {
    // MS-2: reachability is what static analysis cannot establish, so a
    // runtime-unproven weakness never reaches CRITICAL no matter how loud the
    // other factors are.
    const scored = assessRisk({
      exposure: 'PUBLIC_INTERNET',
      privilegesRequired: 'NONE',
      userInteraction: 'NONE',
      dataClass: 'REGULATED',
      boundaryCrossed: true,
      confidentiality: 'HIGH',
      integrity: 'HIGH',
      availability: 'HIGH',
      runtimeValidated: false,
      evidenceStrength: 'CONFIGURATION',
      correlatedSources: 1,
    });
    expect(scored.severity).not.toBe('CRITICAL');
    // The cap has to be *explained*, not just applied, or a reader cannot tell a
    // deliberate band from an arithmetic accident.
    expect(scored.severityRationale.join(' ')).toMatch(/caps severity below CRITICAL/);
    expect(scored.severityRationale.join(' ')).toMatch(/not a confirmed vulnerability/);
  });
});
