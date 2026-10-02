// @vitest-environment node
/**
 * Module-level behaviour for the two registered modules.
 *
 * These tests exist because both modules were shown to be *over-claiming* when
 * first run against the real World Monitor checkout, and the over-claims were
 * the kind that damage a security tool's credibility:
 *
 *  - CORS reported a credentialed data leak against `api/_cors.js` purely
 *    because one file contained both a public wildcard helper and a
 *    credentialed helper. They are separate responses; the finding was fiction.
 *  - CSP reported `object-src` missing from a policy declaring
 *    `default-src 'none'`, even though the absent directive inherits that
 *    default and objects are already blocked.
 *  - COOP/COEP were reported ABSENT when the deployment declares them in
 *    Report-Only mode — a materially different statement about the posture.
 *
 * Each regression below is written against the real file shapes so the fix
 * cannot be undone by a plausible refactor.
 */

import { describe, test, expect } from 'vitest';
import { runAssessment } from '../securescan/orchestrator';
import type { Assessment, AssessmentScope, SecurityTestResult } from '../securescan/types';

const FIXED_CLOCK = (): string => '2026-01-01T00:00:00.000Z';

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
    id: 'ASSESS-MODULES',
    name: 'Module fixture',
    state: 'RUNNING',
    scope: scope(),
    moduleNames: ['security-headers', 'cors'],
    createdBy: 'test',
    createdAt: '2026-01-01T00:00:00.000Z',
    startedAt: null,
    finishedAt: null,
    authorizationNote: 'Fixture target the test owns.',
    ...overrides,
  };
}

function vercelConfig(rules: { source: string; headers: { key: string; value: string }[] }[]): string {
  return JSON.stringify({ headers: rules }, null, 2);
}

const LEGACY_CORS = `const ALLOWED_ORIGIN_PATTERNS = [
  /^https:\\/\\/([a-z0-9-]+\\.)*worldmonitor\\.app$/,
];

export function getPublicCorsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
  };
}
`;

const GATEWAY_CORS = `const ALLOWED_ORIGIN_PATTERNS = [
  /^https:\\/\\/([a-z0-9-]+\\.)*worldmonitor\\.app$/,
];

export function withCors(req, res) {
  const origin = req.headers.get('origin') ?? '';
  const allowOrigin = ALLOWED_ORIGIN_PATTERNS.some((pattern) => pattern.test(origin)) ? origin : null;
  return {
    'Access-Control-Allow-Origin': allowOrigin ?? 'https://worldmonitor.app',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
  };
}
`;

/**
 * Enough of the World Monitor tree for the target-recognition gate to accept
 * the snapshot. Each test then overrides just the file it is about, so the
 * modules are exercised through the real orchestrator rather than in isolation.
 */
function recognisable(overrides: Map<string, string> = new Map()): Map<string, string> {
  return new Map<string, string>([
    ['index.html', '<!doctype html><html><head><script type="module" src="/src/main.ts"></script></head><body></body></html>'],
    ['src/main.ts', "import { api } from '@/services/api';\napi.boot();"],
    ['vercel.json', vercelConfig([{ source: '/', headers: [{ key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'" }] }])],
    ['server/gateway.ts', "export function createDomainGateway() {\n  return { handle: () => null };\n}\n"],
    ['server/cors.ts', GATEWAY_CORS],
    ['api/_cors.js', LEGACY_CORS],
    ['api/rss-proxy.js', "export default async function handler(req) {\n  return new Response('ok');\n}\n"],
    ['.env.example', 'WM_SESSION_SECRET=\nCLERK_PUBLISHABLE_KEY=\nPORT=3000\n'],
    ...overrides,
  ]);
}

async function run(files: Map<string, string>) {
  const outcome = await runAssessment({
    assessment: assessment(),
    snapshot: { rootLabel: 'fixture', revision: 'abc123', files: recognisable(files) },
    now: FIXED_CLOCK,
  });
  if (outcome.result === null) throw new Error(`refused: ${outcome.abortReason}`);
  return outcome.result;
}

function testById(tests: readonly SecurityTestResult[], id: string): SecurityTestResult {
  const found = tests.find((test) => test.testId === id);
  if (!found) throw new Error(`no test ${id}; got ${tests.map((t) => t.testId).join(', ')}`);
  return found;
}

describe('cors: wildcard and credentials are scored per response path', () => {
  // The real `api/_cors.js` shape: a credentialed reflecting helper and a
  // public wildcard helper, side by side in one module. This is the
  // recommended layout, and scoring it as a defect invents a data leak.
  const SEPARATE_HELPERS = `const ALLOWED_ORIGIN_PATTERNS = [
  /^https:\\/\\/(www\\.)?worldmonitor\\.app$/,
];

export function getCorsHeaders(req, methods = 'GET, OPTIONS') {
  const origin = req.headers.get('origin') || '';
  return {
    'Access-Control-Allow-Origin': origin || 'https://worldmonitor.app',
    'Access-Control-Allow-Credentials': 'true',
    'Vary': 'Origin',
  };
}

export function getPublicCorsHeaders(methods = 'GET, OPTIONS') {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': methods,
  };
}
`;

  test('a file holding both a public and a credentialed helper passes', async () => {
    const result = await run(new Map([['api/_cors.js', SEPARATE_HELPERS]]));
    const test = testById(result.tests, 'CORS-NO-WILDCARD-WITH-CREDENTIALS');
    expect(test.status).toBe('PASS');
    expect(test.observed).toContain('No single response path combines');
    // A pass here is a MEDIUM-confidence pass, because a response that spreads
    // a shared wildcard constant and adds credentials inline is not detected.
    // The report has to say so rather than imply a proof.
    expect(test.confidence).toBe('MEDIUM');
    expect(test.notes.join(' ')).toContain('Known gap');
  });

  test('one response emitting both the wildcard and credentials fails and names the function', async () => {
    const BAD = `export function getCorsHeaders(req) {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Credentials': 'true',
  };
}
`;
    const result = await run(new Map([['api/cors.js', BAD]]));
    const test = testById(result.tests, 'CORS-NO-WILDCARD-WITH-CREDENTIALS');
    expect(test.status).toBe('FAIL');
    expect(test.observed).toContain('getCorsHeaders');
    expect(test.evidenceIds.length).toBeGreaterThan(0);
  });

  test('a wildcard ACAO in a comment or string does not create a finding', async () => {
    const DECOY = `// 'Access-Control-Allow-Origin': '*' is wrong on credentialed responses.
/* 'Access-Control-Allow-Origin': '*' with credentials leaks data. */
const EXAMPLE = "'Access-Control-Allow-Origin': '*' + credentials = leak";

export function getCorsHeaders(req) {
  return {
    'Access-Control-Allow-Origin': req.headers.get('origin') || 'https://worldmonitor.app',
    'Access-Control-Allow-Credentials': 'true',
  };
}
`;
    const result = await run(new Map([['api/cors.js', DECOY]]));
    expect(testById(result.tests, 'CORS-NO-WILDCARD-WITH-CREDENTIALS').status).toBe('PASS');
  });
});

describe('security-headers: CSP fallback semantics', () => {
  test('object-src absent under default-src none is not reported missing', async () => {
    // `object-src` inherits `default-src`. Under `default-src 'none'` plugins
    // are already blocked, so calling the directive missing would be wrong.
    const result = await run(
      new Map([
        [
          'vercel.json',
          vercelConfig([
            {
              source: '/api/slack/oauth/callback',
              headers: [{ key: 'Content-Security-Policy', value: "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; script-src 'self'" }],
            },
          ]),
        ],
      ]),
    );
    const test = testById(result.tests, 'SECURITY-HEADERS-CSP-SURFACE-API-SLACK-OAUTH-CALLBACK');
    expect(test.observed).not.toContain('object-src');
    expect(test.observed).toContain('policy met its expectations');
    expect(test.status).toBe('PASS');
  });

  test('base-uri absent is a weakness because it has no fallback', async () => {
    const result = await run(
      new Map([
        [
          'vercel.json',
          vercelConfig([
            {
              source: '/api/slack/oauth/callback',
              headers: [{ key: 'Content-Security-Policy', value: "default-src 'none'; script-src 'self'; object-src 'none'" }],
            },
          ]),
        ],
      ]),
    );
    const test = testById(result.tests, 'SECURITY-HEADERS-CSP-SURFACE-API-SLACK-OAUTH-CALLBACK');
    expect(test.status).toBe('FAIL');
    expect(test.observed).toContain('absent base-uri, which has no fallback');
  });

  test('the sandboxed widget records its inline allowance as contained, not as a weakness', async () => {
    // The real `/wm-widget-sandbox.html` policy. It is genuinely weak on
    // base-uri, but the inline allowance is contained by the opaque origin, so
    // the report must not call the same fact both acceptable and a weakness.
    const result = await run(
      new Map([
        [
          'vercel.json',
          vercelConfig([
            {
              source: '/wm-widget-sandbox.html',
              headers: [
                { key: 'Content-Security-Policy', value: "default-src 'none'; sandbox allow-scripts; script-src 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'unsafe-inline'" },
              ],
            },
          ]),
        ],
      ]),
    );
    const test = testById(result.tests, 'SECURITY-HEADERS-CSP-SURFACE-WM-WIDGET-SANDBOX-HTML');
    expect(test.observed).toContain('contained by the opaque-origin sandbox');
    expect(test.notes.join(' ')).toContain('recorded as a fact, not as a weakness');
    for (const note of test.notes) {
      expect(note).not.toContain("Weakness recorded: script-src permits 'unsafe-inline'");
    }
    // base-uri really is missing, so this surface is still reported weak.
    expect(test.status).toBe('FAIL');
    expect(test.observed).toContain('absent base-uri');
  });
});

describe('security-headers: a missing CSP is an auditable FAIL', () => {
  // Regression: `csp-declared` was recorded as a FAIL with no evidence. The
  // recorder correctly refuses an unevidenced FAIL, which threw and cost the
  // entire module's output — a real deployment missing its CSP would have
  // reported *nothing at all* rather than reporting the gap.
  test('the absence FAIL carries evidence naming the rules that were read', async () => {
    const result = await run(new Map([['vercel.json', vercelConfig([{ source: '/', headers: [{ key: 'X-Content-Type-Options', value: 'nosniff' }] }])]]));
    const test = testById(result.tests, 'SECURITY-HEADERS-CSP-DECLARED');
    expect(test.status).toBe('FAIL');
    expect(test.evidenceIds.length).toBeGreaterThan(0);
    expect(test.observed).toContain('1 header rule(s) present');
  });

  test('an unevidenced FAIL never costs the rest of the module its output', async () => {
    const result = await run(new Map([['vercel.json', vercelConfig([{ source: '/', headers: [{ key: 'X-Content-Type-Options', value: 'nosniff' }] }])]]));
    const progress = result.run.progress.find((entry) => entry.module === 'security-headers');
    expect(progress?.status).toBe('COMPLETE');
    expect(progress?.error ?? null).toBeNull();
    // The simple-header checks must still have run.
    expect(result.tests.map((t) => t.testId)).toContain('SECURITY-HEADERS-X-CONTENT-TYPE-OPTIONS');
  });
});

describe('security-headers: Report-Only is distinguished from absent', () => {
  const APP_RULE = {
    source: '/((?!docs|embed).*)',
    headers: [
      { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'strict-dynamic' 'nonce-abc'; base-uri 'self'; object-src 'none'; frame-ancestors 'self'" },
    ],
  };

  test('COOP and COEP declared Report-Only are reported as declared but not enforced', async () => {
    const result = await run(
      new Map([
        [
          'vercel.json',
          vercelConfig([
            {
              ...APP_RULE,
              headers: [
                ...APP_RULE.headers,
                { key: 'Cross-Origin-Opener-Policy-Report-Only', value: 'same-origin; report-to="wm-coop-coep"' },
                { key: 'Cross-Origin-Embedder-Policy-Report-Only', value: 'require-corp; report-to="wm-coop-coep"' },
              ],
            },
          ]),
        ],
      ]),
    );

    for (const header of ['CROSS-ORIGIN-OPENER-POLICY', 'CROSS-ORIGIN-EMBEDDER-POLICY']) {
      const test = testById(result.tests, `SECURITY-HEADERS-${header}`);
      // Report-Only reports violations and blocks none, so this is a real gap,
      // and it must not be softened to INCONCLUSIVE the way an absent header is.
      expect(test.status).toBe('FAIL');
      expect(test.observed).toContain('report-only mode');
      expect(test.notes.join(' ')).toContain('blocks none');
    }
  });

  test('a header that is genuinely absent stays INCONCLUSIVE', async () => {
    const result = await run(
      new Map([
        ['vercel.json', vercelConfig([APP_RULE])],
      ]),
    );
    const test = testById(result.tests, 'SECURITY-HEADERS-CROSS-ORIGIN-OPENER-POLICY');
    expect(test.status).toBe('INCONCLUSIVE');
    expect(test.observed).toContain('No Cross-Origin-Opener-Policy header is declared');
  });

  test('an enforcing declaration wins over a report-only one for the same header', async () => {
    const result = await run(
      new Map([
        [
          'vercel.json',
          vercelConfig([
            {
              source: '/docs',
              headers: [{ key: 'Cross-Origin-Opener-Policy-Report-Only', value: 'same-origin' }],
            },
            {
              source: '/',
              headers: [{ key: 'Cross-Origin-Opener-Policy', value: 'same-origin' }],
            },
          ]),
        ],
      ]),
    );
    const test = testById(result.tests, 'SECURITY-HEADERS-CROSS-ORIGIN-OPENER-POLICY');
    expect(test.status).toBe('PASS');
  });
});
