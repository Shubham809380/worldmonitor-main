// @vitest-environment node

/**
 * WM SecureScan — engine orchestration.
 *
 * The orchestrator is the only place modules run, so the properties that matter
 * most are properties of the orchestrator, not of any single module:
 *
 *  - **Determinism.** The same snapshot and the same clock must produce
 *    byte-identical output, because a retest that cannot be compared to the
 *    original proves nothing. This is asserted by deep-equality across two runs.
 *  - **Fail-closed authorization.** An unconfirmed assessment must produce no
 *    result at all — not a partial one.
 *  - **Refusal to assess the wrong target.** A snapshot that is not World
 *    Monitor must be refused rather than reported as clean.
 *  - **Nothing disappears.** A module that throws, a module whose name is
 *    unknown, and a component that is absent must all appear in `notTested`
 *    with a reason.
 *
 * The fixture snapshot below is a *synthetic* World Monitor-shaped repository:
 * small enough to reason about, carrying the real files the architecture
 * detector keys on. It is not a copy of the real tree, and the header and CORS
 * policies in it are written to match the real ones where the behaviour matters.
 */

import { describe, test, expect } from 'vitest';
import { runAssessment } from '../securescan/orchestrator';
import { buildCoverage } from '../securescan/findings';
import { RepoView, type ModuleContext, type ModuleOutput, type SecurityModule } from '../securescan/repo';
import { Recorder } from '../securescan/modules/_helpers';
import type { Assessment, AssessmentScope } from '../securescan/types';

const FIXED_CLOCK = (): string => '2026-01-01T00:00:00.000Z';

const VERCEL_JSON = JSON.stringify(
  {
    headers: [
      {
        source: '/((?!docs|embed|embed\\.html|wm-widget-sandbox\\.html).*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value:
              "default-src 'self'; script-src 'self' 'strict-dynamic' 'nonce-wm-static-bootstrap' 'sha256-abc='; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'",
          },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
          { key: 'Permissions-Policy', value: 'geolocation=(), microphone=()' },
          { key: 'Cross-Origin-Opener-Policy-Report-Only', value: 'same-origin' },
        ],
      },
      {
        source: '/embed',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors *; frame-src 'none'; form-action 'none'",
          },
        ],
      },
      {
        source: '/api/slack/oauth/callback',
        headers: [
          { key: 'Content-Security-Policy', value: "default-src 'none'; script-src 'unsafe-inline'" },
        ],
      },
    ],
  },
  null,
  2,
);

const LEGACY_CORS = `const ALLOWED_ORIGIN_PATTERNS = [
  /^https:\\/\\/([a-z0-9-]+\\.)*worldmonitor\\.app$/,
  /^https:\\/\\/localhost:\\d+$/,
];

export function getPublicCorsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
  };
}

export function applyCors(req, res) {
  const origin = req.headers.get('origin') ?? '';
  const allowOrigin = ALLOWED_ORIGIN_PATTERNS.some((p) => p.test(origin)) ? origin : null;
  res.setHeader('Access-Control-Allow-Origin', allowOrigin ?? '*');
  res.setHeader('Vary', 'Origin');
}
`;

const GATEWAY_CORS = `const ALLOWED_ORIGIN_PATTERNS = [
  /^https:\\/\\/([a-z0-9-]+\\.)*worldmonitor\\.app$/,
];

export function buildCorsHeaders(origin, isProduction) {
  const allowOrigin = ALLOWED_ORIGIN_PATTERNS.some((p) => p.test(origin)) ? origin : null;
  return {
    'Access-Control-Allow-Origin': allowOrigin ?? 'null',
    'Access-Control-Allow-Credentials': 'true',
    Vary: 'Origin',
  };
}
`;

/**
 * Small, World-Monitor-shaped snapshot. Paths match the real tree so the
 * architecture detector and attack-surface discovery exercise their real
 * markers.
 */
function worldMonitorFixture(): Map<string, string> {
  return new Map<string, string>([
    ['index.html', '<!doctype html><html><head><script type="module" src="/src/main.ts"></script></head><body></body></html>'],
    ['src/main.ts', "import { api } from '@/services/api';\napi.boot();"],
    ['vercel.json', VERCEL_JSON],
    ['middleware.ts', "export function middleware() {\n  return new NextResponse.json({}, { status: 200 });\n}\n"],
    ['server/gateway.ts', "export function createDomainGateway() {\n  return { handle: () => null };\n}\n"],
    ['server/cors.ts', GATEWAY_CORS],
    ['api/_cors.js', LEGACY_CORS],
    ['api/rss-proxy.js', "export default async function handler(req) {\n  return new Response('ok');\n}\n"],
    ['server/worldmonitor/market/v1/handler.ts', 'export const marketHandler: MarketServiceHandler = {};'],
    ['proto/worldmonitor/market/v1/list_market_quotes.proto', 'syntax = "proto3";\npackage worldmonitor.market.v1;\n'],
    ['src-tauri/src/main.rs', '#[tauri::command]\nfn read_state() {}\n'],
    ['src-tauri/sidecar/local-api-server.mjs', "const LOCAL_API_TOKEN = process.env.LOCAL_API_TOKEN ?? '';\nexport function routes() { return []; }\n"],
    ['.env.example', 'WM_SESSION_SECRET=\nCLERK_PUBLISHABLE_KEY=\nPORT=3000\n'],
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
    id: 'ASSESS-1',
    name: 'Fixture assessment',
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

function request(overrides: Partial<Parameters<typeof runAssessment>[0]> = {}): Parameters<typeof runAssessment>[0] {
  return {
    assessment: assessment(),
    snapshot: { rootLabel: 'fixture', revision: 'abc123', files: worldMonitorFixture() },
    now: FIXED_CLOCK,
    ...overrides,
  };
}

describe('authorization is a gate, not a check', () => {
  test('an unconfirmed assessment produces no result at all', async () => {
    const outcome = await runAssessment(
      request({ assessment: assessment({ scope: scope({ authorization: 'UNCONFIRMED' }) }) }),
    );
    expect(outcome.result).toBeNull();
    expect(outcome.abortReason).toContain('not been confirmed as authorized');
  });

  test('a production target under a self-hosted declaration is refused', async () => {
    const outcome = await runAssessment(
      request({ assessment: assessment({ scope: scope({ authorization: 'SELF_HOSTED', environment: 'PRODUCTION' }) }) }),
    );
    expect(outcome.result).toBeNull();
    expect(outcome.authorization.code).toBe('AUTHORIZATION_UNCONFIRMED');
  });
});

describe('refusal to assess a target that is not World Monitor', () => {
  test('a snapshot with no recognisable components is refused, not reported clean', async () => {
    const outcome = await runAssessment(
      request({
        snapshot: {
          rootLabel: 'not-worldmonitor',
          revision: null,
          files: new Map<string, string>([
            ['package.json', '{"name":"something-else"}'],
            ['vercel.json', '{"headers":[]}'],
          ]),
        },
      }),
    );
    expect(outcome.result).toBeNull();
    expect(outcome.abortReason).toContain('not a World Monitor target');
    // The reason must name what it recognised and what it looked for, so an
    // operator who handed over the wrong directory can tell which.
    expect(outcome.abortReason).toContain('vercel-edge');
    expect(outcome.abortReason).toContain('browser-spa');
  });
});

describe('determinism', () => {
  test('the same snapshot and clock produce byte-identical results', async () => {
    const first = await runAssessment(request());
    const second = await runAssessment(request());
    expect(first.result).not.toBeNull();
    expect(second.result).not.toBeNull();
    expect(JSON.stringify(second.result)).toBe(JSON.stringify(first.result));
  });

  test('evidence digests are content-addressed, not run-scoped', async () => {
    const first = await runAssessment(request());
    const second = await runAssessment(request());
    const a = first.result!.evidence.map((item) => item.sha256).sort();
    const b = second.result!.evidence.map((item) => item.sha256).sort();
    expect(a.length).toBeGreaterThan(0);
    expect(b).toEqual(a);
  });

  test('test ids do not depend on execution order', async () => {
    const reversed = await runAssessment(
      request({ assessment: assessment({ moduleNames: ['cors', 'security-headers'] }) }),
    );
    const forward = await runAssessment(request());
    const reversedIds = reversed.result!.tests.map((test) => test.testId).sort();
    const forwardIds = forward.result!.tests.map((test) => test.testId).sort();
    expect(reversedIds).toEqual(forwardIds);
  });
});

describe('results join correctly', () => {
  test('a test joins to the control it exercised, so coverage is not vacuously NOT_TESTED', async () => {
    const outcome = await runAssessment(request());
    const result = outcome.result!;

    const nocniff = result.coverage.find(
      (entry) => entry.controlId === 'CTRL-VERCEL-EDGE-X-CONTENT-TYPE-OPTIONS',
    );
    expect(nocniff).toBeDefined();
    expect(nocniff!.testIds.length).toBeGreaterThan(0);
    expect(nocniff!.status).toBe('TESTED_PASS');
    expect(nocniff!.evidenceIds.length).toBeGreaterThan(0);
  });

  test('every control has at least one test or an explicit reason', async () => {
    const outcome = await runAssessment(request());
    const result = outcome.result!;
    for (const control of result.controls) {
      const coverage = result.coverage.find((entry) => entry.controlId === control.id);
      expect(coverage).toBeDefined();
      if (coverage!.testIds.length === 0) {
        const explained = result.notTested.some((note) => note.reason.includes(control.id));
        expect(explained).toBe(true);
      }
    }
  });

  test('each test has exactly one owning assessment and run', async () => {
    const outcome = await runAssessment(request());
    for (const test of outcome.result!.tests) {
      expect(test.assessmentId).toBe('ASSESS-1');
      expect(test.runId).toBe(outcome.result!.run.id);
      expect(test.requiresCapability).toBe('NONE');
    }
  });
});

describe('nothing disappears', () => {
  test('an unknown module name is reported rather than ignored', async () => {
    const outcome = await runAssessment(
      request({ assessment: assessment({ moduleNames: ['security-headers', 'does-not-exist'] }) }),
    );
    const note = outcome.result!.notTested.find((entry) => entry.module === 'does-not-exist');
    expect(note).toBeDefined();
    expect(note!.reason).toContain('is registered in this build');
  });

  test('a module that throws is recorded as failed and excluded from results', async () => {
    const exploding: SecurityModule = {
      name: 'exploding',
      label: 'Exploding',
      category: 'TEST',
      boundary: null,
      requires: 'NONE',
      run() {
        throw new Error('module defect');
      },
    };
    const outcome = await runAssessment(
      request({ modules: [...(await import('../securescan/modules')).BUILT_IN_MODULES, exploding] as never, assessment: assessment({ moduleNames: ['exploding', 'security-headers'] }) }),
    );
    const progress = outcome.result!.run.progress.find((entry) => entry.module === 'exploding');
    expect(progress!.status).toBe('FAILED');
    expect(progress!.error).toContain('module defect');
    const note = outcome.result!.notTested.find((entry) => entry.module === 'exploding');
    expect(note!.reason).toContain('module defect');
    // The surviving module must still have contributed.
    expect(outcome.result!.tests.length).toBeGreaterThan(0);
  });

  test('absent components are reported with a reason, never as PASS', async () => {
    const outcome = await runAssessment(request());
    const notes = outcome.result!.notTested.filter((entry) => entry.module.startsWith('architecture:'));
    expect(notes.length).toBeGreaterThan(0);
    for (const note of notes) {
      expect(note.reason.trim().length).toBeGreaterThan(0);
    }
  });

  test('the run counts warnings from inconclusive tests', async () => {
    const outcome = await runAssessment(request());
    const inconclusive = outcome.result!.tests.filter((test) => test.status === 'INCONCLUSIVE').length;
    expect(outcome.result!.run.warningCount).toBe(inconclusive);
    expect(outcome.result!.run.errorCount).toBe(0);
  });
});

describe('recorder invariants', () => {
  function contextFor(): ModuleContext {
    const repo = new RepoView({ rootLabel: 'fixture', revision: null, files: worldMonitorFixture(), unreadable: [] });
    return {
      assessmentId: 'ASSESS-1',
      runId: 'RUN-1',
      repo,
      probe: null,
      now: FIXED_CLOCK,
      moduleCapability: 'NONE',
      architecture: { nodes: [], edges: [], boundaries: [], presentNodeIds: new Set() },
      surface: { entries: [] },
      environment: 'PRODUCTION',
    };
  }

  test('a FAIL with no evidence is refused at record time', async () => {
    const recorder = new Recorder(contextFor(), 'demo', 'TEST', null);
    await expect(
      recorder.test({
        slug: 'no-evidence-fail',
        component: 'demo',
        control: 'demo-control',
        node: 'vercel-edge',
        target: 'x',
        expected: 'y',
        observed: 'z',
        status: 'FAIL',
      }),
    ).rejects.toThrow(/must be evidence-backed/);
  });

  test('two tests may not share a slug, because test ids are retest references', async () => {
    const recorder = new Recorder(contextFor(), 'demo', 'TEST', null);
    const input = {
      slug: 'same-slug',
      component: 'demo',
      control: 'demo-control',
      node: 'vercel-edge' as const,
      target: 'x',
      expected: 'y',
      observed: 'z',
      status: 'PASS' as const,
    };
    await recorder.test(input);
    await expect(recorder.test(input)).rejects.toThrow(/unique within a module/);
  });

  test('identical observations recorded twice collapse to one evidence record', async () => {
    const recorder = new Recorder(contextFor(), 'demo', 'TEST', null);
    const evidence = [
      {
        type: 'CONFIGURATION' as const,
        description: 'Same observation',
        payload: { kind: 'config-value' as const, path: 'vercel.json', pointer: 'p', value: 'v' },
        producedBy: 'demo',
      },
    ];
    const a = await recorder.test({
      slug: 'first',
      component: 'demo',
      control: 'demo-control',
      node: 'vercel-edge',
      target: 'x',
      expected: 'y',
      observed: 'z',
      status: 'PASS',
      evidence,
    });
    const b = await recorder.test({
      slug: 'second',
      component: 'demo',
      control: 'demo-control',
      node: 'vercel-edge',
      target: 'x',
      expected: 'y',
      observed: 'z',
      status: 'PASS',
      evidence,
    });
    const output: ModuleOutput = recorder.output();
    expect(output.evidence).toHaveLength(1);
    expect(output.tests.find((test) => test.testId === a)!.evidenceIds).toEqual(
      output.tests.find((test) => test.testId === b)!.evidenceIds,
    );
  });

  test('a test records the control id so coverage can join on it', async () => {
    const recorder = new Recorder(contextFor(), 'demo', 'TEST', null);
    const testId = await recorder.test({
      slug: 'joinable',
      component: 'demo',
      control: 'origin-allowlist',
      node: 'legacy-api-js',
      target: 'x',
      expected: 'y',
      observed: 'z',
      status: 'PASS',
    });
    const controlId = await recorder.control({
      control: 'origin-allowlist',
      node: 'legacy-api-js',
      label: 'Origin allowlist',
      status: 'PRESENT',
      rationale: 'present',
    });
    const output = recorder.output();
    const coverage = buildCoverage(output.controls, output.tests, FIXED_CLOCK());
    expect(output.tests.find((test) => test.testId === testId)!.control).toBe(controlId);
    expect(coverage[0]!.status).toBe('TESTED_PASS');
  });
});
