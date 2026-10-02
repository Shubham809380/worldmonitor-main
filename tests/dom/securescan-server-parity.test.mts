/**
 * SecureScan client/server parity guard.
 *
 * The browser read models in `src/securescan/services/api.ts` are a hand-written
 * mirror of the handlers in `convex/securescan/`, because the browser bundle
 * must not import a Convex server module and the generated `api.d.ts` cannot be
 * trusted until codegen runs. This file makes that mirror audited rather than
 * assumed, within the gates that exist while a deployment is unavailable:
 *
 *  1. **Reference surface.** Every `ref(api, "module", "name")` the client
 *     issues must resolve to an `export const <name> = query|mutation({` in the
 *     corresponding `convex/securescan/<module>.ts`, and the kind the client
 *     calls (query vs mutation) must match the server registration. This is the
 *     check that would have caught a client still reading a field the server no
 *     longer returns — here it catches a client calling a function the server
 *     does not export.
 *  2. **Terminal vocabulary.** The client's enum-shaped types (`Role`,
 *     `Severity`, `Confidence`) are pinned, one-to-one, to the engine types in
 *     `server/securescan/`. A server that adds a severity, renames a role or
 *     drops a confidence level fails this test at compile time.
 *  3. **Rendering smoke.** The smallest read model is rendered through the real
 *     shell markup path (`mount`), proving `html``;`/`panel`/`link` plumb
 *     through together and that data lands as text, not as injected markup.
 *
 * What this deliberately does not assert: the full field shape of the console
 * read models. Those are inline return objects in `convex/securescan/*.ts` and
 * this convex version does not expose their inferred return types through a
 * public type (no `FunctionReferenceFromExport`, and `RegisteredQuery` drops
 * its return generic), so an exact shape pin is impossible until codegen runs.
 * The reference-surface pin above is the proxy: if the resolver that serves the
 * model survives, the model that reaches the browser is at least served by the
 * function the client expects to define it.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import { mount } from '@/securescan/components/dom';
import { renderAssessmentList } from '@/securescan/pages/assessments';
import { renderFindingDetail } from '@/securescan/pages/finding-detail';
import { OFFERED_TRANSITIONS, retestEligible } from '@/securescan/pages/finding-lifecycle';
import type { AssessmentListReadModel } from '@/securescan/services/api';
import type { FindingDetailReadModel } from '@/securescan/services/api';
import type {
  Confidence as ClientConfidence,
  Role as ClientRole,
  Severity as ClientSeverity,
} from '@/securescan/services/api';

import { FINDING_TRANSITIONS } from '../../server/securescan/findings';
import type { Confidence as EngineConfidence, Severity as EngineSeverity } from '../../server/securescan/types';
import type { Role as EngineRole } from '../../server/securescan/identity';

type Equal<A, B> = [B] extends [A] ? ([A] extends [B] ? true : false) : false;
function assertTrue<T extends true>(value: T): T {
  return value;
}

const ROOT = process.cwd();

interface RefCall {
  module: string;
  name: string;
  kind: 'query' | 'mutation';
}

function clientRefs(): RefCall[] {
  const source = readFileSync(join(ROOT, 'src/securescan/services/api.ts'), 'utf8');
  const refs: RefCall[] = [];
  const pattern = /client\.(query|mutation)\(ref\(api, '([^']+)', '([^']+)'\)/g;
  for (const match of source.matchAll(pattern)) {
    refs.push({ kind: match[1] as 'query' | 'mutation', module: match[2]!, name: match[3]! });
  }
  return refs;
}

function serverExports(moduleName: string): Map<string, 'query' | 'mutation'> {
  const exports = new Map<string, 'query' | 'mutation'>();
  // `moduleName` is the deployed function path (`securescan/console`), so it
  // resolves from the Convex root. Hardcoding a `securescan/` prefix here would
  // have silently accepted the un-prefixed refs that the client used to make,
  // which is exactly the mismatch this suite exists to catch.
  const source = readFileSync(join(ROOT, 'convex', `${moduleName}.ts`), 'utf8');
  const pattern = /^export const (\w+) = (query|mutation|action)\s*\(\{/gm;
  for (const match of source.matchAll(pattern)) {
    exports.set(match[1]!, match[2] as 'query' | 'mutation');
  }
  return exports;
}

function assessmentsFixture(overrides: Partial<AssessmentListReadModel['assessments'][number]> = {}): AssessmentListReadModel {
  return {
    role: 'VIEWER',
    assessments: [
      {
        assessmentId: 'ass_1',
        name: 'Alpha-corpus rebuild',
        state: 'COMPLETED',
        ownerUserId: 'user_9',
        latestRunId: 'run_1',
        abortReason: null,
        updatedAt: 1_700_000_000_000,
        createdAt: 1_690_000_000_000,
        ...overrides,
      },
    ],
  };
}

function findingFixture(overrides: Partial<FindingDetailReadModel['finding']> = {}): FindingDetailReadModel {
  return {
    role: 'SECURITY_ANALYST',
    finding: {
      findingId: 'f_1',
      assessmentId: 'ass_1',
      runId: 'run_1',
      title: 'Missing CSP on the admin origin',
      category: 'CONTENT_SECURITY',
      component: 'server',
      node: 'node-admin',
      boundary: 'edge',
      control: 'CSP',
      severity: 'NONE',
      severityLabel: 'None',
      confidence: 'MEDIUM',
      state: 'CANDIDATE',
      stateLabel: 'Candidate',
      description: 'The admin origin responds without a Content-Security-Policy header on any of its routes.',
      rootCause: 'no CSP header is emitted by the web tier',
      rootCauseId: 'rc_1',
      businessImpact: 'A cross-site-scripting ingestion could run on the admin origin.',
      risk: null,
      affectedEndpoints: ['/admin'],
      fingerprint: 'fp_1',
      historicalStatus: 'CURRENT',
      remediationSummary: null,
      remediatedAt: null,
      lastRetestState: null,
      lastRetestedAt: null,
      regressionTestId: null,
      createdAt: 1_700_000_000_000,
      updatedAt: 1_700_000_000_000,
      ...overrides,
    },
    evidence: [],
    tests: [],
    events: [],
  };
}

describe('SecureScan client/server parity', () => {
  it('every client ref resolves to a server export of the matching kind', () => {
    const refs = clientRefs();
    expect(refs.length).toBeGreaterThan(0);
    for (const ref of refs) {
      expect(serverExports(ref.module).get(ref.name), `${ref.module}.${ref.name} must exist on the server`).toBe(
        ref.kind,
      );
    }
  });

  it('the client vocabulary matches the engine vocabulary exactly', () => {
    assertTrue<Equal<ClientRole, EngineRole>>(true);
    assertTrue<Equal<ClientSeverity, EngineSeverity>>(true);
    assertTrue<Equal<ClientConfidence, EngineConfidence>>(true);
    expect(true).toBe(true);
  });

  it('renders assessment markup from a server-shaped fixture', () => {
    const container = document.createElement('div');
    mount(container, renderAssessmentList(assessmentsFixture()));
    expect(container.textContent).toContain('Alpha-corpus rebuild');
    expect(container.textContent).toContain('Completed');
    expect(container.innerHTML).toContain('href="#/');
  });

  it('keeps a raw string as inert text rather than markup', () => {
    const container = document.createElement('div');
    mount(
      container,
      renderAssessmentList(
        assessmentsFixture({ name: '<img src=x onerror=alert(1)>', state: 'FAILED', abortReason: 'boom' }),
      ),
    );
    expect(container.querySelector('img')).toBeNull();
    expect(container.textContent).toContain('<img src=x onerror=alert(1)>');
  });

  it('renders the empty list as an empty state rather than a silent all-clear', () => {
    const container = document.createElement('div');
    mount(container, renderAssessmentList({ role: 'VIEWER', assessments: [] }));
    expect(container.textContent).toContain('NO ASSESSMENTS YET');
  });

  it('renders the finding detail page with lifecycle forms from server-shaped data', () => {
    const container = document.createElement('div');
    mount(container, renderFindingDetail(findingFixture(), {}).body);
    expect(container.textContent).toContain('Missing CSP on the admin origin');
    expect(container.textContent).toContain('Candidate');
    expect(container.querySelector('#ss-fd-transition')).not.toBeNull();
    expect(container.querySelector('#ss-fd-score')).not.toBeNull();
    expect(container.querySelector('#ss-fd-remediation')).toBeNull();
    expect(container.querySelector('#ss-fd-retest')).toBeNull();
    expect(container.textContent).toContain('NOT SCORED');
  });

  it('offers a retest request only where the engine can run one, and never a verdict', () => {
    // The analyst asks for a retest; the engine reports the outcome. A verdict
    // control here would let a browser assert VERIFIED or REGRESSION for a
    // finding, which is exactly the claim the server has to derive from a run.
    const retestForm = (state: string, stateLabel: string): number => {
      const host = document.createElement('div');
      mount(host, renderFindingDetail(findingFixture({ state, stateLabel }), {}).body);
      expect(host.querySelectorAll('input[name="verdict"]').length).toBe(0);
      expect(host.querySelectorAll('select[name="verdict"]').length).toBe(0);
      return host.querySelectorAll('#ss-fd-retest').length;
    };

    expect(retestForm('RETEST_REQUIRED', 'Retest required')).toBe(1);
    // A verified finding can only regress, so a retest stays available there.
    expect(retestForm('VERIFIED', 'Verified')).toBe(1);
    // Everything else is not retestable, so no form is offered at all.
    expect(retestForm('CANDIDATE', 'Candidate')).toBe(0);
    expect(retestForm('VALIDATING', 'Validating')).toBe(0);
    expect(retestForm('REMEDIATION', 'Remediation')).toBe(0);
  });

  it('offers the retest form exactly where retestEligible allows it', () => {
    // Keeps the page and the eligibility helper from drifting apart, so adding
    // a state to one without the other fails here rather than in production.
    for (const state of ['CANDIDATE', 'VALIDATING', 'VALIDATED', 'REMEDIATION', 'RETEST_REQUIRED', 'REGRESSION', 'VERIFIED', 'FIXED', 'FALSE_POSITIVE']) {
      const host = document.createElement('div');
      mount(host, renderFindingDetail(findingFixture({ state, stateLabel: state }), {}).body);
      expect(host.querySelectorAll('#ss-fd-retest').length, `retest form in ${state}`).toBe(
        retestEligible(state) ? 1 : 0,
      );
    }
  });

  it('keeps the offered lifecycle moves inside the engine transition table', () => {
    const engine = FINDING_TRANSITIONS as Record<string, readonly string[]>;
    const forbiddenTargets = new Set(['VERIFIED', 'FIXED']);
    const states = Object.keys(OFFERED_TRANSITIONS);
    expect(states.length).toBeGreaterThan(0);
    for (const from of states) {
      const offered = OFFERED_TRANSITIONS[from] ?? [];
      expect(engine[from], `${from} is a known engine state`).toBeDefined();
      for (const to of offered) {
        expect(engine[from] ?? [], `${from} -> ${to} must be legal in the engine`).toContain(to);
        expect(forbiddenTargets.has(to), `${from} -> ${to} must go through the retest flow`).toBe(false);
        expect(to, `${from} must not self-loop`).not.toBe(from);
      }
    }
  });
});