/**
 * Finding detail rendering.
 *
 * The timeline is the page's audit trail: it is how a reader answers "who moved
 * this finding, and when". A transition row therefore has to show the two states
 * it moved between, not the string "[object Object]".
 */
import { describe, expect, it } from 'vitest';

import { mount } from '@/securescan/components/dom';
import { renderFindingDetail } from '@/securescan/pages/finding-detail';
import type {
  FindingDetailReadModel,
  FindingEventReadModel,
} from '@/securescan/services/api';

const AT = Date.parse('2026-09-01T12:00:00.000Z');

const FINDING: FindingDetailReadModel['finding'] = {
  findingId: 'FND-1',
  assessmentId: 'ss_assessment_1',
  runId: 'RUN-1',
  title: 'CSP absent on the OAuth callback',
  category: 'SECURITY_HEADERS',
  component: 'Edge',
  node: 'vercel-edge',
  boundary: null,
  control: 'CSP',
  severity: 'MEDIUM',
  severityLabel: 'MEDIUM',
  confidence: 'HIGH',
  state: 'RETEST_REQUIRED',
  stateLabel: 'Retest required',
  description: 'The callback route serves no CSP header.',
  rootCause: 'Headers were only applied to the document response.',
  rootCauseId: 'RC-1',
  businessImpact: 'Callback responses are unprotected.',
  risk: null,
  affectedEndpoints: ['/api/slack/oauth/callback'],
  fingerprint: 'fp-1',
  historicalStatus: 'CURRENTLY_OBSERVED',
  remediationSummary: 'Declared base-uri on the callback policy.',
  remediatedAt: AT,
  lastRetestState: null,
  lastRetestedAt: null,
  regressionTestId: null,
  createdAt: AT,
  updatedAt: AT,
};

function event(over: Partial<FindingEventReadModel>): FindingEventReadModel {
  return {
    kind: 'RETEST_STARTED',
    fromState: 'REMEDIATION',
    toState: 'RETEST_REQUIRED',
    actorUserId: 'user-analyst',
    note: 'change deployed to staging',
    at: AT,
    ...over,
  };
}

function render(events: FindingEventReadModel[]): string {
  const host = document.createElement('div');
  const data: FindingDetailReadModel = {
    role: 'SECURITY_ANALYST',
    finding: FINDING,
    evidence: [],
    tests: [],
    events,
  };
  const view = renderFindingDetail(data, { findingId: 'FND-1' });
  mount(host, view.body);
  return host.innerHTML;
}

describe('finding detail timeline', () => {
  it('renders a transition as its two states, not "[object Object]"', () => {
    const html = render([event({})]);

    // The defect: `stateBadge` returns SafeMarkup, and composing it with a
    // plain template literal stringified each badge to "[object Object]".
    expect(html).not.toContain('[object Object]');
    expect(html).toContain('REMEDIATION');
    expect(html).toContain('RETEST_REQUIRED');
  });

  it('shows the arrow between the states it moved between', () => {
    const html = render([event({})]);
    expect(html).toMatch(/REMEDIATION[\s\S]*RETEST_REQUIRED/);
  });

  it('falls back to the event kind when there is no transition', () => {
    const html = render([
      event({ kind: 'CREATED', fromState: null, toState: null }),
    ]);
    expect(html).not.toContain('[object Object]');
    expect(html).toContain('CREATED');
  });

  it('renders every event in the history', () => {
    const html = render([
      event({ kind: 'CREATED', fromState: null, toState: null }),
      event({ kind: 'VALIDATION_STARTED', fromState: 'CANDIDATE', toState: 'VALIDATING' }),
      event({ kind: 'RETEST_STARTED', fromState: 'REMEDIATION', toState: 'RETEST_REQUIRED' }),
    ]);
    expect(html).toContain('History (3)');
    expect(html).toContain('CREATED');
    expect(html).toContain('VALIDATION_STARTED');
    expect(html).toContain('RETEST_STARTED');
  });

  it('escapes a note rather than treating it as markup', () => {
    const html = render([
      event({ note: '<img src=x onerror=alert(1)>' }),
    ]);
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });
});

describe('finding detail retest state', () => {
  it('never offers a verdict the analyst could submit', () => {
    // The retest form queues a check; the engine reports the outcome. A radio
    // group named "verdict" here would be a control that asserts a security
    // result the server derives from a run.
    const html = render([event({})]);
    expect(html).not.toContain('name="verdict"');
    expect(html).not.toMatch(/value="passed"/);
  });
});

describe('finding detail remediation handoff', () => {
  /** Render the page for a finding sitting in an arbitrary lifecycle state. */
  function renderState(state: string, events: FindingEventReadModel[] = []): string {
    const host = document.createElement('div');
    const data: FindingDetailReadModel = {
      role: 'SECURITY_ANALYST',
      finding: { ...FINDING, state },
      evidence: [],
      tests: [],
      events,
    };
    const view = renderFindingDetail(data, { findingId: 'FND-1' });
    mount(host, view.body);
    return host.innerHTML;
  }

  it('names the next step from REMEDIATION, where both forms disappear', () => {
    // REMEDIATION is neither a remediation precursor nor retest-eligible, so the
    // remediation form and the retest form both vanish the moment a fix is
    // recorded. Without this note the page handed the analyst off to the engine
    // without ever saying the engine was what resolves it.
    const html = renderState('REMEDIATION');

    // The forms really are gone, which is why the note is load-bearing.
    expect(html).not.toContain('id="ss-fd-remediation"');
    expect(html).not.toContain('id="ss-fd-retest"');

    expect(html).toContain('data-next-step="REMEDIATION"');
    expect(html).toContain('RETEST_REQUIRED');
    expect(html).toContain('only a recorded retest resolves it');
  });

  it('tells a waiting finding that only a run can resolve it', () => {
    const html = renderState('RETEST_REQUIRED');
    expect(html).toContain('data-next-step="RETEST_REQUIRED"');
    expect(html).toContain('PASS to VERIFIED');
    expect(html).toContain('FAIL to REGRESSION');
  });

  it('does not name a next step where none exists', () => {
    // A note on a terminal state would be a dead end of its own: it would tell a
    // reader to take a step that is not available.
    for (const state of ['FALSE_POSITIVE', 'ACCEPTED_RISK', 'INFORMATIONAL']) {
      expect(renderState(state), `state ${state}`).not.toContain('data-next-step');
    }
  });

  it('keeps the note out of states that already render a next-step form', () => {
    // VALIDATED still offers the remediation form and RETEST_REQUIRED the retest
    // form; each already explains itself, so the note would be duplicated prose.
    expect(renderState('VALIDATED')).not.toContain('data-next-step');
  });
});
