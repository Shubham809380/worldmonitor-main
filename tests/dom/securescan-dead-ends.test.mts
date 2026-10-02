/**
 * SecureScan dead-end states offer a way out.
 *
 * `errorState` accepts an `action` slot that no route used to fill, so the states
 * for a missing evidence id, assessment id, or finding id read like instructions
 * ("open a finding", "choose an assessment") with nothing to click. A user who
 * arrived at `#/evidence`, `#/report`, or `#/findings` directly was told what to do
 * and given no way to do it.
 *
 * These drive the real `startSecureScan` against a mocked transport, so the fix is
 * pinned where it lives: in the shell's routing. Reconstructing the markup here
 * would keep passing if the routes were reverted.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const getViewerIdentity = vi.fn();
const getDashboard = vi.fn();
const listFindings = vi.fn();
const listMyAssessments = vi.fn();
const getEvidence = vi.fn();
const getReport = vi.fn();
const getFindingDetail = vi.fn();
const getAssessmentDetail = vi.fn();

vi.mock('@/securescan/services/api', async () => {
  const actual = await vi.importActual<typeof import('@/securescan/services/api')>(
    '@/securescan/services/api',
  );
  return {
    ...actual,
    getViewerIdentity: (...args: unknown[]) => getViewerIdentity(...args),
    getDashboard: (...args: unknown[]) => getDashboard(...args),
    listFindings: (...args: unknown[]) => listFindings(...args),
    listMyAssessments: (...args: unknown[]) => listMyAssessments(...args),
    getEvidence: (...args: unknown[]) => getEvidence(...args),
    getReport: (...args: unknown[]) => getReport(...args),
    getFindingDetail: (...args: unknown[]) => getFindingDetail(...args),
    getAssessmentDetail: (...args: unknown[]) => getAssessmentDetail(...args),
  };
});

const DASHBOARD = { role: 'SECURITY_ANALYST', userId: 'user-analyst' };

/**
 * A dashboard read model with nothing in it. The panel shapes come from the
 * real interface in `services/api.ts`, because a partial fixture fails deep
 * inside a render for reasons unrelated to the behaviour under test.
 */
const EMPTY_DASHBOARD = {
  role: 'SECURITY_ANALYST' as const,
  userId: 'user-analyst',
  totals: {
    assessments: 0,
    assessmentsByState: {},
    openFindings: 0,
    closedFindings: 0,
    findingsByState: {},
    findingsBySeverity: {},
    unscoredCandidates: 0,
    runs: 0,
    evidence: 0,
    tests: 0,
    members: 0,
  },
  lastRun: null,
  recentAssessments: [],
  recentFindings: [],
};

function boot(hash: string): void {
  document.body.innerHTML = `
    <div id="ss-boot"><div class="ss-boot__inner"><span>Loading the security console.</span></div></div>
    <div id="ss-root"></div>
  `;
  window.location.hash = hash;
}

async function start(hash: string): Promise<HTMLElement> {
  boot(hash);
  const { startSecureScan } = await import('@/securescan/app');
  await startSecureScan();
  return document.getElementById('ss-root') as HTMLElement;
}

/** Hrefs in the rendered shell, in document order. */
function hrefs(root: HTMLElement): string[] {
  return [...root.querySelectorAll('a[href]')].map((a) => a.getAttribute('href')!);
}

/** The href of the actionable link inside the error state, ignoring nav links. */
function stateHref(root: HTMLElement): string | null {
  const action = root.querySelector('.ss-state--error a[href]');
  return action ? action.getAttribute('href') : null;
}

describe('secure scan dead-end states are escapable', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getViewerIdentity.mockResolvedValue({ ok: true, value: { signedIn: true, userId: 'user-analyst', role: 'SECURITY_ANALYST' } });
    getDashboard.mockResolvedValue({ ok: true, value: DASHBOARD });
    // Every detail fetch must stay uncalled: these routes are supposed to refuse
    // before touching the backend, and a test that let them through would be
    // asserting the wrong thing.
    for (const fn of [getEvidence, getReport, getFindingDetail, getAssessmentDetail]) {
      fn.mockRejectedValue(new Error('route should have refused before fetching'));
    }
  });

  it.each([
    ['#/evidence', 'MISSING EVIDENCE', 'findings'],
    ['#/report', 'CHOOSE AN ASSESSMENT', 'assessments'],
  ])('%s renders the dead-end state without touching the backend', async (hash, title) => {
    const root = await start(hash);
    // Sanity: the shell itself mounted, so we are reading a real page.
    expect(root.querySelector('.ss-app')).not.toBeNull();
    expect(root.querySelector('.ss-state--error')!.textContent).toContain(title!);
    // These routes must refuse on the missing param, not fetch and then fail.
    expect(getEvidence).not.toHaveBeenCalled();
    expect(getReport).not.toHaveBeenCalled();
  });

  it.each([
    ['#/evidence', 'MISSING EVIDENCE', 'findings'],
    ['#/report', 'CHOOSE AN ASSESSMENT', 'assessments'],
  ])('%s names the problem and links out to %s', async (hash, title, expectedRoute) => {
    const root = await start(hash);
    const state = root.querySelector('.ss-state--error')!;
    expect(state.getAttribute('role')).toBe('alert');
    expect(state.textContent).toContain(title!);

    const href = stateHref(root);
    expect(href, 'dead end must contain an actionable link').not.toBeNull();

    const { parseRoute } = await import('@/securescan/routing');
    const target = parseRoute(href!);
    expect(target.name).toBe(expectedRoute);
    // The remedy must not re-enter the dead end it is escaping.
    expect(target.name).not.toBe(parseRoute(hash).name);
  });

  it('the escaped route is one the shell can actually reach', async () => {
    const root = await start('#/evidence');
    const href = stateHref(root)!;
    expect(hrefs(root)).toContain(href);

    // Follow it for real: the link must land on a working list page, not on
    // another error.
    listFindings.mockResolvedValue({ ok: true, value: { findings: [] } });
    const navigated = await start(href);
    expect(navigated.querySelector('.ss-state--error')).toBeNull();
    expect(getEvidence).not.toHaveBeenCalled();
  });

  it.each([
    ['unauthenticated', 'ss-state--denied'],
    ['no_membership', 'ss-state--denied'],
  ])('leaves the %s state without a button', async (kind, expectedClass) => {
    // Sign-in and no-membership deliberately get no in-console link: there is no
    // destination inside SecureScan that would help, and offering one would imply
    // the console can resolve the refusal. They render as denied, not as error.
    // Guarding this keeps the fix from turning every failure state into a button.
    getViewerIdentity.mockResolvedValue({ ok: true, value: { signedIn: false, userId: null, role: null } });
    getDashboard.mockResolvedValue({ ok: false, kind, message: 'Refused.' });
    const root = await start('#/dashboard');
    expect(root.querySelector(`.${expectedClass}`)).not.toBeNull();
    expect(stateHref(root)).toBeNull();
  });

  it('an unrecognised route leaves a way back to the console', async () => {
    // `parseRoute` maps any unknown first segment to `unknown`, so a stale or
    // mistyped link reaches this state. It used to be the one error state with no
    // action at all: the reader was stranded on a page they could not leave.
    const root = await start('#/this-view-does-not-exist');
    const state = root.querySelector('.ss-state--error')!;
    expect(state.textContent).toContain('PAGE NOT FOUND');

    const routes = hrefs(root).map((href) => href);
    expect(routes).toContain('#/dashboard');
    expect(routes).toContain('#/assessments');
    expect(routes).toContain('#/findings');

    // Every escape must resolve to a real route, not back into the dead end.
    const { parseRoute } = await import('@/securescan/routing');
    for (const href of ['#/dashboard', '#/assessments', '#/findings']) {
      expect(parseRoute(href).name, `${href} must be a real route`).not.toBe('unknown');
    }
  });

  it('a following unknown-route escape lands on a working page', async () => {
    const root = await start('#/this-view-does-not-exist');
    expect(hrefs(root)).toContain('#/assessments');
    listMyAssessments.mockResolvedValue({ ok: true, value: { assessments: [] } });
    const navigated = await start('#/assessments');
    expect(navigated.querySelector('.ss-state--error')).toBeNull();
  });

  it('an audit center with no assessments links to the place that makes one', async () => {
    // The copy says "Open one to create the first entry", but the audit center is
    // not where assessments are created, so without an action it was an
    // instruction the reader could not act on.
    listMyAssessments.mockResolvedValue({
      ok: true,
      value: { role: 'SECURITY_ANALYST', assessments: [] },
    });
    const root = await start('#/audit');
    const state = root.querySelector('.ss-state')!;
    expect(state.textContent).toContain('NO ASSESSMENTS');

    const href = state.querySelector('a[href]')!.getAttribute('href');
    const { parseRoute } = await import('@/securescan/routing');
    expect(parseRoute(href!).name).toBe('assessments-new');
  });

  it('a dashboard with nothing awaiting judgement links to the full queue', async () => {
    // "check the Findings view for the full queue" is only actionable if the
    // Findings view is one click away. The panel is driven by unscored rows in
    // `recentFindings`, so an empty list is what puts this state on screen.
    getDashboard.mockResolvedValue({
      ok: true,
      value: { ...EMPTY_DASHBOARD, recentFindings: [] },
    });
    const root = await start('#/dashboard');
    const state = [...root.querySelectorAll('.ss-state')].find((el) =>
      el.textContent!.includes('NO CANDIDATES AWAITING JUDGEMENT'),
    );
    expect(state, 'expected the candidates empty state').toBeDefined();

    const href = state!.querySelector('a[href]')!.getAttribute('href');
    const { parseRoute } = await import('@/securescan/routing');
    expect(parseRoute(href!).name).toBe('findings');
  });
});
