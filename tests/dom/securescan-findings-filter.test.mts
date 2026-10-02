/**
 * SecureScan findings filtering routes through the hash router.
 *
 * The filter used to be a native `<form method="get" action="#/findings">`. That was
 * broken in two ways simultaneously, both confirmed in Chromium:
 *
 *  - A GET submit to a fragment-only action performs a full document navigation, so
 *    the console re-booted instead of re-filtering.
 *  - It writes the values into `location.search`, but `parseRoute` reads only
 *    `location.hash`. The page came back on the unfiltered list.
 *
 * So the user pressed Apply, watched the page reload, and saw every finding.
 *
 * These drive the real `startSecureScan` against a mocked transport, so the fix is
 * pinned where it lives. `expect(listFindings).toHaveBeenCalledWith(...)` is the
 * point of most of them: the filter must become a *server query*, not a client-side
 * row hide, or the totals in the panel title would be a lie.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const getViewerIdentity = vi.fn();
const getDashboard = vi.fn();
const listFindings = vi.fn();
const listMyAssessments = vi.fn();

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
  };
});

const DASHBOARD = { role: 'SECURITY_ANALYST', userId: 'user-analyst' };

function finding(over: Record<string, unknown> = {}) {
  return {
    findingId: 'FND-1',
    assessmentId: 'ASM-1',
    title: 'Reflected XSS in search',
    control: 'A03-2021',
    severity: 'HIGH',
    state: 'CANDIDATE',
    stateLabel: 'Candidate',
    confidence: 80,
    evidenceCount: 2,
    updatedAt: 1750000000000,
    ...over,
  };
}

function list(over: Record<string, unknown> = {}) {
  return {
    ok: true,
    value: { findings: [finding()], total: 1, ...over },
  };
}

/**
 * `startSecureScan` registers a `hashchange` listener and only removes it on
 * `pagehide`. Importing it per test stacks listeners, and a stale listener would
 * repaint the shared `#ss-root` under the current test -- cross-test bleed is
 * exactly what makes a filter suite lie. So boot once and re-route after it.
 */
let booted = false;

async function boot(hash: string): Promise<void> {
  document.body.innerHTML = `
    <div id="ss-boot"><div class="ss-boot__inner"><span>Loading.</span></div></div>
    <div id="ss-root"></div>
  `;
  window.location.hash = hash;
  const { startSecureScan } = await import('@/securescan/app');
  await startSecureScan();
  booted = true;
}

/**
 * Navigate by writing the hash and letting the shell's own listener repaint.
 *
 * `hashchange` is dispatched explicitly: happy-dom does not reliably fire it from a
 * programmatic assignment, and waiting for it silently made several tests pass
 * against the *previous* route's DOM. Dispatching is what the browser does, so this
 * exercises the real path rather than a test-only shortcut.
 */
async function route(hash: string): Promise<HTMLElement> {
  const root = document.getElementById('ss-root') as HTMLElement;
  window.location.hash = hash;
  window.dispatchEvent(new HashChangeEvent('hashchange'));
  // Drain the microtask queue the paint awaits.
  for (let i = 0; i < 8; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));
  return root;
}

async function start(hash: string): Promise<HTMLElement> {
  if (!booted) {
    await boot(hash);
    return document.getElementById('ss-root') as HTMLElement;
  }
  return route(hash);
}

/** Settle the shell after a filter-driven hashchange. */
async function settle(times = 8): Promise<void> {
  for (let i = 0; i < times; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));
}

function select(root: HTMLElement, id: string, value: string): void {
  const el = root.querySelector<HTMLSelectElement>(`#${id}`)!;
  el.value = value;
  el.dispatchEvent(new Event('change'));
}

describe('secure scan findings filters', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getViewerIdentity.mockResolvedValue({
      ok: true,
      value: { signedIn: true, userId: 'user-analyst', role: 'SECURITY_ANALYST' },
    });
    getDashboard.mockResolvedValue({ ok: true, value: DASHBOARD });
    listFindings.mockResolvedValue(list());
  });

  it('does not use a native GET form', async () => {
    // The specific defect. A fragment-only action cannot carry a filter into a
    // hash router, so any GET form here is a silent no-op for the reader. Read
    // from the rendered page rather than from the module, so this is the same
    // markup a reader receives.
    const root = await start('#/findings');
    expect(root.querySelector('form[method="get"]')).toBeNull();
    expect(root.innerHTML).not.toContain('method="get"');
    expect(root.innerHTML).not.toContain('action=');
  });

  it('renders the default view with no filter applied', async () => {
    const root = await start('#/findings');
    expect(listFindings).toHaveBeenCalledWith({ limit: 200 });
    expect(root.querySelector<HTMLSelectElement>('#ss-filter-state')?.value).toBe('');
    expect(root.querySelector<HTMLSelectElement>('#ss-filter-severity')?.value).toBe('');
    expect(root.textContent).toContain('All findings');
    // Clear is pointless with nothing applied, and an enabled button that does
    // nothing is worse than a disabled one.
    expect(root.querySelector<HTMLButtonElement>('#ss-filter-clear')?.disabled).toBe(true);
  });

  it.each(['CANDIDATE', 'VALIDATED', 'REMEDIATION', 'VERIFIED', 'REGRESSION', 'INCONCLUSIVE'])(
    'filters by state %s through a server query',
    async (state) => {
      const root = await start('#/findings');
      listFindings.mockClear();
      select(root, 'ss-filter-state', state);
      await settle();
      expect(listFindings).toHaveBeenCalledWith({ limit: 200, state });
      expect(window.location.hash).toContain(`state=${state}`);
    },
  );

  it.each(['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])(
    'filters by severity %s through a server query',
    async (severity) => {
      const root = await start('#/findings');
      listFindings.mockClear();
      select(root, 'ss-filter-severity', severity);
      await settle();
      expect(listFindings).toHaveBeenCalledWith({ limit: 200, severity });
      expect(window.location.hash).toContain(`severity=${severity}`);
    },
  );

  it('keeps both filters when one is added to the other', async () => {
    const root = await start('#/findings');
    listFindings.mockClear();
    select(root, 'ss-filter-state', 'CANDIDATE');
    await settle();
    select(root, 'ss-filter-severity', 'HIGH');
    await settle();
    expect(listFindings).toHaveBeenLastCalledWith({ limit: 200, state: 'CANDIDATE', severity: 'HIGH' });
    expect(window.location.hash).toContain('state=CANDIDATE');
    expect(window.location.hash).toContain('severity=HIGH');
  });

  it('clears both filters and returns to the unfiltered query', async () => {
    const root = await start('#/findings?state=CANDIDATE&severity=HIGH');
    listFindings.mockClear();
    root.querySelector<HTMLButtonElement>('#ss-filter-clear')!.click();
    await settle();
    expect(listFindings).toHaveBeenCalledWith({ limit: 200 });
    expect(window.location.hash).toBe('#/findings');
  });

  it('deep links a filtered view', async () => {
    // The shareable-URL property the module documents: filters live in the hash.
    //
    // The preselected option is asserted through the DOM rather than through
    // `select.value`: happy-dom resolves `selected` to the first option and does
    // not honour it on later ones (verified against the DOM implementation), so a
    // `.value` assertion here would fail for a correct page. The browser run
    // checks the same control for real.
    const root = await start('#/findings?state=REGRESSION');
    expect(listFindings).toHaveBeenCalledWith({ limit: 200, state: 'REGRESSION' });
    const stateSelect = root.querySelector<HTMLSelectElement>('#ss-filter-state')!;
    expect(stateSelect.querySelector('option[value="REGRESSION"]')?.hasAttribute('selected')).toBe(true);
    expect(root.querySelector<HTMLButtonElement>('#ss-filter-clear')?.disabled).toBe(false);
    expect(root.textContent).toContain('matching');
  });

  it('deep links every supported state and severity as a server query', async () => {
    for (const state of ['CANDIDATE', 'VALIDATED', 'REMEDIATION', 'VERIFIED', 'REGRESSION', 'INCONCLUSIVE']) {
      listFindings.mockClear();
      await start(`#/findings?state=${state}`);
      expect(listFindings, `deep link for ${state}`).toHaveBeenCalledWith({ limit: 200, state });
    }
    for (const severity of ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']) {
      listFindings.mockClear();
      await start(`#/findings?severity=${severity}`);
      expect(listFindings, `deep link for ${severity}`).toHaveBeenCalledWith({ limit: 200, severity });
    }
  });

  it('reports the empty result honestly and offers a way back', async () => {
    listFindings.mockResolvedValue(list({ findings: [], total: 0 }));
    const root = await start('#/findings?state=VERIFIED');
    expect(root.textContent).toContain('NO MATCHING FINDINGS');
    // The copy must not read as a clean result.
    expect(root.textContent).toContain('about the filter');
    const clear = [...root.querySelectorAll('a')].find((a) => a.textContent?.includes('Clear filter'));
    expect(clear, 'no-results state must offer a way out').toBeDefined();
    expect(clear!.getAttribute('href')).toBe('#/findings');
  });

  it('says no run has produced a finding, not that the target is clean', async () => {
    listFindings.mockResolvedValue(list({ findings: [], total: 0 }));
    const root = await start('#/findings');
    expect(root.textContent).toContain('NO FINDINGS RECORDED');
    expect(root.textContent).toContain('run a scan');
    expect(root.textContent).not.toMatch(/\bclean\b|\bsecure\b|0 vulnerabilities/i);
  });

  it.each([
    ['unknown state', '#/findings?state=TOTALLY_INVALID'],
    ['unknown severity', '#/findings?severity=EXTREME'],
    ['prototype pollution attempt', '#/findings?state=__proto__'],
    ['constructor attempt', '#/findings?severity=constructor'],
    ['empty values', '#/findings?state=&severity='],
    ['no scheme injection', "#/findings?state=javascript:alert(1)"],
  ])('drops %s rather than forwarding it to the backend', async (_label, hash) => {
    const root = await start(hash);
    // The value is dropped, so the backend is asked for the unfiltered list. This
    // is input narrowing at the client hop; authorization stays server-side.
    expect(listFindings).toHaveBeenCalledWith({ limit: 200 });
    // And it must not be rendered into the page as if it were a real filter.
    expect(root.querySelector<HTMLSelectElement>('#ss-filter-state')?.value).toBe('');
    expect(root.textContent).not.toContain('TOTALLY_INVALID');
    expect(root.textContent).not.toContain('javascript:alert');
  });

  it('never renders the raw assessmentId filter as unescaped markup', async () => {
    const root = await start('#/findings?assessmentId=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E');
    expect(root.innerHTML).not.toContain('<img');
    expect(root.textContent).not.toContain('onerror');
  });

  it('shows a truthful unavailable state when the backend is down', async () => {
    listFindings.mockResolvedValue({ ok: false, kind: 'unavailable', message: 'No connection.' });
    const root = await start('#/findings');
    expect(root.textContent).toMatch(/BACKEND UNAVAILABLE/i);
    // Critically: not "0 findings" and not a clean bill of health.
    expect(root.textContent).not.toMatch(/NO FINDINGS RECORDED|0 vulnerabilities|\bclean\b/i);
  });

  it('exposes accessible names and announces the result region', async () => {
    const root = await start('#/findings');
    expect(root.querySelector('label[for="ss-filter-state"]')?.textContent).toBe('Validation state');
    expect(root.querySelector('label[for="ss-filter-severity"]')?.textContent).toBe('Severity');
    expect(root.querySelector('#ss-filter-state')?.getAttribute('aria-controls')).toBe('ss-findings-results');
    const status = root.querySelector('#ss-filter-status');
    expect(status?.getAttribute('role')).toBe('status');
    expect(status?.getAttribute('aria-live')).toBe('polite');
    expect(root.querySelector('[role="group"]')?.getAttribute('aria-label')).toBe('Filter findings');
  });
});
