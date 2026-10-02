/**
 * SecureScan boot behaviour.
 *
 * Boot is where the console meets three conditions it must never confuse: no
 * session, a session without a grant, and a response it cannot render. Each has
 * a distinct, truthful outcome, and this suite drives the real `startSecureScan`
 * against a mocked transport so the shell, the boot skeleton, and the boundary
 * are exercised together rather than in isolation.
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

/** The dashboard shape the shell needs. Only the identity fields matter here. */
const DASHBOARD = { role: 'SECURITY_ANALYST', userId: 'user-analyst' };

function viewer(over: Record<string, unknown> = {}) {
  return { ok: true, value: { signedIn: true, userId: 'user-analyst', role: 'SECURITY_ANALYST', ...over } };
}

function boot(hash = '#/dashboard'): void {
  document.body.innerHTML = `
    <div id="ss-boot"><div class="ss-boot__inner"><span>Loading the security console.</span></div></div>
    <div id="ss-root"></div>
  `;
  window.location.hash = hash;
}

async function start() {
  const { startSecureScan } = await import('@/securescan/app');
  await startSecureScan();
  return document.getElementById('ss-root') as HTMLElement;
}

describe('secure scan boot', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getViewerIdentity.mockResolvedValue(viewer());
    getDashboard.mockResolvedValue({ ok: true, value: DASHBOARD });
    boot();
  });

  it('keeps the loading skeleton until the shell is actually mounted', async () => {
    // `getDashboard` waits on the auth handshake. Removing the skeleton before
    // the first paint left a blank white page for the length of that wait.
    let release: () => void = () => {
      throw new Error('getDashboard was never called');
    };
    getDashboard.mockImplementation(
      () =>
        new Promise((resolve) => {
          release = () => resolve({ ok: true, value: DASHBOARD });
        }),
    );

    const { startSecureScan } = await import('@/securescan/app');
    // Imported first so the call below runs synchronously into its first await;
    // a deferred import would leave the gate unresolved by the time we assert.
    const pending = startSecureScan();

    expect(document.getElementById('ss-boot')).not.toBeNull();
    expect(document.getElementById('ss-root')?.innerHTML).toBe('');

    release();
    await pending;
    expect(document.getElementById('ss-boot')).toBeNull();
    expect(document.getElementById('ss-root')?.innerHTML).not.toBe('');
  });

  it('tells a signed-in non-member to obtain a grant, not that the backend is down', async () => {
    getViewerIdentity.mockResolvedValue({ ok: true, value: { signedIn: true, userId: 'user-nobody', role: null } });
    getDashboard.mockResolvedValue({ ok: false, kind: 'no_membership', message: 'SECURESCAN_NO_MEMBERSHIP' });

    const root = await start();
    const html = root.innerHTML;

    expect(html).toContain('NO SECURESCAN MEMBERSHIP');
    expect(html).not.toContain('BACKEND UNAVAILABLE');
    // The sidebar must not contradict the refusal screen.
    expect(html).toContain('Signed in');
    expect(html).not.toContain('Not authenticated');
  });

  it('renders a render fault instead of leaving the console blank', async () => {
    // A malformed payload: the page renderer throws on the way to the DOM.
    getViewerIdentity.mockResolvedValue(viewer());
    getDashboard.mockResolvedValue({
      ok: true,
      value: { ...DASHBOARD, recentAssessments: [{ unexpected: 'shape' }] },
    });
    vi.spyOn(console, 'error').mockImplementation(() => {});

    const root = await start();

    expect(root.innerHTML).toContain('THIS VIEW COULD NOT BE RENDERED');
    // The navigation survives, so the reader is not stranded.
    expect(root.querySelector('.ss-nav')).not.toBeNull();
    // The screen must not imply the fault said anything about security.
    expect(root.innerHTML).not.toContain('BACKEND UNAVAILABLE');
  });

  it('reaches the dashboard without throwing when the transport is unconfigured', async () => {
    getViewerIdentity.mockResolvedValue({ ok: false, kind: 'unavailable', message: 'not configured' });
    getDashboard.mockResolvedValue({ ok: false, kind: 'unavailable', message: 'not configured' });

    const root = await start();
    expect(root.querySelector('.ss-nav')).not.toBeNull();
    expect(root.innerHTML).toContain('BACKEND UNAVAILABLE');
  });

  it('does not report a session when only the viewer query failed', async () => {
    // The viewer query discloses nothing sensitive, so a failure of it must not
    // be read as proof of anonymity.
    getViewerIdentity.mockResolvedValue({ ok: false, kind: 'unavailable', message: 'unreachable' });
    getDashboard.mockResolvedValue({ ok: true, value: DASHBOARD });

    const root = await start();
    expect(root.innerHTML).toContain('Signed in');
    expect(root.innerHTML).not.toContain('Not authenticated');
  });

  it('marks the boot skeleton as failed when boot itself rejects', async () => {
    // `#ss-root` is absent, so `rootElement()` throws. Because `startSecureScan`
    // is async this arrives as a rejection, not a synchronous throw, and the
    // entry point has to catch it as a promise for the user to see anything.
    document.body.innerHTML = '<div id="ss-boot"><div class="ss-boot__inner"></div></div>';

    const { startSecureScan, reportBootFailure } = await import('@/securescan/app');
    await expect(startSecureScan()).rejects.toThrow(/#ss-root/);

    reportBootFailure();
    expect(document.getElementById('ss-boot')?.classList.contains('ss-boot--failed')).toBe(true);
  });
});
