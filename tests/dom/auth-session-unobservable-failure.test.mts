/**
 * Tests for how a completed sign-in that cannot be confirmed is reported.
 *
 * The bug this pins: when `/api/auth/login` answered 200 (so the password was
 * correct and the deployment was configured) but the follow-up
 * `/api/auth/session` read did not show a session, the code reported
 * "Email sign-in is not available in this deployment. Continue with Google."
 * That is three separate lies at once:
 *
 *  - the code was `not_configured`, but the server was configured and answered;
 *  - password sign-in was available and had just succeeded;
 *  - it pointed at Google, which cannot repair a cookie this bundle failed to
 *    observe and would strand the reader on a popup instead.
 *
 * Lives in the DOM suite because auth-session.ts reads window.location at module
 * load (BRIDGE_RETURN_URL), so it cannot be imported into the node data suite.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

type FlowOutcome = { kind: string; code?: string; message?: string; user?: unknown };

const ORIGINAL_FETCH = globalThis.fetch;

/** Route the two endpoints this flow touches: the write, then the session read. */
function stubFetch(routes: { session: unknown; login?: { status: number; body: unknown } }) {
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes('/api/auth/login')) {
      const r = routes.login ?? { status: 200, body: { authenticated: true } };
      return new Response(JSON.stringify(r.body), {
        status: r.status,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (url.includes('/api/auth/session')) {
      return new Response(JSON.stringify(routes.session), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    throw new Error(`unexpected fetch: ${url}`);
  }) as typeof globalThis.fetch;
}

async function signIn(): Promise<FlowOutcome> {
  vi.resetModules();
  const mod = await import('@/worldguard/services/auth-session');
  return (await mod.signInWithPassword('reader@example.com', 'correct-horse')) as FlowOutcome;
}

beforeEach(() => {
  globalThis.document = { cookie: '' } as unknown as Document;
});

afterEach(() => {
  globalThis.fetch = ORIGINAL_FETCH;
  vi.resetModules();
});

describe('sign-in that cannot be confirmed', () => {
  it('does not blame the deployment when the server accepted the password', async () => {
    // Login succeeded; the session read came back anonymous. The honest fault
    // is an unobserved session, not missing configuration.
    stubFetch({ session: { status: 'anonymous' } });
    const outcome = await signIn();

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.code).toBe('service_error');
    expect(outcome.message).not.toMatch(/not available in this deployment/i);
  });

  it('does not send the reader to Google for a session this bundle failed to observe', async () => {
    stubFetch({ session: { status: 'anonymous' } });
    const outcome = await signIn();

    // Google cannot repair an unobserved cookie; this advice strands them.
    expect(outcome.message ?? '').not.toMatch(/continue with google/i);
  });

  it('keeps reporting a real 503 not_configured as a configuration problem', async () => {
    // The fix must not swallow the genuinely-unconfigured case, which is the
    // one place the old wording was accurate.
    stubFetch({
      session: { status: 'anonymous' },
      login: { status: 503, body: { error: 'not_configured' } },
    });
    const outcome = await signIn();

    expect(outcome.kind).toBe('failed');
    if (outcome.kind !== 'failed') return;
    expect(outcome.code).toBe('not_configured');
  });

  it('still authenticates when the session is observable', async () => {
    // Guards the documented invariant: a session is only reported when
    // /api/auth/session confirms it, never on the strength of a 200 alone.
    stubFetch({
      session: {
        status: 'authenticated',
        user: { id: 'u1', name: 'Reader', email: 'reader@example.com', image: null, plan: 'free' },
      },
    });
    const outcome = await signIn();

    expect(outcome.kind).toBe('authenticated');
  });
});
