/**
 * Tests for the Google sign-in start path in src/services/clerk.ts.
 *
 * The bug this pins: `continueWithGoogle` returned a bare `false` on four
 * different failure paths, but opened Clerk's in-app sign-in surface on only
 * ONE of them (the popup-blocked one). The caller could not tell the causes
 * apart, so all four surfaced as "check that pop-ups are allowed". A reader
 * whose deployment had no Clerk publishable key was told to open their browser
 * settings — which cannot help — so retrying never worked.
 *
 * The invariant under test: **every** non-started outcome leaves a usable way in.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  runGoogleOAuthStart,
  type GoogleStartDeps,
  type GoogleStartFailure,
} from '../src/services/clerk.ts';

/** A Window stand-in: the enforcer only ever calls `.close()` on it. */
const fakePopup = { close: () => {} } as unknown as Window;

interface Harness {
  readonly deps: GoogleStartDeps;
  readonly calls: string[];
  readonly captured: unknown[];
}

/**
 * Build a dependency set whose every observable action is recorded, so a test can
 * assert both the returned reason and the side effects that must accompany it.
 */
function harness(overrides: Partial<Harness['deps']> = {}, opts: { authEnabled?: boolean; popupBlocked?: boolean; clerkFails?: boolean; noSignIn?: boolean; oauthThrows?: unknown | null; signIn?: unknown } = {}): Harness {
  const {
    authEnabled = true,
    popupBlocked = false,
    clerkFails = false,
    noSignIn = false,
    oauthThrows = null,
  } = opts;
  const calls: string[] = [];
  const captured: unknown[] = [];

  const signIn =
    noSignIn
      ? null
      : {
          authenticateWithPopup: async (o: unknown) => {
            calls.push('authenticateWithPopup');
            captured.push(o);
            if (oauthThrows) throw oauthThrows;
          },
        };

  const deps: GoogleStartDeps = {
    isAuthEnabled: () => {
      calls.push('isAuthEnabled');
      return authEnabled;
    },
    openPopup: () => {
      calls.push('openPopup');
      return popupBlocked ? null : fakePopup;
    },
    initClerk: async () => {
      calls.push('initClerk');
      if (clerkFails) throw new Error('clerk bundle 503');
    },
    getSignIn: () => {
      calls.push('getSignIn');
      return signIn;
    },
    openSignInFallback: () => {
      calls.push('openSignInFallback');
    },
    closePopup: () => {
      calls.push('closePopup');
    },
    onOAuthError: (err) => {
      calls.push('onOAuthError');
      captured.push(err);
    },
    options: { redirectUrl: 'https://example.test/bridge', redirectUrlComplete: 'https://example.test/done' },
    ...overrides,
  };

  return { deps, calls, captured };
}

describe('runGoogleOAuthStart', () => {
  it('reports success and opens no fallback when the popup transport takes over', async () => {
    const h = harness();
    const result = await runGoogleOAuthStart(h.deps);

    assert.equal(result.started, true);
    assert.equal(result.fallbackOpened, false);
    assert.equal(result.reason, undefined);
    assert.ok(h.calls.includes('authenticateWithPopup'));
    assert.ok(!h.calls.includes('openSignInFallback'));
  });

  it('passes the caller redirect URLs and the live popup to Clerk', async () => {
    const h = harness();
    await runGoogleOAuthStart(h.deps);

    const opts = h.captured[0] as Record<string, unknown>;
    assert.equal(opts.strategy, 'oauth_google');
    assert.equal(opts.redirectUrl, 'https://example.test/bridge');
    assert.equal(opts.redirectUrlComplete, 'https://example.test/done');
    assert.equal(opts.popup, fakePopup);
  });

  it('opens the popup before awaiting anything, so it stays in the user gesture', async () => {
    // A popup blocker only honours a window opened synchronously inside the click.
    // If any await moved ahead of `openPopup`, this order would invert and the
    // real-world symptom would be the popup error this whole file addresses.
    const h = harness();
    await runGoogleOAuthStart(h.deps);

    assert.ok(
      h.calls.indexOf('openPopup') < h.calls.indexOf('initClerk'),
      `openPopup must precede initClerk, got: ${h.calls.join(' -> ')}`,
    );
  });

  // The regression: all four of these used to return false with NO fallback.
  const failures: [string, Parameters<typeof harness>[1], GoogleStartFailure][] = [
    ['no Clerk publishable key', { authEnabled: false }, 'auth-disabled'],
    ['the browser blocked the popup', { popupBlocked: true }, 'popup-blocked'],
    ['the Clerk SDK failed to load', { clerkFails: true }, 'clerk-load-failed'],
    ['Clerk exposes no authenticateWithPopup', { noSignIn: true }, 'clerk-api-unavailable'],
    ['Clerk rejected the OAuth round-trip', { oauthThrows: new Error('unauthorized redirect') }, 'oauth-failed'],
  ];

  for (const [label, opts, expectedReason] of failures) {
    it(`names the real cause when ${label}`, async () => {
      const h = harness({}, opts);
      const result = await runGoogleOAuthStart(h.deps);

      assert.equal(result.started, false);
      assert.equal(result.reason, expectedReason);
    });

    it(`leaves a working sign-in surface when ${label}`, async () => {
      // This is the assertion that would have caught the original bug: the
      // reader must never be left on a dead button with only an error string.
      const h = harness({}, opts);
      const result = await runGoogleOAuthStart(h.deps);

      assert.equal(result.fallbackOpened, true);
      assert.ok(
        h.calls.includes('openSignInFallback'),
        `no fallback opened for ${label}; calls: ${h.calls.join(' -> ')}`,
      );
    });
  }

  it('closes the popup it opened when a later step fails', async () => {
    // Otherwise a blank window is left on screen with no content and no owner.
    for (const opts of [{ clerkFails: true }, { noSignIn: true }, { oauthThrows: new Error('x') }]) {
      const h = harness({}, opts);
      await runGoogleOAuthStart(h.deps);
      assert.ok(h.calls.includes('closePopup'), `popup leaked for ${JSON.stringify(opts)}`);
    }
  });

  it('reports a Clerk OAuth error to the reporter, not only to the log', async () => {
    const boom = new Error('redirect_url not allowed');
    const h = harness({}, { oauthThrows: boom });
    await runGoogleOAuthStart(h.deps);

    assert.ok(h.calls.includes('onOAuthError'));
    assert.ok(h.captured.includes(boom));
  });

  it('never opens a popup when auth is disabled', async () => {
    // No point spending the user's one popup-blocker tolerance on a window that
    // can never complete, when sign-in is not configured to begin with.
    const h = harness({}, { authEnabled: false });
    await runGoogleOAuthStart(h.deps);

    assert.ok(!h.calls.includes('openPopup'));
  });
});
