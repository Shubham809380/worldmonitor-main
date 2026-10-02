/**
 * `waitForClerkSessionToken()` must survive a session that is not there yet.
 *
 * Why this exists: the WorldGuard Google bridge reported "Google sign-in did not
 * complete. Please try again." for users who had in fact completed it. Clerk owns
 * the OAuth round-trip and sends the main window back to `?clerk=bridge`, which
 * is a FRESH page load — so the bridge read the session immediately after
 * `clerk.load()`, while Clerk was still resolving it from its cookie. The old
 * read sampled `clerkInstance.session` exactly once and treated null as failure.
 *
 * The other half of the bug was using the premium-API token path here at all.
 * `getClerkToken()` is tuned for signing many requests: it asks for the `convex`
 * template, and when its forced `skipCache` refresh fails it nulls a token it is
 * already holding, so a cold post-redirect load can return null with a perfectly
 * good token in hand. That is the wrong contract for "finish this sign-in".
 *
 * These tests pin the contract, not the implementation: resolve a late session,
 * don't hang on a genuinely signed-out visitor, and never ask for a template.
 */
import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  __setClerkInstanceForTests,
  waitForClerkSessionToken,
} from '../src/services/clerk.ts';

type Listener = () => void;

/** Minimal stand-in for the parts of a Clerk instance the helper touches. */
function makeClerk(options: { sessionDelayMs?: number; token?: string | null } = {}) {
  const listeners: Listener[] = [];
  const getTokenCalls: Array<Record<string, unknown> | undefined> = [];
  const state: { session: { getToken: (o?: Record<string, unknown>) => Promise<string | null> } | null } = {
    session: null,
  };

  const installSession = (): void => {
    state.session = {
      getToken: async (o?: Record<string, unknown>) => {
        getTokenCalls.push(o);
        return options.token === undefined ? 'session-jwt' : options.token;
      },
    };
    for (const listener of [...listeners]) listener();
  };

  const clerk = {
    get session() {
      return state.session;
    },
    addListener(listener: Listener) {
      listeners.push(listener);
      return () => {
        const i = listeners.indexOf(listener);
        if (i >= 0) listeners.splice(i, 1);
      };
    },
  };

  // Model Clerk resolving the session from its cookie a moment after load().
  if (options.sessionDelayMs !== undefined) {
    setTimeout(installSession, options.sessionDelayMs);
  } else {
    installSession();
  }

  return { clerk, getTokenCalls, listenerCount: () => listeners.length, installSession };
}

afterEach(() => {
  __setClerkInstanceForTests(null);
});

describe('waitForClerkSessionToken', () => {
  it('resolves a session that Clerk only makes available after load', async () => {
    const { clerk } = makeClerk({ sessionDelayMs: 5 });
    __setClerkInstanceForTests(clerk as never);

    const token = await waitForClerkSessionToken(1_000);

    assert.equal(token, 'session-jwt');
  });

  it('returns null instead of hanging when no session ever arrives', async () => {
    // A visitor who closed the popup, or whose session was revoked, must get a
    // prompt failure rather than an unresolved promise on the busy auth card.
    const listeners: Listener[] = [];
    const clerk = {
      get session() {
        return null;
      },
      addListener(listener: Listener) {
        listeners.push(listener);
        return () => {};
      },
    };
    __setClerkInstanceForTests(clerk as never);

    assert.equal(await waitForClerkSessionToken(30), null);
  });

  it('returns null when there is no Clerk instance at all', async () => {
    __setClerkInstanceForTests(null);
    assert.equal(await waitForClerkSessionToken(30), null);
  });

  it('picks up a session that materialises while the listener is attaching', async () => {
    // The window the re-check exists for: `clerk.session` is null at the
    // fast-path check, and the value is populated as a side effect of
    // registering the listener, so no *subsequent* callback is coming. A
    // listener-only implementation waits out the whole timeout here.
    const getTokenCalls: Array<Record<string, unknown> | undefined> = [];
    let session: { getToken: (o?: Record<string, unknown>) => Promise<string | null> } | null = null;
    const clerk = {
      get session() {
        return session;
      },
      addListener() {
        session = {
          getToken: async (o?: Record<string, unknown>) => {
            getTokenCalls.push(o);
            return 'raced-jwt';
          },
        };
        return () => {};
      },
    };
    __setClerkInstanceForTests(clerk as never);

    assert.equal(await waitForClerkSessionToken(1_000), 'raced-jwt');
    assert.equal(getTokenCalls.length, 1);
  });

  it('requests a plain session token, never a JWT template', async () => {
    // The bridge validates an ordinary Clerk session JWT. Asking for the
    // `convex` template would make completing a sign-in depend on an unrelated
    // dashboard setting, and would pass arguments the server has no use for.
    const { clerk, getTokenCalls } = makeClerk();
    __setClerkInstanceForTests(clerk as never);

    await waitForClerkSessionToken(1_000);

    assert.equal(getTokenCalls.length, 1);
    assert.equal(getTokenCalls[0], undefined);
  });

  it('detaches its listener so a later sign-out cannot resolve a settled promise', async () => {
    const { clerk, listenerCount } = makeClerk();
    __setClerkInstanceForTests(clerk as never);

    await waitForClerkSessionToken(1_000);

    assert.equal(listenerCount(), 0);
  });
});
