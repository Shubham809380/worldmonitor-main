/**
 * Tests that a server-side auth fault is not reported as a reader connection fault.
 *
 * The bug this pins: `codeForStatus` ended in `return 'network'`, so every status
 * it did not enumerate — 500, 502, 503, 504 — produced "We could not reach the
 * authentication service. Check your connection." A response arriving at all
 * proves the network worked, so that advice was never actionable: the reader
 * checks a working connection and signs in to the same server error. It is the
 * same class of defect as the Google popup message, which blamed a browser
 * setting for Clerk load, API and OAuth failures.
 *
 * `describeAuthError` had the same flaw for any non-AuthRequestError, which is
 * what a bug in our own code throws.
 *
 * Exercised through the real `request()` path with a stubbed `fetch`, so the
 * status-to-code mapping is tested as shipped rather than through an export.
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import {
  AuthRequestError,
  describeAuthError,
  loginWithPassword,
  setAuthTokenProvider,
} from '@/worldguard/services/auth-api';

const ORIGINAL_FETCH = globalThis.fetch;

/** Answer with a bare status and no body, the way a gateway or crash does. */
function respondWithStatus(status: number): void {
  globalThis.fetch = (async () =>
    new Response(null, { status })) as typeof globalThis.fetch;
}

describe('server-side auth faults are not reported as connection faults', () => {
  beforeEach(() => {
    setAuthTokenProvider(null);
  });

  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
    setAuthTokenProvider(null);
  });

  for (const status of [500, 502, 503, 504]) {
    it(`does not tell the reader to check their connection for a ${status}`, async () => {
      respondWithStatus(status);

      const outcome = await loginWithPassword('reader@example.com', 'pw').catch(
        (error: unknown) => error,
      );

      // The message must not be the connection advice, because the connection
      // is provably fine: a response came back.
      expect(outcome).toBeInstanceOf(AuthRequestError);
      const error = outcome as AuthRequestError;
      expect(error.message).not.toMatch(/check your connection/i);
      expect(error.message).toMatch(/having problems|try again shortly/i);
      expect(error.code).not.toBe('network');
      expect(error.code).toBe('service_error');
    });
  }

  it('still reports a real transport failure as a connection problem', async () => {
    // The one case the connection message is correct for: fetch itself threw,
    // so nothing ever reached the server.
    globalThis.fetch = (async () => {
      throw new TypeError('Failed to fetch');
    }) as typeof globalThis.fetch;

    const outcome = await loginWithPassword('reader@example.com', 'pw').catch(
      (error: unknown) => error,
    );

    expect(outcome).toBeInstanceOf(AuthRequestError);
    const error = outcome as AuthRequestError;
    expect(error.code).toBe('network');
    expect(error.message).toMatch(/check your connection/i);
  });

  it('does not blame the connection for a bug in our own code', () => {
    // Anything that is not an AuthRequestError reached this from our code, not
    // from the network.
    expect(describeAuthError(new TypeError('x is not a function'))).not.toMatch(
      /check your connection/i,
    );
    expect(describeAuthError('a string')).not.toMatch(/check your connection/i);
    expect(describeAuthError(undefined)).not.toMatch(/check your connection/i);
  });

  it('does not let a throwing token provider escape as a connection fault', async () => {
    // A token provider reads a session from a third-party SDK and can throw.
    // That used to bypass every mapping and arrive as a bare error.
    setAuthTokenProvider(async () => {
      throw new Error('Clerk session unavailable');
    });
    respondWithStatus(401);

    const outcome = await import('@/worldguard/services/auth-api').then((m) =>
      m.fetchSession().catch((error: unknown) => error),
    );

    expect(outcome).toBeInstanceOf(AuthRequestError);
    // Mapped through the normal path, so it is an auth verdict and not a lie
    // about the network.
    expect((outcome as AuthRequestError).code).toBe('invalid_credentials');
  });
});
