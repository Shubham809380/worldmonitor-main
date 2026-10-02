/**
 * Tests that a 503 carrying a machine code is not reported as a retryable outage.
 *
 * `api/auth/clerk-bridge.ts` answers 503 for three conditions and reports which
 * one in the body: `not_configured` (no identity provider behind this
 * deployment), `auth_unavailable` and `identity_unavailable` (both genuinely
 * retryable). The client only ever looked at the status, so all three became
 * the same message, and the one that can never succeed by waiting was the one
 * that told the reader to wait.
 *
 * The server was already sending the honest signal; it was being discarded on
 * arrival.
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { AuthRequestError, bridgeClerkSession } from '@/worldguard/services/auth-api';

const ORIGINAL_FETCH = globalThis.fetch;

function respondWithStatus(status: number, error?: string): void {
  globalThis.fetch = (async () =>
    new Response(error === undefined ? null : JSON.stringify({ error }), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })) as typeof globalThis.fetch;
}

async function bridgeOutcome(): Promise<AuthRequestError> {
  const outcome = await bridgeClerkSession('clerk_session_token').catch(
    (error: unknown) => error,
  );
  expect(outcome).toBeInstanceOf(AuthRequestError);
  return outcome as AuthRequestError;
}

describe('a 503 that means "nothing is configured here" is not a retryable outage', () => {
  beforeEach(() => {
    // The bridge posts to /api/auth/clerk-bridge with a token cookie.
    globalThis.document = { cookie: 'wgu_abc.def' } as unknown as Document;
  });

  afterEach(() => {
    globalThis.fetch = ORIGINAL_FETCH;
  });

  it('reports not_configured when the server says so, not a temporary fault', async () => {
    respondWithStatus(503, 'not_configured');

    const error = await bridgeOutcome();

    expect(error.code).toBe('not_configured');
    expect(error.message).toMatch(/not configured/i);
    // The advice that made this unfixable: "try again shortly".
    expect(error.message).not.toMatch(/try again shortly/i);
  });

  it('still reports a genuinely retryable 503 as a temporary fault', async () => {
    respondWithStatus(503, 'auth_unavailable');

    const error = await bridgeOutcome();

    // This one IS worth retrying, so it must keep the retryable wording.
    expect(error.code).toBe('service_error');
    expect(error.message).toMatch(/try again shortly/i);
  });

  it('treats a 503 with no body as retryable rather than unconfigured', async () => {
    // A gateway in front of the deployment can answer 503 with no machine code.
    // Absent the code there is no evidence of misconfiguration, so retrying is
    // the honest reading.
    respondWithStatus(503);

    const error = await bridgeOutcome();

    expect(error.code).toBe('service_error');
    expect(error.message).toMatch(/try again shortly/i);
  });

  it('ignores an unrecognised body code and falls back to the status', async () => {
    // Only enumerated identifiers are honoured, so an unexpected value from
    // the server cannot steer the outcome.
    respondWithStatus(503, 'totally_unexpected_code');

    const error = await bridgeOutcome();

    expect(error.code).toBe('service_error');
  });

  it('keeps honouring the google_only_account message override', async () => {
    // The pre-existing override must survive alongside the new code path.
    respondWithStatus(409, 'google_only_account');

    const error = await bridgeOutcome();

    expect(error.code).toBe('conflict');
    expect(error.message).toMatch(/continue with google/i);
  });
});
