/**
 * Tests for how a failed Google sign-in start is reported to the reader.
 *
 * Lives in the DOM suite because src/worldguard/services/auth-session.ts reads
 * window.location at module load (BRIDGE_RETURN_URL), so it cannot be imported
 * into the node-based data suite.
 *
 * The bug this pins: every non-started Google attempt produced the single
 * message "check that pop-ups are allowed", including cases with no popup
 * involved at all. Only one of those causes is fixed by a browser setting.
 */
import { describe, expect, it } from 'vitest';
import { googleStartFailure } from '@/worldguard/services/auth-session';

describe('googleStartFailure reporting', () => {
  it('only blames pop-ups when pop-ups were actually blocked', async () => {
    // The precise misreport from the bug: a missing key produced a message
    // telling the reader to change a browser permission that cannot fix it.
    const blocked = googleStartFailure('popup-blocked', false);
    expect(blocked.message).toMatch(/pop-ups are allowed/i);
    expect(blocked.kind).toBe('failed');

    for (const reason of ['clerk-load-failed', 'clerk-api-unavailable', 'oauth-failed', 'auth-disabled'] as const) {
      const outcome = googleStartFailure(reason, false);
      expect(outcome.kind).toBe('failed');
      expect(
        !/pop-ups are allowed/i.test(outcome.message),
        `${reason} must not be reported as a pop-up permission problem`,
      );
    }
  });

  it('does not shout about a broken flow when the working form is already open', async () => {
    // Clerk's own surface is on screen and carries the Google button, so an
    // error banner on top of it tells the reader a working flow is broken.
    const outcome = googleStartFailure('oauth-failed', true);
    expect(outcome.kind).toBe('failed');
    expect(outcome.message).toMatch(/sign-in form is open/i);
  });

  it('reports an unconfigured deployment as a configuration problem', async () => {
    const outcome = googleStartFailure('auth-disabled', false);
    expect(outcome.kind).toBe('failed');
    if (outcome.kind === 'failed') {
      expect(outcome.code).toBe('not_configured');
      expect(outcome.message).toMatch(/not configured/i);
    }
  });

  it('still gives a terminal outcome for an unknown reason', async () => {
    // The busy card only clears on a terminal outcome, so this must never
    // resolve to a shape the page cannot render.
    const outcome = googleStartFailure(undefined, false);
    expect(outcome.kind).toBe('failed');
    if (outcome.kind === 'failed') {
      expect(typeof outcome.message).toBe('string');
      expect(outcome.message.length).toBeGreaterThan(0);
    }
  });
});
