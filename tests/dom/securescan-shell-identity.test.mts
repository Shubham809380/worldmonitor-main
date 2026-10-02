/**
 * SecureScan shell identity footer and failure mapping.
 *
 * The sidebar and the refusal screen are the two places where a security
 * product can state a falsehood the reader will act on: "you are not signed
 * in" when they are, and "the backend is down" when it answered a refusal.
 * Both are decided from one field each, so both are pinned here.
 */
import { describe, expect, it } from 'vitest';

import { html, mount } from '@/securescan/components/dom';
import { failureState, shell } from '@/securescan/app';
import { parseRoute } from '@/securescan/routing';

const EMPTY = html`<p>body</p>`;

function renderFooter(identity: {
  signedIn: boolean;
  userId: string | null;
  role: string | null;
}): string {
  const host = document.createElement('div');
  mount(host, shell(parseRoute('#/dashboard'), identity, EMPTY));
  return host.innerHTML;
}

describe('shell identity footer', () => {
  it('names a signed-in member by their role', () => {
    const html = renderFooter({ signedIn: true, userId: 'user-analyst', role: 'SECURITY_ANALYST' });
    expect(html).toContain('Signed in');
    // `roleBadge` renders the human label, not the stored role string.
    expect(html).toContain('ANALYST');
    expect(html).not.toContain('Not authenticated');
  });

  it('does not claim a signed-in non-member is unauthenticated', () => {
    // The regression. `signedIn` is true and `role` is null here, and the
    // footer used to branch on `role` alone -- so a real, signed-in account
    // without a SecureScan grant was told it had no session.
    const html = renderFooter({ signedIn: true, userId: 'user-nobody', role: null });
    expect(html).not.toContain('Not authenticated');
    expect(html).toContain('Signed in');
    expect(html).toContain('No SecureScan role');
  });

  it('reports a genuine absence of session as unauthenticated', () => {
    const html = renderFooter({ signedIn: false, userId: null, role: null });
    expect(html).toContain('Not authenticated');
    expect(html).not.toContain('Signed in');
  });

  it('never prints the literal placeholder "unknown" as a subject', () => {
    // The fallback identity used to be `{ userId: 'unknown' }`, which rendered
    // the string "unknown" as if it were the user's account subject.
    for (const identity of [
      { signedIn: false, userId: null, role: null },
      { signedIn: true, userId: 'user-nobody', role: null },
    ]) {
      const html = renderFooter(identity);
      expect(html).not.toMatch(/>unknown</);
    }
  });

  it('lists every section regardless of role, because navigation is not authorization', () => {
    const html = renderFooter({ signedIn: true, userId: 'user-v', role: 'VIEWER' });
    expect(html).toContain('Administration');
    expect(html).toContain('Audit Center');
  });
});

describe('failure mapping', () => {
  function text(kind: string): string {
    const host = document.createElement('div');
    mount(host, failureState(kind, 'server message'));
    return host.textContent ?? '';
  }

  it('tells a signed-in non-member to get a grant, not to check the backend', () => {
    const body = text('no_membership');
    expect(body).toContain('NO SECURESCAN MEMBERSHIP');
    expect(body).not.toContain('BACKEND UNAVAILABLE');
  });

  it('distinguishes an anonymous caller from a member with the wrong role', () => {
    expect(text('unauthenticated')).toContain('AUTHENTICATION REQUIRED');
    expect(text('forbidden')).toContain('NOT PERMITTED');
  });

  it('claims a backend outage only when that is what happened', () => {
    expect(text('unavailable')).toContain('BACKEND UNAVAILABLE');
    expect(text('not_found')).toContain('NOT FOUND');
  });

  it('keeps every failure kind on a distinct screen', () => {
    const kinds = [
      'unauthenticated',
      'no_membership',
      'forbidden',
      'not_found',
      'unavailable',
      'unexpected',
    ];
    const rendered = kinds.map((k) => text(k));
    expect(new Set(rendered).size).toBe(kinds.length);
  });
});
