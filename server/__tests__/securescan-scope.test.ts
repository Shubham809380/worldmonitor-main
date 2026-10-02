// @vitest-environment node

/**
 * WM SecureScan — scope enforcement.
 *
 * These tests exist to make the platform's central claim checkable: an
 * assessment can only ever reach what the operator declared, and every failure
 * mode is *closed* rather than *permissive*. Each test below corresponds to a way
 * a scanner could quietly overstep, which is the failure this whole file guards.
 *
 * The path-prefix and wildcard-domain cases are here because `startsWith` on a
 * path is the single most common way an allowlist leaks: `/api/mcp` matches
 * `/api/mcp-evil`.
 */

import { describe, test, expect } from 'vitest';
import {
  ProbeRefusal,
  ScopeEnforcer,
  createScopedProbeClient,
  isLoopback,
} from '../securescan/scope';
import type { ProbeOutcome, ProbeRequest, ProbeClient } from '../securescan/repo';
import type { AssessmentScope } from '../securescan/types';

const CLOCK = (): string => '2026-01-01T00:00:00.000Z';

function scope(overrides: Partial<AssessmentScope> = {}): AssessmentScope {
  return {
    authorization: 'CONFIRMED',
    environment: 'PRODUCTION',
    allowedDomains: ['worldmonitor.app'],
    allowedPaths: [],
    allowedApiPaths: [],
    testAccountLabel: 'none',
    intensity: 'LOW',
    maxRequests: 10,
    requestTimeoutMs: 5000,
    collectEvidence: true,
    ...overrides,
  };
}

const GET: ProbeRequest = { method: 'GET', url: 'https://worldmonitor.app/api/health', headers: {} };

function refusalCode(fn: () => unknown): string {
  try {
    fn();
  } catch (error) {
    if (error instanceof ProbeRefusal) return error.code;
    throw error;
  }
  throw new Error('Expected a ProbeRefusal but the call succeeded');
}

describe('authorization gate', () => {
  test('refuses an unconfirmed assessment outright', () => {
    const enforcer = new ScopeEnforcer(scope({ authorization: 'UNCONFIRMED' }), CLOCK);
    const decision = enforcer.authorize();
    expect(decision.allowed).toBe(false);
    expect(decision.code).toBe('AUTHORIZATION_UNCONFIRMED');
  });

  test('a production target requires CONFIRMED, not a self-hosted declaration', () => {
    for (const authorization of ['SELF_HOSTED', 'LOCAL_ONLY', 'PENDING_REVIEW'] as const) {
      const enforcer = new ScopeEnforcer(scope({ authorization, environment: 'PRODUCTION' }), CLOCK);
      const decision = enforcer.authorize();
      expect(decision.allowed).toBe(false);
      expect(decision.code).toBe('AUTHORIZATION_UNCONFIRMED');
    }
  });

  test('a self-hosted target may be assessed under its own declaration', () => {
    const enforcer = new ScopeEnforcer(
      scope({ authorization: 'SELF_HOSTED', environment: 'SELF_HOSTED' }),
      CLOCK,
    );
    expect(enforcer.authorize().allowed).toBe(true);
  });

  test('an empty domain allowlist is refused for active work rather than treated as unrestricted', () => {
    const enforcer = new ScopeEnforcer(scope({ allowedDomains: [], intensity: 'LOW' }), CLOCK);
    const decision = enforcer.authorize();
    expect(decision.allowed).toBe(false);
    expect(decision.code).toBe('DOMAIN_ENTRIES_MISSING');
  });

  test('an empty allowlist is fine for a passive run because it sends nothing', () => {
    const enforcer = new ScopeEnforcer(
      scope({ allowedDomains: [], intensity: 'PASSIVE' }),
      CLOCK,
    );
    expect(enforcer.authorize().allowed).toBe(true);
    expect(enforcer.capability).toBe('NONE');
  });

  test('a negative request budget is rejected as misconfiguration', () => {
    const enforcer = new ScopeEnforcer(scope({ maxRequests: -1 }), CLOCK);
    expect(enforcer.authorize().code).toBe('BUDGET_EXHAUSTED');
  });
});

describe('intensity to capability mapping', () => {
  test('PASSIVE grants no outbound capability at all', () => {
    const enforcer = new ScopeEnforcer(scope({ intensity: 'PASSIVE' }), CLOCK);
    expect(enforcer.capability).toBe('NONE');
    expect(enforcer.admits('SINGLE_REQUEST')).toBe(false);
  });

  test('LOW grants exactly one request and refuses a bounded sequence', () => {
    const enforcer = new ScopeEnforcer(scope({ intensity: 'LOW' }), CLOCK);
    expect(enforcer.capability).toBe('SINGLE_REQUEST');
    expect(enforcer.admits('SINGLE_REQUEST')).toBe(true);
    expect(enforcer.admits('BOUNDED_SEQUENCE')).toBe(false);
  });

  test('a module is never granted more than the scope permits', () => {
    const enforcer = new ScopeEnforcer(scope({ intensity: 'LOW' }), CLOCK);
    expect(enforcer.resolveCapability('BOUNDED_SEQUENCE')).toBe('SINGLE_REQUEST');
    expect(enforcer.resolveCapability('NONE')).toBe('NONE');
  });

  test('PASSIVE refuses an actual request with an actionable reason', () => {
    const enforcer = new ScopeEnforcer(scope({ intensity: 'PASSIVE' }), CLOCK);
    expect(refusalCode(() => enforcer.authorizeRequest(GET))).toBe('INTENSITY_EXCEEDED');
  });
});

describe('host and scheme enforcement', () => {
  const enforcer = (): ScopeEnforcer => new ScopeEnforcer(scope(), CLOCK);

  test('permits an exact allowlisted host', () => {
    const url = enforcer().authorizeRequest(GET);
    expect(url.hostname).toBe('worldmonitor.app');
  });

  test('refuses a host that is not on the list', () => {
    const url = { method: 'GET', url: 'https://evil.example/api/health', headers: {} };
    expect(refusalCode(() => enforcer().authorizeRequest(url))).toBe('UNAUTHORIZED_TARGET');
  });

  test('a suffix must not be mistaken for a subdomain match', () => {
    // `notworldmonitor.app` shares a suffix with the allowlist entry but is a
    // different registrable host.
    const url = { method: 'GET', url: 'https://notworldmonitor.app/api/health', headers: {} };
    expect(refusalCode(() => enforcer().authorizeRequest(url))).toBe('UNAUTHORIZED_TARGET');
  });

  test('a wildcard entry matches the suffix itself and its subdomains only', () => {
    const wildcard = new ScopeEnforcer(scope({ allowedDomains: ['*.worldmonitor.app'] }), CLOCK);
    expect(() => wildcard.authorizeRequest(GET)).not.toThrow();
    expect(() =>
      wildcard.authorizeRequest({ method: 'GET', url: 'https://api.worldmonitor.app/x', headers: {} }),
    ).not.toThrow();
    expect(refusalCode(() =>
      wildcard.authorizeRequest({ method: 'GET', url: 'https://worldmonitor.app.evil.test/x', headers: {} }),
    )).toBe('UNAUTHORIZED_TARGET');
  });

  test('refuses plaintext http to a remote host', () => {
    const url = { method: 'GET', url: 'http://worldmonitor.app/api/health', headers: {} };
    expect(refusalCode(() => enforcer().authorizeRequest(url))).toBe('SCHEME_NOT_ALLOWED');
  });

  test('permits loopback over http so a local self-test can run', () => {
    const local = new ScopeEnforcer(
      scope({ allowedDomains: ['localhost'], environment: 'LOCAL', authorization: 'LOCAL_ONLY' }),
      CLOCK,
    );
    expect(() =>
      local.authorizeRequest({ method: 'GET', url: 'http://localhost:3000/api/health', headers: {} }),
    ).not.toThrow();
  });

  test('a bare asterisk domain entry cannot match everything', () => {
    const sloppy = new ScopeEnforcer(scope({ allowedDomains: ['*'] }), CLOCK);
    expect(refusalCode(() =>
      sloppy.authorizeRequest({ method: 'GET', url: 'https://anything.test/x', headers: {} }),
    )).toBe('UNAUTHORIZED_TARGET');
  });

  test('an unparseable URL fails closed', () => {
    const url = { method: 'GET', url: 'not-a-url', headers: {} };
    expect(refusalCode(() => enforcer().authorizeRequest(url))).toBe('UNAUTHORIZED_TARGET');
  });
});

describe('path prefix enforcement', () => {
  test('matches a prefix at a segment boundary', () => {
    const scoped = new ScopeEnforcer(scope({ allowedPaths: ['/api/mcp'] }), CLOCK);
    expect(() =>
      scoped.authorizeRequest({ method: 'GET', url: 'https://worldmonitor.app/api/mcp/tools', headers: {} }),
    ).not.toThrow();
  });

  test('refuses a sibling path that merely starts with the prefix', () => {
    const scoped = new ScopeEnforcer(scope({ allowedPaths: ['/api/mcp'] }), CLOCK);
    const sibling = { method: 'GET', url: 'https://worldmonitor.app/api/mcp-evil/tools', headers: {} };
    expect(refusalCode(() => scoped.authorizeRequest(sibling))).toBe('PATH_OUT_OF_SCOPE');
  });

  test('refuses a traversal that escapes the prefix', () => {
    const scoped = new ScopeEnforcer(scope({ allowedPaths: ['/api/mcp'] }), CLOCK);
    const traversal = { method: 'GET', url: 'https://worldmonitor.app/api/mcp/../admin', headers: {} };
    expect(refusalCode(() => scoped.authorizeRequest(traversal))).not.toBe('UNAUTHORIZED_TARGET');
  });

  test('api paths and page paths are both honoured', () => {
    const scoped = new ScopeEnforcer(
      scope({ allowedPaths: ['/securescan'], allowedApiPaths: ['/api/health'] }),
      CLOCK,
    );
    expect(() =>
      scoped.authorizeRequest({ method: 'GET', url: 'https://worldmonitor.app/api/health', headers: {} }),
    ).not.toThrow();
    expect(() =>
      scoped.authorizeRequest({ method: 'GET', url: 'https://worldmonitor.app/securescan/assessments', headers: {} }),
    ).not.toThrow();
    expect(refusalCode(() =>
      scoped.authorizeRequest({ method: 'GET', url: 'https://worldmonitor.app/api/other', headers: {} }),
    )).toBe('PATH_OUT_OF_SCOPE');
  });
});

describe('request budget', () => {
  test('refuses once the budget is exhausted', () => {
    const enforcer = new ScopeEnforcer(scope({ maxRequests: 2 }), CLOCK);
    enforcer.authorizeRequest(GET);
    enforcer.authorizeRequest(GET);
    expect(enforcer.issued).toBe(2);
    expect(refusalCode(() => enforcer.authorizeRequest(GET))).toBe('BUDGET_EXHAUSTED');
  });

  test('a refused request does not consume budget', () => {
    const enforcer = new ScopeEnforcer(scope({ maxRequests: 1, allowedPaths: ['/api/allowed'] }), CLOCK);
    // Refused on path: must not count.
    expect(refusalCode(() =>
      enforcer.authorizeRequest({ method: 'GET', url: 'https://worldmonitor.app/api/other', headers: {} }),
    )).toBe('PATH_OUT_OF_SCOPE');
    expect(enforcer.issued).toBe(0);
    // The real request still fits in the budget of 1.
    expect(() =>
      enforcer.authorizeRequest({ method: 'GET', url: 'https://worldmonitor.app/api/allowed', headers: {} }),
    ).not.toThrow();
    expect(enforcer.issued).toBe(1);
  });

  test('a transport-level failure is refunded', () => {
    const enforcer = new ScopeEnforcer(scope({ maxRequests: 1 }), CLOCK);
    enforcer.authorizeRequest(GET);
    expect(enforcer.issued).toBe(1);
    enforcer.refundRequest();
    expect(enforcer.issued).toBe(0);
    expect(() => enforcer.authorizeRequest(GET)).not.toThrow();
  });

  test('remaining budget never goes negative', () => {
    const enforcer = new ScopeEnforcer(scope({ maxRequests: 1 }), CLOCK);
    enforcer.authorizeRequest(GET);
    enforcer.refundRequest();
    enforcer.refundRequest();
    expect(enforcer.remaining).toBe(1);
  });
});

describe('scoped probe client', () => {
  test('returns a refusal without touching the transport for an out-of-scope host', async () => {
    const enforcer = new ScopeEnforcer(scope(), CLOCK);
    let transportCalls = 0;
    const client = createScopedProbeClient(enforcer, async () => {
      transportCalls += 1;
      return { kind: 'response', response: { status: 200, headers: {}, body: '', durationMs: 1 } };
    });

    const outcome = await client.send({ method: 'GET', url: 'https://evil.test/x', headers: {} });
    expect(outcome.kind).toBe('refused');
    expect(transportCalls).toBe(0);
    expect(enforcer.issued).toBe(0);
  });

  test('passes the scope timeout to the transport, not the request budget', async () => {
    const enforcer = new ScopeEnforcer(scope({ maxRequests: 250, requestTimeoutMs: 1500 }), CLOCK);
    let seenTimeout: number | null = null;
    const client = createScopedProbeClient(enforcer, async (_request, timeoutMs) => {
      seenTimeout = timeoutMs;
      return { kind: 'response', response: { status: 204, headers: {}, body: '', durationMs: 1 } };
    });

    await client.send(GET);
    expect(seenTimeout).toBe(1500);
  });

  test('refunds the budget slot when the transport errors', async () => {
    const enforcer = new ScopeEnforcer(scope({ maxRequests: 1 }), CLOCK);
    const client: ProbeClient = createScopedProbeClient(enforcer, async (): Promise<ProbeOutcome> => ({
      kind: 'error',
      message: 'connection reset',
    }));

    const outcome = await client.send(GET);
    expect(outcome.kind).toBe('error');
    expect(enforcer.issued).toBe(0);
  });

  test('a refused request is not retried by the client', async () => {
    const enforcer = new ScopeEnforcer(scope({ allowedPaths: ['/api/only'] }), CLOCK);
    let transportCalls = 0;
    const client = createScopedProbeClient(enforcer, async () => {
      transportCalls += 1;
      return { kind: 'response', response: { status: 200, headers: {}, body: '', durationMs: 1 } };
    });

    const outcome = await client.send({ method: 'GET', url: 'https://worldmonitor.app/other', headers: {} });
    expect(outcome.kind).toBe('refused');
    expect(transportCalls).toBe(0);
  });
});

describe('loopback classification', () => {
  test('recognises the loopback forms a dev server actually binds', () => {
    for (const host of ['localhost', 'LOCALHOST', '127.0.0.1', '::1', '[::1]']) {
      expect(isLoopback(host)).toBe(true);
    }
  });

  test('does not treat a lookalike host as loopback', () => {
    for (const host of ['localhost.evil.test', '127.0.0.1.evil.test', '127001', '0.0.0.0']) {
      expect(isLoopback(host)).toBe(false);
    }
  });
});
