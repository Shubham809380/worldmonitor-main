// @vitest-environment node
/**
 * Authorization and audit tests.
 *
 * These are the tests the product's credibility rests on. A security assessment
 * console that leaks findings to viewers, lets a viewer start a scan, or
 * permits an analyst to escalate to admin is worse than no console, so each
 * rule below is pinned by a test that fails if the rule is weakened.
 *
 * The negative cases are the point. A test that only proves an admin can do
 * something proves nothing about access control.
 */

import { describe, test, expect } from 'vitest';
import {
  ACTIONS,
  ROLES,
  authorize,
  authorizeFindingTransition,
  can,
  permissionsFor,
  rolesAllowing,
  validateTriageInput,
  type Action,
  type Actor,
  type Role,
} from '../securescan/identity';
import * as identity from '../securescan/identity';
import {
  AUDIT_GENESIS,
  appendAuditEntry,
  digestOf,
  redact,
  recordAllowed,
  recordDenied,
  requiresAudit,
  verifyAuditChain,
  type AuditEntry,
} from '../securescan/audit';

const NOW = '2026-02-01T00:00:00.000Z';

function actor(role: Role, userId = `user-${role.toLowerCase()}`): Actor {
  return { userId, role };
}

const admin = actor('ADMIN', 'u-admin');
const analyst = actor('SECURITY_ANALYST', 'u-analyst');
const otherAnalyst = actor('SECURITY_ANALYST', 'u-analyst-2');
const viewer = actor('VIEWER', 'u-viewer');

describe('roles and the permission matrix', () => {
test('there is no default role, and a missing grant is not a read', () => {
    // SecureScan used to export `DEFAULT_ROLE = 'VIEWER'`, justified as least
    // privilege. That was wrong about the cost of a read: assessment results,
    // evidence payloads, target configuration and finding detail are the
    // sensitive data, and reads are workspace-wide within the team. A default
    // handed every self-registered account all of it.
    expect('DEFAULT_ROLE' in identity).toBe(false);
    // A VIEWER is still a legitimate granted role, and still read-only.
    expect(can('VIEWER', 'finding:read')).toBe(true);
    expect(can('VIEWER', 'assessment:start')).toBe(false);
    // The refusal itself lives at the boundary, in
    // `convex/securescan/_shared.ts` -> `requireMemberRole`, which throws
    // SECURESCAN_NO_MEMBERSHIP for a caller with no membership row.
});


  test('VIEWER may read but never write, run, or administer', () => {
    const forbidden: Action[] = [
      'assessment:create',
      'assessment:start',
      'assessment:cancel',
      'assessment:delete',
      'finding:triage',
      'finding:verify',
      'finding:dismiss',
      'finding:reopen',
      'evidence:attach',
      'runtime:execute',
      'remediation:write',
      'retest:execute',
      'report:generate',
      'admin:users',
      'admin:audit',
      'user:role',
      'user:session',
      'target:manage',
    ];
    for (const action of forbidden) {
      expect(can('VIEWER', action), `VIEWER must not hold ${action}`).toBe(false);
    }
  });

  test('VIEWER can still read every domain it needs for monitoring', () => {
    const readable: Action[] = [
      'assessment:read',
      'finding:read',
      'evidence:read',
      'runtime:read',
      'remediation:read',
      'retest:read',
      'report:read',
      'target:read',
    ];
    for (const action of readable) {
      expect(can('VIEWER', action), `VIEWER should read ${action}`).toBe(true);
    }
  });

  test('SECURITY_ANALYST can assess and triage but cannot manage users or roles', () => {
    expect(can('SECURITY_ANALYST', 'assessment:start')).toBe(true);
    expect(can('SECURITY_ANALYST', 'finding:verify')).toBe(true);
    expect(can('SECURITY_ANALYST', 'runtime:execute')).toBe(true);
    expect(can('SECURITY_ANALYST', 'retest:execute')).toBe(true);
    // The privilege-escalation edge: an analyst who could change roles could
    // simply promote themselves.
    expect(can('SECURITY_ANALYST', 'admin:users')).toBe(false);
    expect(can('SECURITY_ANALYST', 'user:role')).toBe(false);
    expect(can('SECURITY_ANALYST', 'user:session')).toBe(false);
    expect(can('SECURITY_ANALYST', 'admin:settings')).toBe(false);
  });

  test('ADMIN holds every declared action', () => {
    for (const action of ACTIONS) {
      expect(can('ADMIN', action), `ADMIN should hold ${action}`).toBe(true);
    }
    expect(permissionsFor('ADMIN').length).toBe(ACTIONS.length);
  });

  test('a role with no permissions for an action reports which roles do', () => {
    expect(rolesAllowing('admin:users')).toEqual(['ADMIN']);
    expect(rolesAllowing('assessment:start').sort()).toEqual(['ADMIN', 'SECURITY_ANALYST']);
  });
});

describe('authorize()', () => {
  test('an unauthenticated request is refused before the role gate', () => {
    const decision = authorize(null, 'finding:read');
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.code).toBe('AUTH_REQUIRED');
  });

  test('an empty userId is treated as unauthenticated', () => {
    const decision = authorize({ userId: '', role: 'ADMIN' }, 'finding:read');
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.code).toBe('AUTH_REQUIRED');
  });

  test('a viewer attempting to start an assessment is denied with a role reason', () => {
    const decision = authorize(viewer, 'assessment:start');
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) {
      expect(decision.code).toBe('ROLE_FORBIDDEN');
      expect(decision.requiredRoles).toEqual(['ADMIN', 'SECURITY_ANALYST']);
    }
  });
});

describe('resource-level authorization (IDOR)', () => {
  const owned = { id: 'ASM-1', kind: 'assessment' as const, ownerId: 'u-analyst' };
  const foreign = { id: 'ASM-2', kind: 'assessment' as const, ownerId: 'u-someone-else' };

  test('the owner may mutate their own resource', () => {
    expect(authorize(analyst, 'assessment:cancel', owned).allowed).toBe(true);
  });

  test('an analyst cannot cancel an assessment they do not own', () => {
    const decision = authorize(otherAnalyst, 'assessment:cancel', foreign);
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) {
      expect(decision.code).toBe('NOT_RESOURCE_OWNER');
      // The message must not leak the owner's identity.
      expect(decision.reason).not.toContain('u-someone-else');
    }
  });

  test('ADMIN overrides ownership, because support needs it', () => {
    expect(authorize(admin, 'assessment:cancel', foreign).allowed).toBe(true);
  });

  test('reads stay workspace-wide so peers can review each other', () => {
    expect(authorize(viewer, 'finding:read', foreign).allowed).toBe(true);
    expect(authorize(analyst, 'evidence:read', foreign).allowed).toBe(true);
  });

  test('a resource with no owner is not owner-gated', () => {
    expect(authorize(analyst, 'assessment:cancel', { id: 'ASM-3', kind: 'assessment', ownerId: null }).allowed).toBe(true);
  });

  test('a viewer is refused on ownership grounds only after the role gate', () => {
    // Both would deny, but the role is the more informative reason and must win,
    // because a viewer should never learn whether a resource exists.
    const decision = authorize(viewer, 'assessment:cancel', foreign);
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.code).toBe('ROLE_FORBIDDEN');
  });
});

describe('finding triage authorization', () => {
  const candidate = { id: 'FND-1', state: 'CANDIDATE' as const, ownerId: 'u-analyst' };

  test('validation is a two-step edge, never a shortcut', () => {
    // CANDIDATE -> VALIDATED and CANDIDATE -> VERIFIED are both illegal. The
    // VALIDATING step is where `validateFinding` attaches and checks evidence,
    // so a candidate that skipped it would reach VERIFIED with nothing proven.
    expect(authorizeFindingTransition(analyst, candidate, 'VERIFIED').allowed).toBe(false);
    expect(authorizeFindingTransition(analyst, candidate, 'VALIDATED').allowed).toBe(false);
    expect(authorizeFindingTransition(analyst, candidate, 'VALIDATING').allowed).toBe(true);

    const validating = { ...candidate, state: 'VALIDATING' as const };
    expect(authorizeFindingTransition(analyst, validating, 'VALIDATED').allowed).toBe(true);
  });

  test('an illegal state change is refused even with the right role', () => {
    const decision = authorizeFindingTransition(admin, candidate, 'FIXED');
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.code).toBe('INVALID_TRANSITION');
  });

  test('a viewer cannot dismiss a finding', () => {
    const decision = authorizeFindingTransition(viewer, candidate, 'FALSE_POSITIVE');
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.code).toBe('ROLE_FORBIDDEN');
  });

  test('an analyst cannot dismiss another analyst finding', () => {
    const decision = authorizeFindingTransition(otherAnalyst, candidate, 'FALSE_POSITIVE');
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.code).toBe('NOT_RESOURCE_OWNER');
  });

  test('a dismissed finding can be reopened without editing history', () => {
    const dismissed = { id: 'FND-1', state: 'FALSE_POSITIVE' as const, ownerId: 'u-analyst' };
    expect(authorizeFindingTransition(analyst, dismissed, 'CANDIDATE').allowed).toBe(true);
  });
});

describe('triage input validation', () => {
  test('a false-positive decision without a reason is rejected', () => {
    const errors = validateTriageInput({ to: 'FALSE_POSITIVE', reason: 'no' });
    expect(errors).toHaveLength(1);
    expect(errors[0]?.field).toBe('reason');
  });

  test('an accepted-risk decision demands a real justification', () => {
    // Both dismissal paths require a reason, and both are checked the same way.
    expect(validateTriageInput({ to: 'ACCEPTED_RISK', reason: 'ok' })).toHaveLength(1);
    expect(validateTriageInput({ to: 'ACCEPTED_RISK', reason: 'risk accepted by the platform owner' })).toHaveLength(0);
  });

  test('a normal verification note needs no minimum length', () => {
    expect(validateTriageInput({ to: 'VERIFIED', reason: 'ok' })).toHaveLength(0);
  });

  test('an overlong reason is rejected', () => {
    expect(validateTriageInput({ to: 'VERIFIED', reason: 'x'.repeat(2001) })).toHaveLength(1);
  });
});

describe('audit redaction', () => {
  test('a bearer token in a detail string is removed', () => {
    expect(redact('failed with Authorization: Bearer abcdef1234567890')).not.toContain('abcdef1234567890');
  });

  test('a JWT is removed', () => {
    expect(redact('token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefgh')).not.toContain('eyJhbGciOiJIUzI1NiJ9');
  });

  test('a secret assignment keeps the variable name but loses the value', () => {
    const out = redact('WM_SESSION_SECRET=super-secret-value');
    expect(out).toContain('WM_SESSION_SECRET');
    expect(out).not.toContain('super-secret-value');
  });

  test('a private key block is removed', () => {
    const pem = '-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----';
    expect(redact(`leaked ${pem}`)).not.toContain('MIIabc');
  });

  test('an open-source token is removed', () => {
    expect(redact('used ghp_abcdefghijklmnopqrstuvwxyz0123')).not.toContain('ghp_abcdefghijklmnopqrstuvwxyz0123');
  });

  test('ordinary prose is untouched', () => {
    expect(redact('CSP missing base-uri on the OAuth callback route')).toBe('CSP missing base-uri on the OAuth callback route');
  });

  // The rules above only ever exercised SHOUTING_CASE names. These pin the
  // spellings that were leaking verbatim into an append-only, hash-anchored log.
  test('a lowercase credential name is redacted, not just an uppercase one', () => {
    const out = redact('connect failed: api_key=super-secret-value');
    expect(out).toContain('api_key');
    expect(out).not.toContain('super-secret-value');
  });

  test('a camelCase credential name is redacted', () => {
    const out = redact('retrying with ApiKey=super-secret-value');
    expect(out).toContain('ApiKey');
    expect(out).not.toContain('super-secret-value');
  });

  test('a credential header that is not authorization or cookie is redacted', () => {
    const out = redact('request headers were {"x-api-key": "abcdef1234567890"}');
    expect(out).not.toContain('abcdef1234567890');
  });

  test('a cloud access key id is redacted even with no variable name', () => {
    expect(redact('auth failed for AKIAIOSFODNN7EXAMPLE')).not.toContain('AKIAIOSFODNN7EXAMPLE');
  });

  test('a named cloud secret is redacted', () => {
    const out = redact('aws_secret_access_key=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY');
    expect(out).toContain('aws_secret_access_key');
    expect(out).not.toContain('wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY');
  });

  test('a credential pasted into prose as a copula is redacted', () => {
    expect(redact('operator note: the password is hunter2000')).not.toContain('hunter2000');
  });

  // An earlier pattern can redact a value before the name=value rule sees it.
  // Without the marker guard the second pass re-redacted it and left a dangling
  // bracket in the stored entry.
  test('overlapping rules redact once and do not corrupt the value', () => {
    const out = redact('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE');
    expect(out).not.toContain('AKIAIOSFODNN7EXAMPLE');
    // Exactly one marker: the AWS rule redacts the value, then the name=value
    // rule must leave that marker alone rather than re-redacting it.
    expect(out.match(/\[REDACTED/g) ?? []).toHaveLength(1);
    expect(out).not.toContain(']]');
    expect(out).toBe('AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key-id]');
  });

  test('diagnostic prose survives the broader name rule', () => {
    for (const line of [
      'Target https://example.com/api/health returned 200 in 143ms',
      'Retest evidence digest 9f2a4c1b8e7d6a5f matched',
      'Blocked SSRF attempt to 169.254.169.254 refused as UNAUTHORIZED_TARGET',
      'Finding severity raised MEDIUM to HIGH after manual review',
      'Cookie scanning skipped for third-party asset on cdn.example.com',
    ]) {
      expect(redact(line)).toBe(line);
    }
  });
});

describe('audit hash chain', () => {
  function build(count: number): AuditEntry[] {
    const entries: AuditEntry[] = [];
    let previous: string | null = null;
    for (let i = 0; i < count; i += 1) {
      const entry = appendAuditEntry(
        recordAllowed(analyst, 'finding:verify', 'finding', `FND-${i}`, `verified finding ${i}`),
        { now: NOW, previousDigest: previous, sequence: i + 1 },
      );
      entries.push(entry);
      previous = entry.digest;
    }
    return entries;
  }

  test('an intact chain verifies', () => {
    expect(verifyAuditChain(build(5))).toBeNull();
  });

  test('an edited entry breaks the chain at that index', () => {
    const entries = build(5);
    (entries[2] as { detail?: string }).detail = 'silently reworded';
    expect(verifyAuditChain(entries)).toBe(2);
  });

  test('a deleted entry breaks the chain at the seam', () => {
    const entries = build(5);
    entries.splice(2, 1);
    expect(verifyAuditChain(entries)).not.toBeNull();
  });

  test('the first entry links to the genesis marker', () => {
    const entries = build(1);
    expect(entries[0]?.previousDigest).toBe(AUDIT_GENESIS);
  });

  test('digests are deterministic and content-sensitive', () => {
    expect(digestOf('abc', 'payload')).toBe(digestOf('abc', 'payload'));
    expect(digestOf('abc', 'payload')).not.toBe(digestOf('abc', 'payload2'));
    expect(digestOf('abc', 'payload')).not.toBe(digestOf('abd', 'payload'));
  });
});

describe('audit coverage of sensitive actions', () => {
  test('every mutating or administrative action is auditable', () => {
    const mutating: Action[] = [
      'assessment:create',
      'assessment:start',
      'assessment:cancel',
      'assessment:delete',
      'target:manage',
      'finding:triage',
      'finding:verify',
      'finding:dismiss',
      'finding:reopen',
      'evidence:attach',
      'runtime:execute',
      'remediation:write',
      'retest:execute',
      'report:generate',
      'admin:users',
      'admin:audit',
      'admin:settings',
      'user:role',
      'user:session',
    ];
    for (const action of mutating) {
      expect(requiresAudit(action), `${action} must be auditable`).toBe(true);
    }
  });

  test('reads are not required to be auditable, to keep the log signal-rich', () => {
    for (const action of ROLES.length > 0 ? (['finding:read', 'assessment:read', 'evidence:read'] as Action[]) : []) {
      expect(requiresAudit(action)).toBe(false);
    }
  });

  test('a denial is recorded with its code and reason', () => {
    const decision = authorize(viewer, 'assessment:start');
    if (decision.allowed) throw new Error('expected a denial');
    const entry = recordDenied(viewer, 'assessment:start', decision, 'assessment', 'ASM-9');
    expect(entry.outcome).toBe('DENIED');
    expect(entry.code).toBe('ROLE_FORBIDDEN');
    expect(entry.detail).toContain('VIEWER');
  });

  test('an anonymous denial is attributed to anonymous, not to a guessed user', () => {
    const decision = authorize(null, 'finding:read');
    if (decision.allowed) throw new Error('expected a denial');
    const entry = recordDenied(null, 'finding:read', decision, 'finding', 'FND-1');
    expect(entry.actor.id).toBe('anonymous');
    expect(entry.actor.kind).toBe('user');
  });
});
