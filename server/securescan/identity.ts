/**
 * WM SecureScan identity, roles and resource-level authorization.
 *
 * Design constraints, in priority order:
 *
 *  1. **The server decides.** This module is imported by the API and by the
 *     Convex functions. Nothing here reads a role from a request body, a query
 *     parameter or a hidden control, because a client that can name its own role
 *     needs no password.
 *  2. **Role gates capability; ownership gates the row.** A role alone answers
 *     "may an analyst run a scan at all?". It cannot answer "may this analyst
 *     cancel *this* run?", because that is a question about one specific
 *     resource. So every mutating check also takes the resource and its owner,
 *     which is what stops an analyst from enumerating IDs to cancel somebody
 *     else's assessment. A check that only looked at the role would be an IDOR
 *     with extra steps.
 *  3. **Denials are values, not exceptions.** An unauthorized attempt is an
 *     expected outcome that must be logged, counted and returned, not a crash.
 *     `authorize` returns a decision; the caller decides how to surface it.
 *  4. **Pure.** No clock, no environment, no network. Everything is a function
 *     of its arguments, so the authorization rules are unit-testable and cannot
 *     drift at runtime.
 *
 * Every `Action` below is also an auditable event (see `audit.ts`), so adding a
 * capability here without a corresponding audit record is not possible.
 */

import type { Confidence, FindingState, Severity } from './types';
import { canTransitionFinding } from './findings';

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

export const ROLES = ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'] as const;
export type Role = (typeof ROLES)[number];

export function isRole(value: unknown): value is Role {
  return typeof value === 'string' && (ROLES as readonly string[]).includes(value);
}

/**
 * There is deliberately no default role.
 *
 * An earlier version of this module exported `DEFAULT_ROLE = 'VIEWER'` on the
 * reasoning that least privilege means "can read, cannot scan". That was wrong
 * about what a read costs here: assessment results, evidence payloads, target
 * configuration and finding detail are the sensitive data, and reads are
 * workspace-wide within the team. A default therefore grants every
 * self-registered account a view of every security assessment in the
 * deployment, and no amount of write-restriction gives that back.
 *
 * SecureScan access is granted by an admin, not inherited from having a World
 * Monitor account. `convex/securescan/_shared.ts` resolves a role from the
 * membership table and refuses callers with no row.
 */

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/**
 * A capability. These are deliberately verbs over domain nouns, not routes:
 * a route name changes when the router changes, a capability does not.
 */
export const ACTIONS = [
  // Assessment lifecycle
  'assessment:create',
  'assessment:read',
  'assessment:start',
  'assessment:cancel',
  'assessment:delete',
  'target:read',
  'target:manage',
  // Findings
  'finding:read',
  'finding:triage',
  'finding:verify',
  'finding:dismiss',
  'finding:reopen',
  // Evidence
  'evidence:read',
  'evidence:attach',
  // Runtime testing
  'runtime:read',
  'runtime:execute',
  // Remediation and retesting
  'remediation:read',
  'remediation:write',
  'retest:read',
  'retest:execute',
  // Reporting
  'report:read',
  'report:generate',
  // Administration
  'admin:users',
  'admin:audit',
  'admin:settings',
  'user:read',
  'user:role',
  'user:session',
] as const;

export type Action = (typeof ACTIONS)[number];

/**
 * Actions that change state or reveal audit data. These are the ones that must
 * leave a trail, and the ones a VIEWER must never hold.
 */
export const SENSITIVE_ACTIONS: ReadonlySet<Action> = new Set<Action>([
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
]);

/**
 * Read-only capabilities. VIEWER holds exactly these and nothing else.
 */
const READ_ACTIONS: readonly Action[] = [
  'assessment:read',
  'target:read',
  'finding:read',
  'evidence:read',
  'runtime:read',
  'remediation:read',
  'retest:read',
  'report:read',
  'user:read',
];

/**
 * Everything a security analyst may do. Note what is *absent*: `admin:users`,
 * `user:role`, `user:session` and `admin:settings`. An analyst can run and
 * triage assessments; an analyst cannot grant themselves analyst rights, which
 * is the privilege-escalation edge this product is most likely to grow.
 */
const ANALYST_ACTIONS: readonly Action[] = [
  ...READ_ACTIONS,
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
];

/**
 * ADMIN holds every declared action. It is derived from `ACTIONS` rather than
 * re-listed, so a newly added capability cannot be accidentally withheld from
 * the administrator — and cannot be accidentally granted to anybody else.
 */
const PERMISSIONS: Readonly<Record<Role, ReadonlySet<Action>>> = {
  VIEWER: new Set<Action>(READ_ACTIONS),
  SECURITY_ANALYST: new Set<Action>(ANALYST_ACTIONS),
  ADMIN: new Set<Action>(ACTIONS),
};

export function can(role: Role, action: Action): boolean {
  return PERMISSIONS[role].has(action);
}

export function permissionsFor(role: Role): readonly Action[] {
  return ACTIONS.filter((action) => PERMISSIONS[role].has(action));
}

// ---------------------------------------------------------------------------
// Actors and resources
// ---------------------------------------------------------------------------

export interface Actor {
  readonly userId: string;
  readonly role: Role;
  /** Stable display name for audit records. Never used for authorization. */
  readonly displayName?: string;
}

/**
 * A resource the caller named by ID. The server must have loaded this from its
 * own store rather than accepting the client's copy of these fields — the
 * ownership decision is only as trustworthy as the lookup that produced it.
 */
export interface SecuredResource {
  readonly id: string;
  readonly kind: 'assessment' | 'finding' | 'evidence' | 'target' | 'report' | 'retest' | 'user';
  readonly ownerId?: string | null;
}

export type Decision =
  | { readonly allowed: true; readonly actor: Actor; readonly action: Action }
  | {
      readonly allowed: false;
      readonly reason: string;
      readonly code: 'AUTH_REQUIRED' | 'ROLE_FORBIDDEN' | 'NOT_RESOURCE_OWNER' | 'INVALID_TRANSITION';
      readonly requiredRoles: readonly Role[];
    };

/**
 * Roles that could perform `action`. Used in denial messages so an operator can
 * tell "wrong role" from "not your resource" from "illegal state change" without
 * reading the source.
 */
export function rolesAllowing(action: Action): readonly Role[] {
  return ROLES.filter((role) => PERMISSIONS[role].has(action));
}

const ALL_ROLES: readonly Role[] = ROLES;

/**
 * Authorize one action against one resource.
 *
 * Order matters: the role gate runs first because it is cheaper to reason
 * about, and because leaking "this resource exists but is not yours" to an
 * under-privileged role is an unnecessary disclosure. A caller that needs a
 * blanket resource check (read access) should pass no resource and rely on the
 * role gate alone.
 */
export function authorize(
  actor: Actor | null,
  action: Action,
  resource?: SecuredResource | null,
): Decision {
  if (actor === null || actor.userId === '') {
    return {
      allowed: false,
      code: 'AUTH_REQUIRED',
      reason: 'No authenticated identity is attached to this request.',
      requiredRoles: ALL_ROLES,
    };
  }

  if (!PERMISSIONS[actor.role].has(action)) {
    return {
      allowed: false,
      code: 'ROLE_FORBIDDEN',
      reason: `Role ${actor.role} may not perform ${action}.`,
      requiredRoles: rolesAllowing(action),
    };
  }

  // Reads are workspace-wide by design: a security analyst has to be able to
  // see a colleague's finding to review it, and the audit trail is the
  // accountability mechanism. Only mutations are owner-scoped.
  if (resource && MUTATING_ACTIONS.has(action) && resource.ownerId != null && resource.ownerId !== actor.userId) {
    if (actor.role !== 'ADMIN') {
      return {
        allowed: false,
        code: 'NOT_RESOURCE_OWNER',
        reason: `${action} is owner-scoped and this ${resource.kind} belongs to another user.`,
        requiredRoles: rolesAllowing(action),
      };
    }
  }

  return { allowed: true, actor, action };
}

/** Actions that alter a resource and are therefore owner-scoped. */
const MUTATING_ACTIONS: ReadonlySet<Action> = new Set<Action>([
  'assessment:start',
  'assessment:cancel',
  'assessment:delete',
  'finding:triage',
  'finding:verify',
  'finding:dismiss',
  'finding:reopen',
  'evidence:attach',
  'remediation:write',
  'retest:execute',
  'report:generate',
  'user:role',
  'user:session',
]);

export function isMutating(action: Action): boolean {
  return MUTATING_ACTIONS.has(action);
}

// ---------------------------------------------------------------------------
// Finding lifecycle
// ---------------------------------------------------------------------------

/**
 * Allowed finding transitions live in `findings.ts` next to
 * `transitionFinding`, so the state machine and the authorization layer cannot
 * drift apart. `identity` layers the role gate on the same table.
 */
export function canTransition(from: FindingState, to: FindingState): boolean {
  return canTransitionFinding(from, to);
}


/**
 * Transition with the role gate applied on top of the state machine.
 *
 * Triage and dismissal are separated on purpose: dismissing a finding is the
 * action most likely to hide a real problem, so it is a distinct capability
 * from adding a note, and the audit record names which one happened.
 */
export function authorizeFindingTransition(
  actor: Actor | null,
  finding: { readonly id: string; readonly state: FindingState; readonly ownerId?: string | null },
  to: FindingState,
): Decision {
  const action: Action = to === 'FALSE_POSITIVE' || to === 'ACCEPTED_RISK'
    ? 'finding:dismiss'
    : to === 'VERIFIED' || to === 'VALIDATED'
      ? 'finding:verify'
      : 'finding:triage';

  const gate = authorize(actor, action, { id: finding.id, kind: 'finding', ownerId: finding.ownerId ?? null });
  if (!gate.allowed) return gate;

  if (!canTransition(finding.state, to)) {
    return {
      allowed: false,
      code: 'INVALID_TRANSITION',
      reason: `A finding in ${finding.state} cannot move to ${to}.`,
      requiredRoles: rolesAllowing(action),
    };
  }

  return { allowed: true, actor: (gate as { actor: Actor }).actor, action };
}

// ---------------------------------------------------------------------------
// Triage input
// ---------------------------------------------------------------------------

/**
 * What a reviewer asserts when they change a finding's state. The reason is
 * mandatory because a dismissal without a reason is indistinguishable from
 * negligence during an incident review, and it is the one field a false-positive
 * workflow cannot do without.
 */
export interface TriageInput {
  readonly to: FindingState;
  readonly reason: string;
  /** Optional lowered severity, which is itself a sensitive action. */
  readonly severity?: Severity;
  /** Never taken from the client as an authority; see `notes.ts` guidance. */
  readonly confidence?: Confidence;
}

export interface TriageValidationError {
  readonly field: string;
  readonly message: string;
}

const MIN_REASON_LENGTH = 12;

export function validateTriageInput(input: TriageInput): readonly TriageValidationError[] {
  const errors: TriageValidationError[] = [];
  if (input.to === 'FALSE_POSITIVE' || input.to === 'ACCEPTED_RISK') {
    if (input.reason.trim().length < MIN_REASON_LENGTH) {
      errors.push({
        field: 'reason',
        message: `A ${input.to === 'FALSE_POSITIVE' ? 'false-positive' : 'accepted-risk'} decision needs a reason of at least ${MIN_REASON_LENGTH} characters.`,
      });
    }
  }
  if (input.reason.length > 2000) {
    errors.push({ field: 'reason', message: 'Reason must be 2000 characters or fewer.' });
  }
  return errors;
}
