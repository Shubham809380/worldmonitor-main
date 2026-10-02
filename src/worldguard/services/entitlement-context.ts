/**
 * The one plan and capability context for the authenticated shell.
 *
 * Every surface that needs to say "what can this account do" reads it from here,
 * so the top bar, the dashboard, and an upgrade gate cannot disagree with each
 * other. It is a pure function of the session the server handed back — nothing
 * is read from the URL, `localStorage`, or a `?plan=` parameter, because none of
 * those are an authority for anything.
 *
 * ## What this is, and what it deliberately is not
 *
 * This is a *display* context. It explains the session the server reported and
 * the state of the services behind it. It is not an authorization check, and the
 * docstring would be dishonest if it implied otherwise: hiding a sidebar entry or
 * greying a button is a courtesy to the reader, never a control. Every one of
 * these capabilities is enforced on the server, and the server does not consult
 * this file.
 *
 * The distinction matters most for `plan`. `/api/auth/session` hardcodes
 * `plan: 'free'` for WorldGuard accounts (`api/auth/session.js`) — billing and
 * entitlements are Clerk-keyed Convex tables that are not provisioned for these
 * accounts, which `api/_worldguard-db.js` records as intentional. So `plan` here
 * is *reported*, not *resolved*, and `billing` is `not_provisioned`. A Free label
 * next to a working upgrade button would be a claim about a payment path that
 * does not exist for this account, so the gate says what is actually true.
 *
 * `capabilityState` is the other half of that honesty. It does not map features
 * onto plans, because no plan check exists in the SecureScan backend to map. It
 * reports, per capability, the real reason it is or is not reachable: a live
 * backend, a backend this deployment has not connected, or a service that is
 * not provisioned for WorldGuard accounts at all.
 */

import type { SessionUser } from './auth-session';

/** The plan string the session endpoint reports. Only two are defined server-side. */
export type Plan = SessionUser['plan'];

/**
 * Why a capability is or is not reachable for this session.
 *
 * `live` — a backend exists and the server decides per request.
 * `backend_unavailable` — this deployment has no Convex deployment configured,
 *   so nothing backed by it can answer. Distinct from a denial: the server was
 *   never asked.
 * `not_provisioned` — the service exists for other products but is intentionally
 *   not wired up for WorldGuard accounts.
 */
export type CapabilityState = 'live' | 'backend_unavailable' | 'not_provisioned';

export type CapabilityId =
  | 'assessments'
  | 'findings'
  | 'evidence'
  | 'report'
  | 'audit'
  | 'workspace_membership'
  | 'api_keys'
  | 'billing';

export interface Capability {
  readonly id: CapabilityId;
  readonly label: string;
  readonly state: CapabilityState;
  /** Plain-language reason shown to the reader when `state` is not `live`. */
  readonly reason: string;
}

export interface EntitlementContext {
  readonly plan: Plan;
  readonly planLabel: string;
  readonly billingState: CapabilityState;
  /** True when at least one capability is waiting on a backend that is absent. */
  readonly backendUnconnected: boolean;
  readonly capabilities: readonly Capability[];
}

const CONNECT_WORKSPACE =
  'Connect your SecureScan workspace to load live assessment data.';

function capability(
  id: CapabilityId,
  label: string,
  state: CapabilityState,
  reason: string,
): Capability {
  return { id, label, state, reason };
}

/**
 * Build the context for a session.
 *
 * `backendConnected` is passed in by the caller because only it can know whether
 * a deployment is configured — the browser cannot infer that from a failed
 * request, because "absent" and "denied" and "slow" all arrive as failures.
 */
export function createEntitlementContext(user: SessionUser, backendConnected: boolean): EntitlementContext {
  const state: CapabilityState = backendConnected ? 'live' : 'backend_unavailable';
  const unavailableReason = backendConnected
    ? 'The server refused this request.'
    : CONNECT_WORKSPACE;

  const capabilities: readonly Capability[] = [
    capability('assessments', 'Assessments', state, unavailableReason),
    capability('findings', 'Findings', state, unavailableReason),
    capability('evidence', 'Evidence', state, unavailableReason),
    capability('report', 'Reports', state, unavailableReason),
    capability('audit', 'Audit Center', state, unavailableReason),
    capability(
      'workspace_membership',
      'Workspace membership',
      'not_provisioned',
      'Members, roles, and invitations are Convex-keyed and are not provisioned for this account type.',
    ),
    capability(
      'api_keys',
      'API keys',
      'not_provisioned',
      'API keys are issued against Clerk-keyed records and are not provisioned for this account type.',
    ),
    capability(
      'billing',
      'Paid plans',
      'not_provisioned',
      'SecureScan billing is not connected for this account type. No payment can be taken here.',
    ),
  ];

  return {
    plan: user.plan,
    planLabel: user.plan === 'pro' ? 'Pro' : 'Free',
    billingState: 'not_provisioned',
    backendUnconnected: !backendConnected,
    capabilities,
  };
}

/** Look a capability up by id. */
export function findCapability(
  context: EntitlementContext,
  id: CapabilityId,
): Capability | undefined {
  return context.capabilities.find((entry) => entry.id === id);
}