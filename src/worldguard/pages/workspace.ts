/**
 * Workspace and Team.
 *
 * Both pages are about the same missing thing, so they live together and share
 * one honest explanation. Workspace *membership* — roles, seats, invitations —
 * is a Clerk-keyed Convex concept (`convex/securescan/members.ts`) that is
 * intentionally not provisioned for WorldGuard accounts; `api/_worldguard-db.js`
 * records that decision. So these pages do not render a member table with a
 * single row and an invite button that cannot deliver.
 *
 * Instead they state what the session actually is — one personal workspace,
 * scoped to this account — and show the invite affordance as a gate whose
 * caption says *why* it is closed. A page that shows the shape of a feature it
 * cannot run is how a product ends up promising something it will not deliver.
 *
 * Roles are also not editable here for a second reason: SecureScan enforces
 * role server-side on every query and mutation, so a client-side role editor
 * would write a value nothing reads. The page says that outright rather than
 * shipping a control that looks permanent and silently does nothing.
 */

import { html, safeHref, type SafeMarkup } from '../components/dom';
import { icon } from '../components/icons';
import { renderPageHead } from '../components/app-shell';
import type { EntitlementContext } from '../services/entitlement-context';
import type { SessionUser } from '../services/auth-session';

function renderDefinition(label: string, value: SafeMarkup | string): SafeMarkup {
  return html`<div class="wga-def">
    <dt class="wga-def__key">${label}</dt>
    <dd class="wga-def__val">${value}</dd>
  </div>`;
}

function renderNotice(
  title: string,
  detail: string,
  tone: 'info' | 'locked',
): SafeMarkup {
  return html`<div class="wga-notice wga-notice--${tone}" role="note">
    <span class="wga-notice__icon" aria-hidden="true">${icon(tone === 'locked' ? 'lock' : 'info', { size: 17, strokeWidth: 1.8 })}</span>
    <div class="wga-notice__body">
      <h2 class="wga-notice__title">${title}</h2>
      <p class="wga-notice__detail">${detail}</p>
    </div>
  </div>`;
}

export function renderWorkspacePage(
  user: SessionUser,
  entitlements: EntitlementContext,
): SafeMarkup {
  const membership = entitlements.capabilities.find((cap) => cap.id === 'workspace_membership');

  return html`<div class="wga-page" data-wga-page="workspace">
    ${renderPageHead('Workspace', 'The workspace this session is attached to, and what it is scoped to.')}

    <section class="wga-card" aria-labelledby="wga-ws-detail">
      <h2 class="wga-card__title" id="wga-ws-detail">Workspace</h2>
      <dl class="wga-defs">
        ${renderDefinition(
          'Name',
          html`<span class="wga-mono">Personal</span>
            <span class="wga-tag">Default</span>`,
        )}
        ${renderDefinition('Owner', user.name || user.email)}
        ${renderDefinition('Plan', entitlements.planLabel)}
        ${renderDefinition(
          'Scope',
          'Everything recorded in SecureScan under this account.',
        )}
      </dl>
    </section>

    ${renderNotice(
      'One personal workspace',
      'Switching between workspaces needs a membership record, and membership is not provisioned for this account type. Your work is not at risk — there is only one place for it to be.',
      'info',
    )}

    ${membership && membership.state !== 'live'
      ? renderNotice(
          'Shared workspaces are not enabled for this account',
          membership.reason,
          'locked',
        )
      : ''}
  </div>`;
}

export function renderTeamPage(
  user: SessionUser,
  entitlements: EntitlementContext,
): SafeMarkup {
  const membership = entitlements.capabilities.find((cap) => cap.id === 'workspace_membership');
  const apiKeys = entitlements.capabilities.find((cap) => cap.id === 'api_keys');

  return html`<div class="wga-page" data-wga-page="team">
    ${renderPageHead(
      'Team',
      'Members and roles. Roles are enforced on the server, not by this page.',
    )}

    <section class="wga-card" aria-labelledby="wga-team-members">
      <div class="wga-card__head">
        <h2 class="wga-card__title" id="wga-team-members">Members</h2>
        <span class="wga-count" data-wga-member-count>1</span>
      </div>
      <ul class="wga-members">
        <li class="wga-member">
          <span class="wga-member__avatar" aria-hidden="true">${icon('user', { size: 15, strokeWidth: 1.8 })}</span>
          <span class="wga-member__body">
            <span class="wga-member__name">${user.name || user.email}</span>
            <span class="wga-member__email">${user.email}</span>
          </span>
          <span class="wga-member__role">Owner</span>
        </li>
      </ul>
    </section>

    <section class="wga-card wga-card--gate" aria-labelledby="wga-invite">
      <h2 class="wga-card__title" id="wga-invite">Invite a teammate</h2>
      <p class="wga-card__detail">
        Invitations are part of workspace membership${membership ? `: ${membership.reason.charAt(0).toLowerCase()}${membership.reason.slice(1)}` : '.'}
      </p>
      <div class="wga-gate">
        <span class="wga-gate__badge" data-wga-gate="invite">Coming soon</span>
        <p class="wga-gate__detail">
          No paid plan can be purchased for SecureScan yet, so this control stays closed
          rather than accepting an invitation that would never arrive.
          ${apiKeys ? ` The same applies to API keys: ${apiKeys.reason.charAt(0).toLowerCase()}${apiKeys.reason.slice(1)}` : ''}
        </p>
        <a class="wga-btn wga-btn--ghost" href=${safeHref('#/pricing')}>See plan status</a>
      </div>
    </section>

    ${renderNotice(
      'Roles cannot be changed here',
      'SecureScan checks role on every query and mutation on the server, and stores it against a membership record this account type does not have. A role editor on this page would save a value nothing reads, so it is not offered.',
      'info',
    )}
  </div>`;
}
