/**
 * Plans and upgrade.
 *
 * The single most important thing on this page is what it does *not* do: there
 * is no card form, no plan toggle that writes anything, and no "upgrade"
 * button that pretends to start a purchase. SecureScan has no billing
 * integration for these accounts. WorldGuard's session endpoint hardcodes
 * `plan: 'free'` (`api/auth/session.js`) and entitlements are Clerk-keyed
 * Convex records that are not provisioned for this account type
 * (`api/_worldguard-db.js`). So any checkout UI here would be a fiction with a
 * credit-card field in it.
 *
 * What the page does instead:
 *
 *  1. States the plan the server reports, and says plainly that it is reported
 *     rather than computed.
 *  2. Describes the Pro feature set as *intent*, each row marked with whether
 *     it is available, waiting on a connected workspace, or not provisioned.
 *     The rows come from the shared capability context, so this page cannot
 *     claim a capability the dashboard denies.
 *  3. Points at the real WorldMonitor pricing page for the product that *does*
 *     take payment, and says in the same breath that a WorldMonitor plan does
 *     not change SecureScan access — because it does not.
 *
 * That last sentence is the one that keeps this page honest. Linking out without
 * it would be a bait-and-switch: a reader pays, comes back, and finds the same
 * `Free` badge, having no idea why.
 */

import { html, safeHref, type SafeMarkup } from '../components/dom';
import { icon } from '../components/icons';
import { renderPageHead } from '../components/app-shell';
import { WEB_APP_ORIGIN } from '@/config/web-origin';
import type { EntitlementContext } from '../services/entitlement-context';

const PRO_INTENT: ReadonlyArray<{ id: string; label: string; detail: string }> = [
  {
    id: 'assessments',
    label: 'Unlimited assessments',
    detail: 'Run a new target at any time instead of a fixed monthly allowance.',
  },
  {
    id: 'findings',
    label: 'Full finding history',
    detail: 'Keep resolved findings and their remediation record beyond the free window.',
  },
  {
    id: 'audit',
    label: 'Audit Center retention',
    detail: 'Longer chain-of-custody history for assessments your team has to evidence.',
  },
  {
    id: 'workspace_membership',
    label: 'Shared workspaces',
    detail: 'Roles, seats, and invitations so more than one person can work in a workspace.',
  },
  {
    id: 'api_keys',
    label: 'API keys',
    detail: 'Run assessments from CI or a scheduled job against a key you own.',
  },
];

const STATE_TEXT: Record<string, string> = {
  live: 'Included',
  backend_unavailable: 'Included — needs a connected workspace',
  not_provisioned: 'Not available yet',
};

function renderCurrentPlan(entitlements: EntitlementContext): SafeMarkup {
  return html`<section class="wga-card wga-card--current" aria-labelledby="wga-plan-current">
    <div class="wga-card__head">
      <h2 class="wga-card__title" id="wga-plan-current">Your plan</h2>
      <span class="wga-plan wga-plan--lg" data-wga-plan=${entitlements.plan}>
        <span class="wga-plan__value">${entitlements.planLabel}</span>
      </span>
    </div>
    <p class="wga-card__detail">
      This is the plan the server reports for your session. It is not derived from a
      purchase made on this page, because no purchase can be made here.
    </p>
  </section>`;
}

function renderProIntent(entitlements: EntitlementContext): SafeMarkup {
  return html`<section class="wga-card" aria-labelledby="wga-plan-pro">
    <div class="wga-card__head">
      <h2 class="wga-card__title" id="wga-plan-pro">What Pro is intended to include</h2>
      <span class="wga-tag wga-tag--muted">In design</span>
    </div>
    <ul class="wga-features">
      ${PRO_INTENT.map((row) => {
        const cap = entitlements.capabilities.find((entry) => entry.id === row.id);
        const state = cap?.state ?? 'not_provisioned';
        return html`<li class="wga-feature" data-wga-feature=${row.id}>
          <span class="wga-feature__mark" aria-hidden="true">${icon('checkCircle', { size: 15, strokeWidth: 1.8 })}</span>
          <span class="wga-feature__body">
            <span class="wga-feature__label">${row.label}</span>
            <span class="wga-feature__detail">${row.detail}</span>
          </span>
          <span class="wga-feature__state" data-wga-state=${state}>${STATE_TEXT[state] ?? STATE_TEXT.not_provisioned}</span>
        </li>`;
      })}
    </ul>
  </section>`;
}

function renderBillingGate(entitlements: EntitlementContext): SafeMarkup {
  const billing = entitlements.capabilities.find((cap) => cap.id === 'billing');

  return html`<section class="wga-card wga-card--gate" aria-labelledby="wga-plan-cta">
    <h2 class="wga-card__title" id="wga-plan-cta">Upgrading</h2>
    <div class="wga-gate">
      <span class="wga-gate__badge" data-wga-gate="upgrade">Coming soon</span>
      <p class="wga-gate__detail">
        SecureScan billing is not connected for this account type, so no payment can be
        taken here and no upgrade button can honestly be offered.
        ${billing ? billing.reason : ''}
      </p>
      <a
        class="wga-btn wga-btn--ghost"
        href=${safeHref(`${WEB_APP_ORIGIN}/pro#pricing`)}
        data-wga-external="pricing"
      >
        <span aria-hidden="true">${icon('external', { size: 14, strokeWidth: 1.9 })}</span>
        View WorldMonitor plans
      </a>
      <p class="wga-gate__caveat">
        WorldMonitor Pro is a separate subscription for the live dashboard. It does not
        change anything on this page, and it will not unlock the rows above — those
        depend on SecureScan billing, which is a separate piece of work.
      </p>
    </div>
  </section>`;
}

export function renderPricingPage(entitlements: EntitlementContext): SafeMarkup {
  return html`<div class="wga-page" data-wga-page="pricing">
    ${renderPageHead(
      'Plans',
      'What each plan is intended to include, and the current state of billing for SecureScan.',
    )}
    ${renderCurrentPlan(entitlements)}
    ${renderProIntent(entitlements)}
    ${renderBillingGate(entitlements)}
  </div>`;
}
