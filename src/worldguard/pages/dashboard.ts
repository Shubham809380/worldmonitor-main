/**
 * The signed-in landing page.
 *
 * Its job is to answer "what is my state, and what do I do next" without
 * inventing any of it. So the page is built from two sources only: the session
 * the server returned, and the honest capability states from
 * `entitlement-context.ts`. There is no cached assessment total, no last-seen
 * timestamp, and no activity feed, because no producer in this repository emits
 * them for a WorldGuard session — a dashboard that shows "0 open findings" when
 * it cannot read the finding store is not a dashboard, it is a guess.
 *
 * Where a number would normally go, the page says the store is not connected
 * instead. That is the whole design of this file: the interesting part is the
 * distinction between "zero" and "cannot tell yet".
 */

import { html, safeHref, type SafeMarkup } from '../components/dom';
import { icon } from '../components/icons';
import { renderConnectState, renderPageHead, renderStat } from '../components/app-shell';
import { secureScanHref } from '../routing';
import type { EntitlementContext } from '../services/entitlement-context';
import type { SessionUser } from '../services/auth-session';

const QUICK_LINKS: ReadonlyArray<{ label: string; detail: string; hash: string; glyph: 'target' | 'shieldAlert' | 'fileSearch' | 'shieldCheck' }> = [
  {
    label: 'New assessment',
    detail: 'Start a target from scratch',
    hash: '#/assessments',
    glyph: 'target',
  },
  {
    label: 'Findings',
    detail: 'Triage and record remediation',
    hash: '#/findings',
    glyph: 'shieldAlert',
  },
  {
    label: 'Evidence',
    detail: 'Attach proof for a finding',
    hash: '#/evidence',
    glyph: 'fileSearch',
  },
  {
    label: 'Audit Center',
    detail: 'Verify the chain of custody',
    hash: '#/audit',
    glyph: 'shieldCheck',
  },
];

function renderGreeting(user: SessionUser): SafeMarkup {
  const name = user.name || user.email;
  return html`<p class="wga-dashboard__welcome">
    Signed in as <strong>${name}</strong>${user.email !== name ? html` <span class="wga-dashboard__alt">(${user.email})</span>` : ''}.
  </p>`;
}

/**
 * The four summary tiles.
 *
 * When the backend is connected these still read "—" rather than a count: a
 * count is only correct if it was fetched, and this page does not fetch finding
 * and assessment stores. `—` plus the caption "not loaded here" is the accurate
 * answer, and it is what the caption below each tile says.
 */
function renderStats(entitlements: EntitlementContext): SafeMarkup {
  const connected = !entitlements.backendUnconnected;
  const hint = connected
    ? 'Open the section to load these'
    : 'Needs a connected workspace';
  const dash = '—';

  return html`<section class="wga-stats" aria-label="Summary">
    ${renderStat('Open findings', dash, hint)}
    ${renderStat('Assessments in flight', dash, hint)}
    ${renderStat('Evidence attached', dash, hint)}
    ${renderStat('Unresolved criticals', dash, hint)}
  </section>`;
}

function renderQuickLinks(): SafeMarkup {
  return html`<section class="wga-dashboard__block" aria-labelledby="wga-quick">
    <h2 class="wga-dashboard__block-title" id="wga-quick">Where to go next</h2>
    <ul class="wga-quick">
      ${QUICK_LINKS.map(
        (item) => html`<li>
          <a class="wga-quick__card" href=${safeHref(secureScanHref(item.hash))}>
            <span class="wga-quick__icon" aria-hidden="true">${icon(item.glyph, { size: 18, strokeWidth: 1.7 })}</span>
            <span class="wga-quick__body">
              <span class="wga-quick__label">${item.label}</span>
              <span class="wga-quick__detail">${item.detail}</span>
            </span>
            <span class="wga-quick__go" aria-hidden="true">${icon('chevronRight', { size: 15, strokeWidth: 2 })}</span>
          </a>
        </li>`,
      )}
    </ul>
  </section>`;
}

/**
 * Capability ledger.
 *
 * This is the block that makes the rest of the page trustworthy: it states, per
 * capability, whether it is live, waiting on a backend, or intentionally not
 * wired up for this account type. It is the same list the upgrade gate and the
 * team page read, so a reader who checks one and then another finds the same
 * answer.
 */
function renderCapabilities(entitlements: EntitlementContext): SafeMarkup {
  const BADGE: Record<string, { text: string; cls: string }> = {
    live: { text: 'Available', cls: 'wga-cap--live' },
    backend_unavailable: { text: 'Not connected', cls: 'wga-cap--waiting' },
    not_provisioned: { text: 'Not available on this plan', cls: 'wga-cap--off' },
  };

  return html`<section class="wga-dashboard__block" aria-labelledby="wga-caps">
    <h2 class="wga-dashboard__block-title" id="wga-caps">What this account can use</h2>
    <ul class="wga-caps">
      ${entitlements.capabilities.map((cap) => {
        const badge = BADGE[cap.state] ?? BADGE.not_provisioned!;
        return html`<li class="wga-cap">
          <span class="wga-cap__head">
            <span class="wga-cap__label">${cap.label}</span>
            <span class="wga-cap__badge ${badge.cls}" data-wga-cap=${cap.id} data-wga-state=${cap.state}>${badge.text}</span>
          </span>
            ${cap.state === 'live' ? '' : html`<span class="wga-cap__reason">${cap.reason}</span>`}
        </li>`;
      })}
    </ul>
  </section>`;
}

export function renderDashboardPage(
  user: SessionUser,
  entitlements: EntitlementContext,
): SafeMarkup {
  return html`<div class="wga-dashboard" data-wga-page="dashboard">
    ${renderPageHead(
      'Your security assessment workspace',
      'Where assessment work starts and what is still waiting on you.',
      html`<a class="wga-btn wga-btn--primary" href=${safeHref(secureScanHref('#/assessments'))}>
        <span aria-hidden="true">${icon('target', { size: 15, strokeWidth: 1.9 })}</span>
        Start an assessment
      </a>`,
    )}
    ${renderGreeting(user)}

    ${entitlements.backendUnconnected
      ? renderConnectState(
          'SecureScan workspace not connected',
          'Assessment data lives in a SecureScan workspace. Connect one to load live findings, evidence, and audit history — nothing below is being faked in the meantime.',
        )
      : ''}

    ${renderStats(entitlements)}
    ${renderQuickLinks()}
    ${renderCapabilities(entitlements)}
  </div>`;
}
