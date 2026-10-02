/**
 * Account settings.
 *
 * Read-only, and honest about being read-only. Every field on this page is a
 * value the server already reports for the session — the display name and email
 * from `/api/auth/session`, and the cookie's own attributes. Nothing here
 * pretends to be editable, because nothing here is: WorldGuard's identity lives
 * in `api/_worldguard-db.js`, there is no update-identity endpoint, and building
 * a form that submits nowhere is worse than not offering the form.
 *
 * The one control that *is* real is sign out, and it is a genuine
 * `POST /api/auth/logout` that clears the `wg-session` cookie — the same
 * teardown the account menu performs.
 */

import { html, type SafeMarkup } from '../components/dom';
import { icon } from '../components/icons';
import { renderPageHead } from '../components/app-shell';
import type { EntitlementContext } from '../services/entitlement-context';
import type { SessionUser } from '../services/auth-session';

function renderRow(label: string, value: SafeMarkup | string): SafeMarkup {
  return html`<div class="wga-setting">
    <dt class="wga-setting__key">${label}</dt>
    <dd class="wga-setting__val">${value}</dd>
  </div>`;
}

export function renderSettingsPage(
  user: SessionUser,
  entitlements: EntitlementContext,
): SafeMarkup {
  return html`<div class="wga-page" data-wga-page="settings">
    ${renderPageHead(
      'Account settings',
      'The identity and session the server reports for you, read-only.',
    )}

    <section class="wga-card" aria-labelledby="wga-set-identity">
      <div class="wga-card__head">
        <h2 class="wga-card__title" id="wga-set-identity">Identity</h2>
        <span class="wga-readonly" data-wga-readonly>Read-only</span>
      </div>
      <dl class="wga-settings">
        ${renderRow('Name', user.name || '—')}
        ${renderRow('Email', user.email)}
        ${renderRow('Plan', entitlements.planLabel)}
        ${renderRow(
          'User ID',
          html`<span class="wga-mono">${user.id}</span>`,
        )}
      </dl>
      <p class="wga-card__detail">
        These details come from the account record and cannot be edited from the
        dashboard. Changing your email means signing up again with the new address.
      </p>
    </section>

    <section class="wga-card" aria-labelledby="wga-set-session">
      <h2 class="wga-card__title" id="wga-set-session">Session</h2>
      <dl class="wga-settings">
        ${renderRow(
          'Authentication',
          html`<span class="wga-mono">HttpOnly cookie wg-session</span>`,
        )}
        ${renderRow('Authority', 'The server validates this session on every request.')}
      </dl>
      <p class="wga-card__detail">
        The session cookie is not readable by scripts on this page, and nothing in
        this dashboard decides what you may see — SecureScan re-checks the session
        and your role on the server for every request it serves.
      </p>
    </section>

    <section class="wga-card wga-card--danger" aria-labelledby="wga-set-signout">
      <h2 class="wga-card__title" id="wga-set-signout">Sign out</h2>
      <p class="wga-card__detail">
        Ends this session and clears the <span class="wga-mono">wg-session</span> cookie.
        You will return to the sign-in page.
      </p>
      <button type="button" class="wga-btn wga-btn--danger" data-wga-sign-out>
        <span aria-hidden="true">${icon('lock', { size: 15, strokeWidth: 1.9 })}</span>
        Sign out
      </button>
    </section>
  </div>`;
}
