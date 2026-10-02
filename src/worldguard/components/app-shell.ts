/**
 * Authenticated product shell: the sidebar and top bar a signed-in user works in.
 *
 * This is the surface the sign-in card hands off to. It is chrome only — the
 * sidebar, the top bar, and a slot for the page — so that the sign-in view and
 * the signed-in product share the same design tokens, icon set, and focus
 * treatment without either one owning the other's layout.
 *
 * ## On the sidebar listing every destination for every role
 *
 * The sidebar is not a permission model. A `Free` account sees `Audit Center`
 * and `Administration` exactly as a paying admin would, because hiding an entry
 * would only hide the fact that the server is the thing refusing — the reader
 * would conclude the product has no such feature rather than that they may not
 * use it yet. SecureScan's own router states the same rule for itself
 * (`src/securescan/routing.ts`): *navigation is not authorization*, and the
 * console must behave correctly when someone arrives at a URL directly. So the
 * entries are listed, and each server-authoritative surface answers for itself.
 *
 * ## The workspace selector
 *
 * There is exactly one workspace here, and it is the account's own. Workspace
 * *membership* — the part with roles, seats, and invitations — lives in Clerk-
 * keyed Convex records that are not provisioned for these accounts, so a
 * multi-workspace switcher would be a control that cannot do anything. It is
 * rendered as a labelled single-value control with that fact stated inline
 * rather than as a disabled-looking dropdown, because a dropdown that opens onto
 * nothing is worse than a clear sentence.
 */

import { html, mount, raw, safeHref, type SafeMarkup } from './dom';
import { icon, type IconName } from './icons';
import { NAV_ITEMS, NAV_SECTIONS, navHref, type NavItem } from '../routing';
import type { EntitlementContext } from '../services/entitlement-context';
import type { SessionUser } from '../services/auth-session';

const ICONS: Readonly<Record<string, IconName>> = {
  dashboard: 'grid',
  assessments: 'target',
  findings: 'shieldAlert',
  evidence: 'fileSearch',
  remediation: 'layers',
  retesting: 'refresh',
  reports: 'fileSearch',
  audit: 'shieldCheck',
  workspace: 'globe',
  team: 'users',
  settings: 'cpu',
  pricing: 'zap',
};

function navIcon(id: string): SafeMarkup {
  return icon(ICONS[id] ?? 'grid', { size: 16, strokeWidth: 1.8 });
}

export function renderNavSection(
  section: string,
  items: readonly NavItem[],
  activeId: string,
): SafeMarkup {
  return html`<div class="wga-nav__group">
    <span class="wga-nav__group-label" id="wga-nav-${section}">${section}</span>
    <ul class="wga-nav__list" aria-labelledby="wga-nav-${section}">
      ${items.map((item) => {
        const active = item.id === activeId;
        return html`<li>
          <a
            class="wga-nav__link${active ? ' wga-nav__link--active' : ''}"
            href=${safeHref(navHref(item))}
            ${active ? raw('aria-current="page"') : ''}
            data-wga-nav=${item.id}
          >
            <span class="wga-nav__icon" aria-hidden="true">${navIcon(item.id)}</span>
            <span class="wga-nav__label">${item.label}</span>
          </a>
        </li>`;
      })}
    </ul>
  </div>`;
}

function renderSidebar(activeId: string, user: SessionUser): SafeMarkup {
  return html`<aside class="wga-sidebar" aria-label="Product sections">
    <div class="wga-sidebar__brand">
      <span class="wga-sidebar__mark" aria-hidden="true">${icon('shieldCheck', { size: 20, strokeWidth: 1.8 })}</span>
      <span class="wga-sidebar__names">
        <span class="wga-sidebar__product">WM SecureScan</span>
        <span class="wga-sidebar__tagline">Security Assessment Platform</span>
      </span>
    </div>

    <nav class="wga-nav" aria-label="Product sections">
      ${NAV_SECTIONS.map((section) => {
        const items = NAV_ITEMS.filter((item) => item.section === section);
        if (items.length === 0) return '';
        return renderNavSection(section, items, activeId);
      })}
    </nav>

    <div class="wga-sidebar__foot">
      <p class="wga-sidebar__account">
        <span class="wga-sidebar__account-name">${user.name || user.email}</span>
        <span class="wga-sidebar__account-email">${user.email}</span>
      </p>
    </div>
  </aside>`;
}

/**
 * The top bar, and the account menu.
 *
 * The account menu's own links use `data-wga-menu-item`, deliberately not the
 * sidebar's `data-wga-nav`. The controller marks the current page by setting
 * `aria-current` on `data-wga-nav`; sharing one hook would mark the same route
 * current twice, telling assistive tech there are two current pages.
 */
function renderTopBar(user: SessionUser, entitlements: EntitlementContext): SafeMarkup {
  return html`<header class="wga-topbar">
    <div class="wga-topbar__start">
      <span class="wga-workspace" title="This session is scoped to your own account.">
        <span class="wga-workspace__icon" aria-hidden="true">${icon('globe', { size: 15, strokeWidth: 1.8 })}</span>
        <span class="wga-workspace__label">Workspace</span>
        <span class="wga-workspace__value">Personal</span>
      </span>
      <span class="wga-plan" data-wga-plan=${entitlements.plan}>
        <span class="wga-plan__label">Plan</span>
        <span class="wga-plan__value">${entitlements.planLabel}</span>
      </span>
    </div>

    <div class="wga-topbar__end">
      <details class="wga-account">
        <summary class="wga-account__trigger" aria-label="Account menu">
          <span class="wga-account__avatar" aria-hidden="true">${icon('user', { size: 16, strokeWidth: 1.8 })}</span>
          <span class="wga-account__name">${user.name || user.email}</span>
          <span class="wga-account__chevron" aria-hidden="true">${icon('chevronRight', { size: 14, strokeWidth: 2 })}</span>
        </summary>
        <div class="wga-account__menu" role="group" aria-label="Account">
          <p class="wga-account__row"><span>Email</span><span>${user.email}</span></p>
          <p class="wga-account__row"><span>Plan</span><span>${entitlements.planLabel}</span></p>
          <a class="wga-account__item" href="#/settings" data-wga-menu-item="settings">Account settings</a>
          <a class="wga-account__item" href="#/pricing" data-wga-menu-item="pricing">Plans &amp; pricing</a>
          <button type="button" class="wga-account__item wga-account__item--danger" data-wga-sign-out>
            Sign out
          </button>
        </div>
      </details>
    </div>
  </header>`;
}

/**
 * The shell frame, with an empty page slot.
 *
 * `pageSlot` is replaced by the controller on each render; the sidebar and top
 * bar are rendered once per route change and never re-created mid-keystroke, so
 * a native `<details>` menu cannot close itself while the reader is using it.
 */
export function renderShell(
  user: SessionUser,
  entitlements: EntitlementContext,
  activeId: string,
): SafeMarkup {
  return html`<div class="wga-layout">
    <a class="wga-skip-link" href="#wga-page">Skip to main content</a>
    ${renderSidebar(activeId, user)}
    <div class="wga-main">
      ${renderTopBar(user, entitlements)}
      <main class="wga-page" id="wga-page" tabindex="-1">
        <div class="wga-page__inner" data-wga-page-slot></div>
      </main>
    </div>
  </div>`;
}

/** Page header block shared by every shell page. */
export function renderPageHead(
  heading: string,
  sub: string,
  actions?: SafeMarkup,
): SafeMarkup {
  return html`<div class="wga-pagehead">
    <div>
      <h1 class="wga-pagehead__title">${heading}</h1>
      <p class="wga-pagehead__sub">${sub}</p>
    </div>
    ${actions ? html`<div class="wga-pagehead__actions">${actions}</div>` : ''}
  </div>`;
}

/** The honest state used wherever a surface needs a backend that is not there. */
export function renderConnectState(title: string, detail: string): SafeMarkup {
  return html`<section class="wga-connect" aria-label="${title}">
    <span class="wga-connect__icon" aria-hidden="true">${icon('database', { size: 20, strokeWidth: 1.7 })}</span>
    <div class="wga-connect__body">
      <h2 class="wga-connect__title">${title}</h2>
      <p class="wga-connect__detail">${detail}</p>
    </div>
  </section>`;
}

export function renderStat(label: string, value: string, hint: string): SafeMarkup {
  return html`<div class="wga-stat">
    <span class="wga-stat__label">${label}</span>
    <span class="wga-stat__value">${value}</span>
    <span class="wga-stat__hint">${hint}</span>
  </div>`;
}

export { mount };
