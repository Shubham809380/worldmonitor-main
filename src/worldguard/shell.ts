/**
 * The signed-in product shell controller.
 *
 * Owns the lifecycle of the authenticated view: mounts the chrome, resolves the
 * current hash to a page, renders it into the page slot, and tears everything
 * down on sign-out. It replaces the static "You are signed in" card that used to
 * be the whole of a successful sign-in.
 *
 * ## On hand-off
 *
 * A typed `#/audit` — or any SecureScan route name pasted into this document —
 * resolves to a hand-off, not a page. The shell cannot render SecureScan's
 * routes, so it redirects to the document that owns them. Registering those
 * redirects here is what keeps the sidebar honest: an entry that points at
 * SecureScan is one the shell can always resolve, whether it was clicked or
 * typed.
 *
 * ## On teardown
 *
 * Sign-out returns to the sign-in surface, which means the shell's listeners
 * must be gone first — otherwise a `hashchange` arriving during the swap would
 * render a page for a session that no longer exists. Teardown therefore removes
 * every listener it added and clears the hash back to the route the sign-in view
 * uses, so a later sign-in starts at the dashboard rather than a stale route.
 */

import { mount, html, type SafeMarkup } from './components/dom';
import { renderPageHead, renderShell } from './components/app-shell';
import { renderDashboardPage } from './pages/dashboard';
import { renderWorkspacePage, renderTeamPage } from './pages/workspace';
import { renderSettingsPage } from './pages/settings';
import { renderPricingPage } from './pages/pricing';
import {
  DEFAULT_SHELL_ROUTE,
  NAV_ITEMS,
  UNKNOWN_ROUTE,
  currentHash,
  navHref,
  replaceHash,
  resolveLocation,
  secureScanHref,
  type ShellRouteName,
} from './routing';
import { createEntitlementContext, type EntitlementContext } from './services/entitlement-context';
import { signOut } from './services/auth-session';
import type { SessionUser } from './services/auth-session';

export interface ShellCallbacks {
  /** Invoked after the server session is gone, so the caller can show sign-in. */
  onSignedOut: () => void;
}

/**
 * Whether this build has a Convex deployment to talk to.
 *
 * Read from the build-time env var, exactly as `src/services/convex-client.ts`
 * does, because that is the only signal that distinguishes "no backend
 * configured" from "backend refused the request". The capability context turns
 * this into the "not connected" states the pages render.
 */
export function isBackendConfigured(): boolean {
  try {
    return Boolean(import.meta.env?.VITE_CONVEX_URL);
  } catch {
    return false;
  }
}

/** The nav entry matching a shell route, for the active-item marker. */
function activeNavId(route: ShellRouteName): string {
  if (route === 'unknown') return '';
  return route;
}

/**
 * The page for a hash that matches no destination.
 *
 * Deliberately not a blank slate and not the dashboard: the reader has to be
 * able to tell a retired link from a working one, and to get back.
 */
function renderNotFoundPage(): SafeMarkup {
  return html`<div class="wga-page__inner" data-wga-page="not-found">
    ${renderPageHead(
      UNKNOWN_ROUTE.heading,
      UNKNOWN_ROUTE.sub,
      html`<a class="wga-btn wga-btn--primary" href="#/${DEFAULT_SHELL_ROUTE}">Go to dashboard</a>`,
    )}
  </div>`;
}

/**
 * Render the page for a shell route.
 *
 * An unrecognised hash gets the route's own not-found copy, not the dashboard.
 * The dashboard would be the friendlier-looking choice, and it is the wrong one:
 * the title would say "Not found" while the page showed onboarding, so a mistyped
 * or retired link would look like it worked. Following the spec's copy keeps the
 * two consistent, and the visible dashboard link gives the reader the way out.
 */
export function renderShellPage(
  route: ShellRouteName,
  user: SessionUser,
  entitlements: EntitlementContext,
): SafeMarkup {
  switch (route) {
    case 'workspace':
      return renderWorkspacePage(user, entitlements);
    case 'team':
      return renderTeamPage(user, entitlements);
    case 'settings':
      return renderSettingsPage(user, entitlements);
    case 'pricing':
      return renderPricingPage(entitlements);
    case 'unknown':
      return renderNotFoundPage();
    case 'dashboard':
    default:
      return renderDashboardPage(user, entitlements);
  }
}

export function mountShell(
  host: HTMLElement,
  user: SessionUser,
  callbacks: ShellCallbacks,
): () => void {
  const entitlements = createEntitlementContext(user, isBackendConfigured());

  // A sign-in that lands on the shell starts at the dashboard. `replaceState`
  // rather than assigning the hash: the sign-in view is not a history entry the
  // reader navigated to, and Back should not bounce them to a signed-out page.
  if (resolveLocation(currentHash()).route.name !== 'unknown' && currentHash() === '') {
    replaceHash(`#/${DEFAULT_SHELL_ROUTE}`);
  }

  let tornDown = false;
  let signingOut = false;

  mount(host, renderShell(user, entitlements, activeNavId(resolveLocation(currentHash()).route.name)));

  /** Render the page for `hash` into the slot, or hand off to SecureScan. */
  function renderRoute(): void {
    if (tornDown) return;

    const { route, handOff } = resolveLocation(currentHash());

    if (handOff) {
      const item = NAV_ITEMS.find(
        (entry) => entry.target.kind === 'securescan' && entry.target.hash === handOff.hash,
      );
      const href = item ? navHref(item) : secureScanHref(handOff.hash);
      window.location.assign(href);
      return;
    }

    const slot = host.querySelector<HTMLElement>('[data-wga-page-slot]');
    if (!slot) return;

    mount(slot, renderShellPage(route.name, user, entitlements));

    // Mark the active sidebar entry. Re-rendering the chrome for this is
    // unnecessary, and doing so would close the account menu on every click.
    // Scoped to the sidebar: `aria-current` must describe the one current page,
    // so it cannot be applied document-wide to every link carrying a route id.
    host
      .querySelectorAll<HTMLElement>('.wga-nav [data-wga-nav]')
      .forEach((link) => {
        const isActive = link.dataset['wgaNav'] === activeNavId(route.name);
        link.classList.toggle('wga-nav__link--active', isActive);
        if (isActive) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
      });

    document.title = `${route.title} · WM SecureScan`;
  }

  const onHashChange = (): void => renderRoute();

  const onClick = (event: Event): void => {
    if (tornDown || signingOut) return;
    const target = event.target as Element | null;
    const trigger = target?.closest?.('[data-wga-sign-out]');
    if (!trigger) return;
    event.preventDefault();
    signingOut = true;
    void signOut()
      .catch(() => {
        // A failed teardown still ends the local session view: the cookie may
        // already be gone, and leaving a live shell over a dead session would
        // be the worse failure. The next request re-validates regardless.
      })
      .finally(() => {
        signingOut = false;
        callbacks.onSignedOut();
      });
  };

  window.addEventListener('hashchange', onHashChange);
  host.addEventListener('click', onClick);
  renderRoute();

  return () => {
    if (tornDown) return;
    tornDown = true;
    window.removeEventListener('hashchange', onHashChange);
    host.removeEventListener('click', onClick);
    // Return the URL to the sign-in view's own `?view=` routing, so a later
    // sign-in is not dropped on a leftover shell route.
    replaceHash('');
  };
}
