/**
 * Authenticated shell guard.
 *
 * The sign-in flow worked and then stopped at a static "You are signed in" card.
 * These tests pin the properties that make the replacement trustworthy, each of
 * which is a way the shell could quietly become a lie:
 *
 *  1. **Every navigation entry resolves.** A sidebar link that goes nowhere is
 *     the specific failure this surface was rebuilt to fix, so the route table
 *     and the renderer are checked against each other rather than against a
 *     hand-written list that could drift.
 *  2. **No invented destinations.** Remediation and retesting are per-finding
 *     forms on the finding detail page, not routes. A test asserts no entry
 *     points at a SecureScan hash the app does not serve, so a future entry
 *     cannot quietly claim a route that resolves to "unknown".
 *  3. **Nothing is faked.** No plan beyond what the server reports, no counts,
 *     no upgrade button that implies a payment path. A backend that is absent
 *     must read as "not connected", never as "zero" and never as a purchase.
 *  4. **The gate stays server-side.** A capability marked unavailable must not
 *     disappear from the page, because hiding it would hide the reason.
 *
 * The backend is stubbed out rather than reached: this proves what the shell
 * does with the state it is given. That the server refuses a non-admin is
 * asserted there, not re-implemented here.
 */

import { describe, expect, it } from 'vitest';

import {
  NAV_ITEMS,
  NAV_SECTIONS,
  SECURE_SCAN_PATH,
  SHELL_ROUTES,
  isShellEntry,
  navHref,
  replaceHash,
  resolveLocation,
  secureScanHref,
} from '@/worldguard/routing';
import { createEntitlementContext } from '@/worldguard/services/entitlement-context';
import { renderShell } from '@/worldguard/components/app-shell';
import { renderDashboardPage } from '@/worldguard/pages/dashboard';
import { renderTeamPage, renderWorkspacePage } from '@/worldguard/pages/workspace';
import { renderSettingsPage } from '@/worldguard/pages/settings';
import { renderPricingPage } from '@/worldguard/pages/pricing';
import { renderShellPage } from '@/worldguard/shell';
import type { SessionUser } from '@/worldguard/services/auth-session';

/**
 * SecureScan's own route names, mirrored from `src/securescan/routing.ts`.
 *
 * Deliberately duplicated rather than imported: the two surfaces are separate
 * documents that must be independently deployable, and importing across the
 * boundary would make a shared chunk out of two apps that share nothing else.
 * The copy is what makes the "no invented destination" check meaningful — if
 * SecureScan renames a route, this list fails and the entry gets revisited.
 */
const SECURESCAN_ROUTES: readonly string[] = [
  'dashboard',
  'assessments',
  'assessment',
  'findings',
  'finding',
  'evidence',
  'report',
  'audit',
  'admin',
  'console',
];

const USER: SessionUser = {
  id: 'usr_1',
  name: 'Ada Lovelace',
  email: 'ada@example.com',
  image: null,
  plan: 'free',
};

function text(markup: { value: string }): string {
  return markup.value;
}

describe('replaceHash', () => {
  // Chromium treats `replaceState(state, '', '')` as a no-op and keeps the
  // fragment. Sign-out clears the hash, so if that regressed, a stale route
  // would survive on the sign-in form. This is the cheapest place to catch it,
  // because a DOM assertion on the shell would not notice.
  it('clears the fragment rather than leaving it in place', () => {
    window.history.replaceState({}, '', '/worldguard.html#/settings');
    expect(window.location.hash).toBe('#/settings');

    replaceHash('');

    expect(window.location.hash).toBe('');
    expect(window.location.pathname).toBe('/worldguard.html');
  });

  it('keeps the path and query when setting a hash', () => {
    window.history.replaceState({}, '', '/worldguard.html?view=register#/team');
    replaceHash('#/dashboard');

    expect(window.location.hash).toBe('#/dashboard');
    expect(window.location.pathname).toBe('/worldguard.html');
    expect(window.location.search).toBe('?view=register');
  });

  it('drops only the fragment, not the query, when clearing', () => {
    window.history.replaceState({}, '', '/worldguard.html?view=register#/settings');
    replaceHash('');

    expect(window.location.hash).toBe('');
    expect(window.location.search).toBe('?view=register');
  });
});

describe('shell navigation', () => {
  it('gives every entry a unique id', () => {
    const ids = NAV_ITEMS.map((item) => item.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('resolves every entry to a page or a hand-off, never to nothing', () => {
    for (const item of NAV_ITEMS) {
      const resolved = resolveLocation(`#/${item.id}`);
      if (isShellEntry(item)) {
        expect(resolved.handOff, `shell entry "${item.id}" unexpectedly handed off`).toBeNull();
        // A shell entry that fell through to the unknown route would render a
        // reader-visible dead end even though its href looks fine.
        expect(resolved.route.name, `entry "${item.id}" resolved to unknown`).not.toBe('unknown');
      } else {
        // A hand-off carries no page to render, so `unknown` is the expected
        // route there; what matters is that the hand-off is present and points
        // somewhere, so the shell can forward instead of dead-ending.
        expect(resolved.handOff, `entry "${item.id}" did not hand off`).not.toBeNull();
        expect(resolved.handOff?.kind).toBe('securescan');
      }
    }
  });

  it('points only at SecureScan routes that actually exist', () => {
    for (const item of NAV_ITEMS) {
      // Narrow on the discriminated union rather than through `isShellEntry`:
      // a type predicate cannot *remove* the matching half of an interface, so
      // the `continue` path would still see the full `NavTarget`.
      if (item.target.kind !== 'securescan') continue;
      const route = item.target.hash.replace(/^#\/?/, '').split('?')[0] ?? '';
      expect(
        SECURESCAN_ROUTES,
        `entry "${item.id}" points at SecureScan route "${route}", which the app does not serve`,
      ).toContain(route);
    }
  });

  it('sends remediation and retesting to the findings surface, with the reason stated', () => {
    // These are per-finding actions, so there is no dedicated route to link to.
    // The entry must be honest about that rather than implying a queue exists.
    for (const id of ['remediation', 'retesting']) {
      const item = NAV_ITEMS.find((entry) => entry.id === id);
      expect(item, `missing nav entry: ${id}`).toBeDefined();
      expect(item!.target).toEqual({ kind: 'securescan', hash: '#/findings' });
      expect(item!.note, `entry "${id}" must explain where the work happens`).toBeTruthy();
    }
  });

  it('routes every sidebar entry to a usable href', () => {
    for (const item of NAV_ITEMS) {
      const href = navHref(item);
      expect(href, `entry "${item.id}" produced an empty href`).not.toBe('');
      if (isShellEntry(item)) {
        expect(href.startsWith('#/')).toBe(true);
      } else {
        expect(href.startsWith(SECURE_SCAN_PATH)).toBe(true);
      }
    }
  });

  it('lists every section in the sidebar order', () => {
    const used = new Set(NAV_ITEMS.map((item) => item.section));
    expect([...used].sort()).toEqual([...NAV_SECTIONS].sort());
  });

  it('uses root-relative cross-links, which is what safeHref permits', () => {
    // `safeHref` drops document-relative paths, so a `securescan.html/...` link
    // would silently render as `href=""` and land the reader back on this page.
    for (const item of NAV_ITEMS) {
      if (isShellEntry(item)) continue;
      expect(navHref(item).startsWith('/')).toBe(true);
      expect(navHref(item).startsWith('//')).toBe(false);
    }
    expect(secureScanHref('#/audit')).toBe('/securescan#/audit');
  });
});

describe('shell routing', () => {
  it('defaults an empty hash to the dashboard', () => {
    expect(resolveLocation('').route.name).toBe('dashboard');
    expect(resolveLocation('#').route.name).toBe('dashboard');
    expect(resolveLocation('#/').route.name).toBe('dashboard');
  });

  it('resolves each shell route to its own page', () => {
    for (const name of Object.keys(SHELL_ROUTES) as Array<keyof typeof SHELL_ROUTES>) {
      const resolved = resolveLocation(`#/${name}`);
      expect(resolved.route.name).toBe(name);
      expect(resolved.handOff).toBeNull();
      expect(resolved.route.heading).toBe(SHELL_ROUTES[name].heading);
    }
  });

  it('hands a SecureScan route to the SecureScan app rather than rendering it', () => {
    const resolved = resolveLocation('#/audit');
    expect(resolved.handOff).toEqual({ kind: 'securescan', hash: '#/audit' });
  });

  it('reads "not found" for an unknown segment instead of throwing', () => {
    const resolved = resolveLocation('#/not-a-real-page');
    expect(resolved.route.name).toBe('unknown');
    expect(resolved.handOff).toBeNull();
  });

  it('ignores a query string on the hash', () => {
    expect(resolveLocation('#/findings?assessmentId=ASM-1').handOff).toEqual({
      kind: 'securescan',
      hash: '#/findings',
    });
  });
});

describe('unresolvable routes', () => {
  it('says so rather than showing the dashboard under a "Not found" title', () => {
    const { route, handOff } = resolveLocation('#/nonsense');
    expect(route.name).toBe('unknown');
    expect(handOff).toBeNull();

    const markup = text(renderShellPage('unknown', USER, createEntitlementContext(USER, true)));
    expect(markup).toContain('data-wga-page="not-found"');
    expect(markup).toContain(route.heading);
    // The dashboard's own copy must not leak through, or the reader cannot tell
    // a retired link from a working one.
    expect(markup).not.toContain('Get started');
  });

  it('offers a way back to a working page', () => {
    const markup = text(renderShellPage('unknown', USER, createEntitlementContext(USER, true)));
    expect(markup).toContain('href="#/dashboard"');
  });

  it('marks no destination as current', () => {
    const markup = text(renderShell(USER, createEntitlementContext(USER, true), ''));
    expect(markup).not.toContain('aria-current="page"');
  });
});

describe('shell chrome', () => {
  it('gives the sidebar and the account menu distinct route hooks', () => {
    // The controller marks the current page with `aria-current` via
    // `data-wga-nav`. If the account menu reused that hook, the same route would
    // be marked current twice, and assistive tech would be told there are two
    // current pages.
    const markup = text(renderShell(USER, createEntitlementContext(USER, true), 'dashboard'));
    const menuItems = markup.match(/data-wga-menu-item="[^"]+"/g) ?? [];
    expect(menuItems.length).toBeGreaterThan(0);

    for (const route of ['settings', 'pricing']) {
      expect(markup).toContain(`data-wga-menu-item="${route}"`);
    }
  });

  it('marks exactly one sidebar entry as the current page', () => {
    const markup = text(renderShell(USER, createEntitlementContext(USER, true), 'pricing'));
    expect(markup).toContain('aria-current="page"');
    expect(markup.match(/aria-current="page"/g) ?? []).toHaveLength(1);
  });

  it('links the sidebar to every destination, cross-document entries included', () => {
    const markup = text(renderShell(USER, createEntitlementContext(USER, true), 'dashboard'));
    for (const item of NAV_ITEMS) {
      expect(markup, `sidebar is missing an entry for "${item.id}"`).toContain(
        `data-wga-nav=${item.id}`,
      );
    }
  });

  it('reports the session plan in the chrome rather than a stored one', () => {
    const free = text(renderShell(USER, createEntitlementContext(USER, true), 'dashboard'));
    expect(free).toContain('data-wga-plan=free');
    const pro = text(
      renderShell({ ...USER, plan: 'pro' }, createEntitlementContext({ ...USER, plan: 'pro' }, true), 'dashboard'),
    );
    expect(pro).toContain('data-wga-plan=pro');
  });
});

describe('entitlement context', () => {
  it('reports the plan the server sent and nothing more', () => {
    const context = createEntitlementContext(USER, true);
    expect(context.plan).toBe('free');
    expect(context.planLabel).toBe('Free');
  });

  it('marks assessment capabilities live only when a backend is configured', () => {
    const connected = createEntitlementContext(USER, true);
    expect(connected.backendUnconnected).toBe(false);
    expect(connected.capabilities.find((c) => c.id === 'findings')?.state).toBe('live');

    const offline = createEntitlementContext(USER, false);
    expect(offline.backendUnconnected).toBe(true);
    // "Not connected" must not read as "denied" or "zero".
    expect(offline.capabilities.find((c) => c.id === 'findings')?.state).toBe('backend_unavailable');
  });

  it('never reports billing as provisioned, whatever the plan says', () => {
    for (const plan of ['free', 'pro'] as const) {
      const context = createEntitlementContext({ ...USER, plan }, true);
      const billing = context.capabilities.find((c) => c.id === 'billing');
      expect(billing?.state).toBe('not_provisioned');
      expect(billing?.reason).toMatch(/not connected/i);
    }
  });
});

describe('dashboard', () => {
  it('shows no finding counts when they were never fetched', () => {
    const markup = text(renderDashboardPage(USER, createEntitlementContext(USER, true)));
    // A `0` here would be indistinguishable from a real zero.
    expect(markup).not.toMatch(/0\s*open findings/i);
    expect(markup).toContain('Open findings');
  });

  it('states that the workspace is not connected instead of implying empty data', () => {
    const markup = text(renderDashboardPage(USER, createEntitlementContext(USER, false)));
    expect(markup).toContain('not connected');
    expect(markup).toMatch(/nothing below is being faked/i);
  });

  it('omits the connect notice once a backend is configured', () => {
    const markup = text(renderDashboardPage(USER, createEntitlementContext(USER, true)));
    // The notice itself, not the phrase: billing is legitimately described as
    // "not connected" even here, and matching that phrase would make this
    // assertion pass for the wrong reason.
    expect(markup).not.toContain('SecureScan workspace not connected');
    expect(markup).not.toContain('wga-connect');
  });

  it('lists every capability with its state, including the unavailable ones', () => {
    const context = createEntitlementContext(USER, true);
    const markup = text(renderDashboardPage(USER, context));
    for (const cap of context.capabilities) {
      expect(markup).toContain(cap.label);
      // A hidden entry would hide the reason it is unavailable. The `html` tag
      // emits interpolated attribute values unquoted, hence the loose match.
      expect(markup).toContain(`data-wga-cap=${cap.id}`);
    }
  });
});

describe('team and workspace', () => {
  it('shows the single real member rather than an empty team', () => {
    const context = createEntitlementContext(USER, true);
    const team = text(renderTeamPage(USER, context));
    expect(team).toContain(USER.email);
    expect(team).toContain('Owner');
  });

  it('gates the invite affordance as "coming soon" with no active control', () => {
    const markup = text(renderTeamPage(USER, createEntitlementContext(USER, true)));
    expect(markup).toContain('data-wga-gate="invite"');
    expect(markup).toContain('Coming soon');
    // The gate is informational: a disabled-looking button would still be a
    // promise that it can be enabled.
    expect(markup).not.toMatch(/<button[^>]*>[^<]*Invite/i);
  });

  it('does not offer a role editor, because the server holds role', () => {
    const markup = text(renderTeamPage(USER, createEntitlementContext(USER, true)));
    expect(markup).toMatch(/Roles cannot be changed here/);
    expect(markup).not.toMatch(/<select/i);
  });

  it('states that there is one personal workspace', () => {
    const markup = text(renderWorkspacePage(USER, createEntitlementContext(USER, true)));
    expect(markup).toContain('Personal');
    expect(markup).toMatch(/One personal workspace/);
  });
});

describe('settings', () => {
  it('reports only fields the session endpoint actually returns', () => {
    const markup = text(renderSettingsPage(USER, createEntitlementContext(USER, true)));
    expect(markup).toContain(USER.email);
    expect(markup).toContain(USER.id);
    // `provider` is not in the session payload, so the page must not claim a
    // sign-in method the server never reported.
    expect(markup).not.toMatch(/Provider/);
  });

  it('marks the identity read-only and explains why', () => {
    const markup = text(renderSettingsPage(USER, createEntitlementContext(USER, true)));
    expect(markup).toContain('data-wga-readonly');
    expect(markup).toMatch(/cannot be edited/i);
  });

  it('offers a real sign-out control', () => {
    const markup = text(renderSettingsPage(USER, createEntitlementContext(USER, true)));
    expect(markup).toContain('data-wga-sign-out');
    expect(markup).toContain('wg-session');
  });
});

describe('pricing', () => {
  it('never renders a payment form or a fake upgrade control', () => {
    const markup = text(renderPricingPage(createEntitlementContext(USER, true)));
    expect(markup).not.toMatch(/<form/i);
    expect(markup).not.toMatch(/type="password"/i);
    expect(markup).not.toMatch(/card number|expiry|cvv/i);
    // A button that says "Upgrade" and does not upgrade is the failure mode.
    expect(markup).not.toMatch(/<button[^>]*>[^<]*Upgrade/i);
  });

  it('marks the upgrade gate as coming soon', () => {
    const markup = text(renderPricingPage(createEntitlementContext(USER, true)));
    expect(markup).toContain('data-wga-gate="upgrade"');
    expect(markup).toContain('Coming soon');
  });

  it('says the external pricing page does not unlock SecureScan', () => {
    const markup = text(renderPricingPage(createEntitlementContext(USER, true)));
    expect(markup).toContain('worldmonitor.app/pro#pricing');
    expect(markup).toMatch(/does not\s+change anything on this page/i);
  });

  it('keeps feature rows honest about their real state', () => {
    const context = createEntitlementContext(USER, false);
    const markup = text(renderPricingPage(context));
    // Team seats are not provisioned regardless of the backend, so the row must
    // not be presented as something a purchase would switch on.
    expect(markup).toContain('data-wga-feature=workspace_membership');
    expect(markup).toContain('data-wga-state=not_provisioned');
    expect(markup).toMatch(/Not available yet/);
  });

  it('reports the plan from the session and admits it is not derived here', () => {
    const markup = text(renderPricingPage(createEntitlementContext(USER, true)));
    expect(markup).toContain('Free');
    expect(markup).toMatch(/no purchase can be made here/i);
  });
});
