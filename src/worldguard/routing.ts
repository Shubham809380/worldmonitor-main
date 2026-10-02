/**
 * Authenticated shell routing for WM SecureScan.
 *
 * The sign-in surface routes with `?view=`; the signed-in product needs a
 * back-button that means something, so the shell is hash-routed. It reuses the
 * same hash architecture as the SecureScan app (`src/securescan/routing.ts`)
 * rather than introducing a second router, and it never touches SecureScan's
 * route table — those entries are addressed across a document boundary.
 *
 * **`NAV_ITEMS` is the single source of truth for the sidebar.** The shell
 * renders navigation from it and the router resolves hashes through it, so an
 * item cannot appear in the sidebar and be unresolvable at the same time: a dead
 * link is unrepresentable rather than something a test has to catch. This is
 * why the destination of each entry is declared once, next to its label.
 *
 * Two destination kinds, because SecureScan is a separate document:
 *
 *  - `shell` — a page in this bundle (`#/dashboard`, `#/pricing`, …).
 *  - `securescan` — a route owned by `src/securescan/routing.ts`, reached as
 *    `securescan.html#<hash>`. The hash is passed through verbatim, so the
 *    SecureScan app stays the single authority on its own route names and
 *    nothing here can drift out of sync with it.
 *
 * A note on entries that are *not* their own SecureScan route: remediation and
 * retesting are per-finding actions rendered on the finding detail page
 * (`src/securescan/pages/finding-detail.ts` — `renderRemediationForm`,
 * `renderRetestForm`), gated on the finding's lifecycle state. There is no
 * `#/remediation` or `#/retesting` route to link to, and inventing one would
 * produce a link that resolves to SecureScan's "unknown route" view. Each such
 * entry therefore points at the findings surface, where that work is actually
 * performed, and carries a `note` so the UI can say so rather than implying a
 * dedicated queue exists.
 */

export type ShellRouteName = 'dashboard' | 'workspace' | 'team' | 'settings' | 'pricing' | 'unknown';

export interface ShellRouteSpec {
  readonly name: ShellRouteName;
  readonly title: string;
  readonly heading: string;
  readonly sub: string;
}

export const SHELL_ROUTES: Record<Exclude<ShellRouteName, 'unknown'>, ShellRouteSpec> = {
  dashboard: {
    name: 'dashboard',
    title: 'Dashboard',
    heading: 'Your security assessment workspace',
    sub: 'Where assessment work starts and what is still waiting on you.',
  },
  workspace: {
    name: 'workspace',
    title: 'Workspace',
    heading: 'Workspace',
    sub: 'The workspace this session is attached to, and what it is scoped to.',
  },
  team: {
    name: 'team',
    title: 'Team',
    heading: 'Team',
    sub: 'Members and roles. Roles are enforced on the server, not by this page.',
  },
  settings: {
    name: 'settings',
    title: 'Settings',
    heading: 'Account settings',
    sub: 'The identity and session the server reports for you, read-only.',
  },
  pricing: {
    name: 'pricing',
    title: 'Pricing',
    heading: 'Plans',
    sub: 'What each plan is intended to include, and the current state of billing for SecureScan.',
  },
};

export const DEFAULT_SHELL_ROUTE: ShellRouteName = 'dashboard';

/** Where a sidebar entry lives. */
export type NavTarget =
  | { readonly kind: 'shell'; readonly route: Exclude<ShellRouteName, 'unknown'> }
  | { readonly kind: 'securescan'; readonly hash: string };

export interface NavItem {
  /** Hash segment. Unique across the table, and resolvable by definition. */
  readonly id: string;
  readonly label: string;
  readonly section: string;
  readonly target: NavTarget;
  /**
   * Why this entry points where it does, when that is not obvious from the
   * label. Rendered as help text — an entry that needs a paragraph explaining
   * itself is a sign the routing is honest, not that the label is wrong.
   */
  readonly note?: string;
}

export const NAV_ITEMS: readonly NavItem[] = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    section: 'Overview',
    target: { kind: 'shell', route: 'dashboard' },
  },
  {
    id: 'assessments',
    label: 'Assessments',
    section: 'Assess',
    target: { kind: 'securescan', hash: '#/assessments' },
  },
  {
    id: 'findings',
    label: 'Findings',
    section: 'Assess',
    target: { kind: 'securescan', hash: '#/findings' },
  },
  {
    id: 'evidence',
    label: 'Evidence',
    section: 'Assess',
    target: { kind: 'securescan', hash: '#/evidence' },
  },
  {
    id: 'remediation',
    label: 'Remediation',
    section: 'Resolve',
    // Not a SecureScan route: remediation is recorded on a specific finding.
    target: { kind: 'securescan', hash: '#/findings' },
    note: 'Remediation is recorded against an individual finding, so it starts from the findings list.',
  },
  {
    id: 'retesting',
    label: 'Retesting',
    section: 'Resolve',
    // Not a SecureScan route either: a retest is a per-finding lifecycle action.
    target: { kind: 'securescan', hash: '#/findings' },
    note: 'A retest is run from the finding it resolves, and only a passing retest verifies a fix.',
  },
  {
    id: 'reports',
    label: 'Reports',
    section: 'Resolve',
    target: { kind: 'securescan', hash: '#/report' },
  },
  {
    id: 'audit',
    label: 'Audit Center',
    section: 'Assurance',
    target: { kind: 'securescan', hash: '#/audit' },
    note: 'Admin only — the server refuses the request for any other role.',
  },
  {
    id: 'workspace',
    label: 'Workspace',
    section: 'Manage',
    target: { kind: 'shell', route: 'workspace' },
  },
  {
    id: 'team',
    label: 'Team',
    section: 'Manage',
    target: { kind: 'shell', route: 'team' },
  },
  {
    id: 'settings',
    label: 'Settings',
    section: 'Manage',
    target: { kind: 'shell', route: 'settings' },
  },
  {
    id: 'pricing',
    label: 'Pricing / Upgrade',
    section: 'Manage',
    target: { kind: 'shell', route: 'pricing' },
  },
];

export const NAV_SECTIONS: readonly string[] = ['Overview', 'Assess', 'Resolve', 'Assurance', 'Manage'];

const NAV_BY_ID: ReadonlyMap<string, NavItem> = new Map(NAV_ITEMS.map((item) => [item.id, item]));

/**
 * Canonical path of the SecureScan document.
 *
 * `/securescan` is the public path, not the file name: `vercel.json` rewrites it
 * to `securescan.html`, and the Vite dev server resolves the extension-less form
 * of an MPA entry. Writing `/securescan.html` directly would be a path that
 * exists in exactly one of the two environments the surface runs in.
 *
 * Root-relative on purpose. It is what `safeHref` permits (`src/worldguard/
 * components/dom.ts` — a document-relative `securescan.html` would be dropped,
 * silently turning every cross-link into `href=""`), and it is stable when
 * WorldGuard is reached at `/worldguard` or `/worldguard.html` alike. The desktop
 * WebView is not a concern here: `src-tauri` references neither document.
 */
export const SECURE_SCAN_PATH = '/securescan';

/** Href into a SecureScan route, from any WorldGuard page. */
export function secureScanHref(hash: string): string {
  return `${SECURE_SCAN_PATH}${hash}`;
}

/** Full href for a sidebar entry: local hash, or the SecureScan document + hash. */
export function navHref(item: NavItem): string {
  if (item.target.kind === 'shell') return `#/${item.id}`;
  return secureScanHref(item.target.hash);
}

/**
 * True when this entry renders inside the shell rather than navigating away.
 *
 * A type predicate, not a plain boolean: every caller that asks this question
 * does so to reach the matching half of the target union afterwards, and a
 * boolean would force each of them to re-narrow by hand.
 */
export function isShellEntry(
  item: NavItem,
): item is NavItem & { readonly target: Extract<NavTarget, { readonly kind: 'shell' }> } {
  return item.target.kind === 'shell';
}

/** The SecureScan half of a destination, for callers that must hand off. */
export type SecureScanTarget = Extract<NavTarget, { readonly kind: 'securescan' }>;

export interface ResolvedLocation {
  readonly route: ShellRoute;
  /**
   * Set when the hash addresses a SecureScan route rather than a shell page. The
   * shell hands off instead of rendering, so this is a navigation instruction,
   * not a page to draw.
   */
  readonly handOff: SecureScanTarget | null;
}

export interface ShellRoute {
  readonly name: ShellRouteName;
  readonly title: string;
  readonly heading: string;
  readonly sub: string;
}

export const UNKNOWN_ROUTE: ShellRoute = {
  name: 'unknown',
  title: 'Not found',
  heading: 'That page does not exist',
  sub: 'Pick a destination from the navigation, or return to the dashboard.',
};

const DEFAULT_ROUTE_SPEC = SHELL_ROUTES[DEFAULT_SHELL_ROUTE];

/**
 * Resolve `location.hash` to a shell page or a SecureScan hand-off.
 *
 * An unrecognised segment resolves to the "not found" route rather than
 * throwing. Throwing here would blank the whole shell for one bad link, and a
 * mistyped URL should read as a mistyped URL.
 */
export function resolveLocation(hash: string): ResolvedLocation {
  const segment = hash.replace(/^#\/?/, '').split('?')[0]?.trim() ?? '';

  if (segment !== '') {
    const item = NAV_BY_ID.get(segment);
    if (item) {
      if (item.target.kind === 'securescan') {
        return { route: UNKNOWN_ROUTE, handOff: item.target };
      }
      const spec = SHELL_ROUTES[item.target.route];
      return { route: spec, handOff: null };
    }
  }

  return { route: segment === '' ? DEFAULT_ROUTE_SPEC : UNKNOWN_ROUTE, handOff: null };
}

/** Read the current location's hash, tolerating an unavailable `location`. */
export function currentHash(): string {
  try {
    return window.location.hash;
  } catch {
    return '';
  }
}

/**
 * Replace the hash without adding a history entry.
 *
 * The path and query are always restated explicitly. `replaceState(state, '', '')`
 * is a no-op in Chromium — an empty URL leaves the document exactly where it is,
 * fragment included — so clearing the hash has to name the document. Sign-out
 * depends on that: without it, `#/settings` would survive on a page showing the
 * sign-in form, and the next sign-in would resume a route from a session that no
 * longer exists.
 *
 * A `SecurityError` is swallowed for the same reason `currentHash` tolerates a
 * missing `location`: the route is still correct in memory.
 */
export function replaceHash(hash: string): void {
  try {
    const { pathname, search } = window.location;
    window.history.replaceState({}, '', `${pathname}${search}${hash}`);
  } catch {
    // History unavailable (sandboxed frame): the route is still correct in memory.
  }
}
