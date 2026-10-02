/**
 * WorldGuard application shell.
 *
 * One HTML entry with two surfaces behind a single authentication decision: the
 * sign-in stage, and the signed-in product shell. The `?view=` query parameter
 * selects the initial sign-in surface and the auth controller keeps it in sync
 * via `replaceState`, so a deep link to `/worldguard?view=register` opens
 * directly on the registration form and the back button stays meaningful.
 *
 * The signed-in side is hash-routed instead (`src/worldguard/routing.ts`), which
 * is the same scheme SecureScan uses, so both surfaces of this entry reason
 * about location the same way.
 *
 * In the redesigned layout, both the root branding and the auth card are
 * rendered together on the same page rather than as separate full-screen views.
 */

import type { AuthViewName } from './components/auth-shell';
import { mountAuth, type AuthCallbacks } from './pages/auth';
import { mountRoot, type RootCallbacks } from './pages/root';
import { mountShell } from './shell';

const AUTH_VIEWS: readonly AuthViewName[] = ['login', 'register', 'otp', 'forgot'];

const VIEW_PARAM = 'view';

function bootTarget(): HTMLElement {
  const root = document.getElementById('wg-root');
  if (!root) throw new Error('WorldGuard: #wg-root is missing from the document.');
  return root;
}

/** Mark the boot skeleton as failed so it can explain itself instead of spinning. */
export function reportBootFailure(): void {
  document.getElementById('wg-boot')?.classList.add('wg-boot--failed');
}

function clearBootSkeleton(): void {
  document.getElementById('wg-boot')?.remove();
  document.getElementById('wg-boot-fallback')?.remove();
}

/**
 * Read the deep-linked auth view before anything can rewrite the URL.
 *
 * The root layout opens the sign-in view as soon as it mounts, which would
 * otherwise clear `?view=` before the auth controller ever reads it.
 */
function requestedAuthView(): AuthViewName {
  try {
    const requested = new URLSearchParams(window.location.search).get(VIEW_PARAM);
    if (requested && (AUTH_VIEWS as readonly string[]).includes(requested)) {
      return requested as AuthViewName;
    }
  } catch {
    // No URL access in this context; the caller falls back to the default.
  }
  return 'login';
}

/**
 * Seed the requested auth view into the URL before the auth controller mounts.
 */
function writeAuthView(view: string): void {
  try {
    const url = new URL(window.location.href);
    if (view === 'login') url.searchParams.delete(VIEW_PARAM);
    else url.searchParams.set(VIEW_PARAM, view);
    window.history.replaceState({ view }, '', url);
  } catch {
    // No history access
  }
}

/**
 * Drop `?view=` entirely.
 *
 * Used when the surface on screen is not one of the auth views (the account
 * view), so the URL stops claiming a form the user is no longer looking at.
 */
function clearAuthView(): void {
  try {
    const url = new URL(window.location.href);
    if (!url.searchParams.has(VIEW_PARAM)) return;
    url.searchParams.delete(VIEW_PARAM);
    window.history.replaceState({}, '', url);
  } catch {
    // History is unavailable (sandboxed frame, older engine) — the view is
    // still correct in-memory, only the URL stops tracking it.
  }
}

export function startWorldGuard(): void {
  const root = bootTarget();
  let rootTeardown: (() => void) | null = null;
  let authTeardown: (() => void) | null = null;
  let shellTeardown: (() => void) | null = null;

  // View to force on the next root mount, consumed once. A sign-out pins
  // 'login', so a session that started at `?view=register` does not reopen the
  // registration form on the way out.
  let pinnedView: AuthViewName | null = null;

  clearBootSkeleton();

  // Capture the deep link before the root's default sign-in open rewrites it.
  const initialView = requestedAuthView();

  // Mount the root layout first (renders the full page with card slot)
  const rootCallbacks: RootCallbacks = {
    openAuth: (view) => {
      const pinned = pinnedView;
      pinnedView = null;
      // The root's mount-time open is a default, not a user navigation: honour
      // `?view=` instead of clobbering it back to the sign-in view.
      writeAuthView(pinned ?? (authTeardown ? view : (view === 'login' ? initialView : view)));
      mountAuthInSlot();
    },
  };
  rootTeardown = mountRoot(root, rootCallbacks);

  // Mount the auth card into the right-side slot
  function mountAuthInSlot(): void {
    const cardSlot = root.querySelector<HTMLElement>('[data-wg-card-slot]');
    if (!cardSlot) return;
    if (authTeardown) return; // Already mounted

    const callbacks: AuthCallbacks = {
      // A fresh sign-in and an already-valid cookie both arrive here, so this is
      // the single place that decides where a signed-in user ends up.
      //
      // Deliberately NOT the main WorldMonitor dashboard. That dashboard resolves
      // "signed in" from Clerk alone (`src/services/auth-state.ts` ->
      // `getCurrentClerkUser()`), and a WorldGuard password account has no Clerk
      // session, so a user sent to `/` landed on a signed-out page whose "Sign In"
      // button pointed straight back here.
      //
      // Instead the signed-in surface is the WM SecureScan product shell, which is
      // gated on the session WorldGuard actually holds — the same session the
      // sign-in flow just established, re-validated by `/api/auth/session` on load.
      // The shell replaces the root layout rather than filling its card slot: a
      // sidebar and a top bar do not belong inside the sign-in split pane, and
      // leaving the auth chrome behind would make the product look like a dialog.
      onAuthenticated: (user) => {
        authTeardown?.();
        authTeardown = null;
        // The shell is not one of the auth views, so a surviving `?view=register`
        // would misreport the surface on screen (and survive a reload as a
        // misleading link). Drop it.
        clearAuthView();
        rootTeardown?.();
        rootTeardown = null;
        shellTeardown = mountShell(root, user, { onSignedOut: showSignIn });
      },
      onBackToRoot: () => {
        // In the new design, back just goes to login view
      },
    };
    authTeardown = mountAuth(cardSlot, callbacks);
  }

  /** Swap the signed-in shell back out for the sign-in card. */
  function showSignIn(): void {
    // Tear the shell down before the auth view goes back in: its `hashchange`
    // listener would otherwise render a page for a session that no longer exists
    // during the swap. The teardown also resets the hash for us.
    shellTeardown?.();
    shellTeardown = null;
    // The auth controller skips re-mounting if it is still live, so tear it down
    // as well: a sign-out must not leave a form bound to a dead session behind.
    authTeardown?.();
    authTeardown = null;
    writeAuthView('login');
    // The shell replaced the root layout, so the card slot the auth view needs
    // has to exist again before `mountAuthInSlot` can find it. `openAuth` fires
    // from the re-mounted root, which is what re-enters the card — pinned to
    // 'login' so a `?view=register` deep link does not survive the sign-out.
    pinnedView = 'login';
    rootTeardown?.();
    rootTeardown = mountRoot(root, rootCallbacks);
  }

  window.addEventListener('pagehide', () => {
    rootTeardown?.();
    authTeardown?.();
    shellTeardown?.();
    rootTeardown = null;
    authTeardown = null;
    shellTeardown = null;
  });
}
