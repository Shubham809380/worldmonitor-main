/**
 * WorldGuard session layer — the single integration point for authentication.
 *
 * WorldGuard owns its own identity system and no third-party is its session
 * authority: accounts live in the `worldguard_users` Postgres table
 * (api/_worldguard-db.js) and every sign-in ends in the HttpOnly `wg-session`
 * cookie, not a provider token. Clerk appears only as a Google OAuth broker —
 * it runs the consent screen and vouches for a verified address, then gets out
 * of the way. There are two ways in:
 *
 *  - Password: `createAccount()` and `signInWithPassword()` POST to
 *    `/api/auth/register` and `/api/auth/login` (api/auth/register.js,
 *    api/auth/login.js). The server validates, bcrypt-hashes, writes the row,
 *    and sets the HttpOnly `wg-session` cookie.
 *  - Google: `signInWithGoogle()` navigates the full page to
 *    Clerk's Google popup, then re-entering here on `?clerk=bridge` to exchange
 *    the Clerk session for a WorldGuard one (api/auth/clerk-bridge.ts). That
 *    endpoint upserts by *verified* email so a password account and a Google
 *    identity stay one account, and returns the same `wg-session` cookie.
 *
 * The browser's only window into that cookie is `/api/auth/session`, which
 * verifies it server-side and reports `authenticated`/`anonymous`.
 *
 * The invariant is unchanged: no path here reports `authenticated` that cannot
 * be observed. "Observable" means a cookie-backed `/api/auth/session` answer.
 *
 * OTP and password-reset flows still have forms but have NO server counterpart
 * (`/api/auth/send-otp`, `/api/auth/verify-otp`, `/api/auth/forgot-password`,
 * `/api/auth/reset-password` do not exist). They surface a clear error rather
 * than pretending a session happened. Closing them properly needs a mail
 * provider and is tracked as follow-up work.
 */

import {
  continueWithGoogle,
  type GoogleStartFailure,
  getClerk,
  initClerk,
  openSignInAndWait,
  waitForClerkSessionToken,
} from '@/services/clerk';
import {
  bridgeClerkSession,
  describeAuthError,
  type AuthErrorCode,
  type AuthRequestError,
  isNotConfigured,
  loginWithPassword,
  logout as worldGuardLogout,
  registerAccount,
  requestOtpCode,
  requestPasswordReset,
  setAuthTokenProvider,
  type SessionResponse,
  submitPasswordReset,
  verifyOtpCode,
} from './auth-api';

/**
 * Where Clerk sends the main window after it owns the Google round-trip, and
 * where this page re-enters to finish the bridge.
 *
 * Built from the CURRENT pathname, not a hardcoded `/`: WorldGuard ships at
 * `/worldguard.html` and also under variant/dashboard routes, and the bridge has
 * to run on the page that can act on the result. Hardcoding a root path would
 * send the user to the dashboard, which never completes the exchange.
 */
const BRIDGE_RETURN_URL = (() => {
  const path = `${window.location.pathname}${window.location.search}`;
  return `${window.location.origin}${path}${path.includes('?') ? '&' : '?'}clerk=bridge`;
})();
const BRIDGE_FLAG = 'clerk';

/**
 * True when Clerk has just returned to this page with a session to bridge.
 *
 * Read from the URL rather than from memory because the Clerk popup completes on
 * Clerk's domain and navigates this tab: a page reload is the handoff, so the
 * flag is the only durable evidence that a bridge is owed.
 */
export function isClerkBridgeReturn(): boolean {
  try {
    return new URL(window.location.href).searchParams.get(BRIDGE_FLAG) === 'bridge';
  } catch {
    return false;
  }
}

/**
 * Drop the bridge flag from the visible URL once it has been consumed, so a
 * reload does not re-run the exchange and the address bar stays clean.
 */
export function clearClerkBridgeFlag(): void {
  try {
    const url = new URL(window.location.href);
    if (!url.searchParams.has(BRIDGE_FLAG)) return;
    url.searchParams.delete(BRIDGE_FLAG);
    window.history.replaceState(null, '', `${url.pathname}${url.search}${url.hash}`);
  } catch {
    // Nothing to clean up if the URL is unreadable.
  }
}

export interface SessionUser {
  readonly id: string;
  readonly name: string;
  readonly email: string;
  readonly image: string | null;
  readonly plan: 'free' | 'pro';
}

export type SessionState =
  | { readonly status: 'anonymous' }
  | { readonly status: 'authenticated'; readonly user: SessionUser }
  /** The session endpoint is unreachable, so nobody is (provably) signed in. */
  | { readonly status: 'unavailable' };

export type AuthFlowOutcome =
  | { readonly kind: 'authenticated'; readonly user: SessionUser }
  /** A second factor is required before a session is granted. */
  | { readonly kind: 'needs_otp'; readonly challengeId: string; readonly maskedDestination: string }
  /**
   * A flow outside this bundle took over (Clerk's Google popup). `opened` is
   * retained for API parity; the WorldGuard Google flow always opens Clerk's own
   * surface.
   */
  | { readonly kind: 'handoff'; readonly opened: boolean }
  | { readonly kind: 'failed'; readonly code: AuthErrorCode; readonly message: string };

export type PasswordResetOutcome =
  | { readonly kind: 'sent' }
  | { readonly kind: 'failed'; readonly code: AuthErrorCode; readonly message: string };

const EMAIL_NOT_AVAILABLE = 'Email sign-in is not available in this deployment. Continue with Google.';

/** Best-effort text for a caught throw, for a console-only diagnostic. */
function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function failure(error: unknown): AuthFlowOutcome {
  return { kind: 'failed', code: errorCode(error), message: describeAuthError(error) };
}

function notConfiguredOutcome(message: string): AuthFlowOutcome {
  return { kind: 'failed', code: 'not_configured', message };
}

/**
 * The server accepted the credentials, but the session it promised could not be
 * observed afterwards.
 *
 * This is deliberately NOT `not_configured`. The deployment answered, validated
 * the password and issued a token, so nothing is missing from the config and
 * "not available in this deployment" was a false diagnosis. It also must not
 * suggest Google: the same unreachable session would strand that reader on the
 * popup instead. This is a real fault with the same retry affordance as any
 * other transient server error.
 */
function sessionNotObservedOutcome(): AuthFlowOutcome {
  return {
    kind: 'failed',
    code: 'service_error',
    message: 'Signed in, but the session could not be confirmed. Please try again.',
  };
}

function notConfiguredReset(message: string): PasswordResetOutcome {
  return { kind: 'failed', code: 'not_configured', message };
}

// Last-known session, refreshed by `/api/auth/session`. The cookie is HttpOnly,
// so the client cannot read it synchronously; `getSession()` returns this cache
// and `subscribeSession()` keeps it honest on boot, focus and tab re-entry.
let cachedState: SessionState = { status: 'anonymous' };
let refreshInFlight: Promise<void> | null = null;

async function fetchSessionState(): Promise<SessionState> {
  let res: Response;
  try {
    res = await fetch('/api/auth/session', { method: 'GET', credentials: 'same-origin', cache: 'no-store' });
  } catch {
    return { status: 'unavailable' };
  }
  if (!res.ok) return { status: 'unavailable' };
  let data: { status?: unknown; user?: SessionUser } | null = null;
  try {
    data = await res.json();
  } catch {
    return { status: 'unavailable' };
  }
  if (data && data.status === 'authenticated' && data.user) return { status: 'authenticated', user: data.user };
  if (data && data.status === 'anonymous') return { status: 'anonymous' };
  return { status: 'unavailable' };
}

function refreshSession(): Promise<void> {
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = fetchSessionState()
    .then((state) => {
      cachedState = state;
    })
    .finally(() => {
      refreshInFlight = null;
    });
  return refreshInFlight;
}

/** True when this deployment can authenticate anyone at all. */
export function isAuthAvailable(): boolean {
  return true;
}

async function currentUser(): Promise<SessionUser | null> {
  await refreshSession();
  return cachedState.status === 'authenticated' ? cachedState.user : null;
}

export function getSession(): SessionState {
  return cachedState;
}

/**
 * Observe session changes. Fires once shortly after attach once the
 * cookie-backed state is fetched, so a fresh callback-signed cookie becomes
 * visible without a page reload. Also re-checks on visibility/focus so a
 * session established in another tab surfaces here.
 */
export function subscribeSession(listener: (state: SessionState) => void): () => void {
  let previousStatus: SessionState['status'] | null = null;
  const emit = (state: SessionState): void => {
    if (state.status !== previousStatus) {
      previousStatus = state.status;
      listener(state);
    }
  };
  void refreshSession().then(() => emit(cachedState));

  const onVisibility = (): void => {
    if (typeof document !== 'undefined' && document.visibilityState === 'visible') {
      void refreshSession().then(() => emit(cachedState));
    }
  };
  const onFocus = (): void => {
    if (typeof document !== 'undefined' && document.visibilityState !== 'hidden') {
      void refreshSession().then(() => emit(cachedState));
    }
  };
  if (typeof document !== 'undefined') {
    document.addEventListener('visibilitychange', onVisibility);
    window.addEventListener('focus', onFocus);
  }

  return () => {
    if (typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', onVisibility);
      window.removeEventListener('focus', onFocus);
    }
  };
}

/**
 * Warms the sign-in path so the first click has nothing to wait for. No
 * SDK to preload in a cookie-backed setup — the OAuth start endpoint is cold
 * anyway, so this is intentionally a no-op kept for API parity.
 */
export function primeAuth(): void {
  void refreshSession();
}

// ---- Password sign-in -----------------------------------------------------

export async function signInWithPassword(
  identifier: string,
  password: string,
  signal?: AbortSignal,
): Promise<AuthFlowOutcome> {
  try {
    const response = await loginWithPassword(identifier, password, signal);
    // A successful response is not yet a session; only the cookie-backed
    // session endpoint can confirm one was issued.
    const user = await currentUser();
    if (user) return { kind: 'authenticated', user };
    if (response.otpRequired && response.challengeId) {
      return {
        kind: 'needs_otp',
        challengeId: response.challengeId,
        maskedDestination: maskDestination(identifier),
      };
    }
    return sessionNotObservedOutcome();
  } catch (error) {
    if (isNotConfigured(error)) return notConfiguredOutcome(EMAIL_NOT_AVAILABLE);
    return failure(error);
  }
}

/**
 * Google sign-in, brokered by Clerk.
 *
 * Clerk OWNS the OAuth: it owns the Google social connection, runs the popup,
 * and holds the resulting browser session. This bundle never sees a Google
 * credential, and WorldGuard implements no Google OAuth code of its own.
 *
 * When Clerk completes, it sends the main window to BRIDGE_RETURN_URL, which
 * re-enters this page as `?clerk=bridge`. `completeClerkBridge()` then trades
 * the Clerk session for a WorldGuard one. Until that second step lands there is
 * no WorldGuard session, so this returns `handoff` and the page stops
 * intercepting — exactly the outcome a full-page navigation already produced.
 *
 * `continueWithGoogle` reports a non-started outcome when Clerk is unavailable
 * or the popup is blocked. Every such path opens Clerk's own sign-in surface
 * first, which carries the Google button, so the reader is not stranded.
 */
/**
 * Turn a non-started Google attempt into a reportable outcome.
 *
 * The previous version returned one message for every cause — "check that pop-ups
 * are allowed" — and only one of the causes that produces actually responds to a
 * site setting. Reporting a missing Clerk key as a popup problem sends the reader
 * to a settings page that cannot help, which is why retrying never worked.
 *
 * Split out from `signInWithGoogle` so the mapping is testable on its own and the
 * reason survives into logs rather than being flattened at the call site.
 */
export function googleStartFailure(
  reason: GoogleStartFailure | undefined,
  fallbackOpened: boolean,
): AuthFlowOutcome {
  // When Clerk's own surface is already on screen it carries the Google button,
  // so leading with an error would tell the reader a flow is broken while the
  // working one is in front of them. Name the cause for the log, not the user.
  if (fallbackOpened) {
    return {
      kind: 'failed',
      code: reason === 'auth-disabled' ? 'not_configured' : 'network',
      message:
        reason === 'auth-disabled'
          ? 'Sign-in is not configured on this deployment. Please contact an administrator.'
          : 'Google sign-in could not start here, so the regular sign-in form is open instead. Please try again.',
    };
  }

  switch (reason) {
    case 'popup-blocked':
      return {
        kind: 'failed',
        code: 'network',
        message: 'Google sign-in could not start. Check that pop-ups are allowed for this site, then try again.',
      };
    case 'auth-disabled':
      return {
        kind: 'failed',
        code: 'not_configured',
        message: 'Sign-in is not configured on this deployment. Please contact an administrator.',
      };
    default:
      return {
        kind: 'failed',
        code: 'network',
        message: 'Google sign-in did not complete. Please try again.',
      };
  }
}

export async function signInWithGoogle(): Promise<AuthFlowOutcome> {
  const started = await continueWithGoogle({
    redirectUrl: BRIDGE_RETURN_URL,
    redirectUrlComplete: BRIDGE_RETURN_URL,
  });

  // `handoff` used to be returned unconditionally and the promise ignored. That
  // made every failure mode indistinguishable: a blocked popup, an unauthorised
  // redirect URL, or a Clerk error all left the reader staring at
  // "Finishing Google sign-in…" with no error and no way back, because the
  // only thing that clears the busy card is a terminal outcome. Every
  // non-started outcome now carries its own cause, and has already opened a
  // working sign-in surface, so report it honestly.
  if (!started.started) {
    return googleStartFailure(started.reason, started.fallbackOpened);
  }
  return { kind: 'handoff', opened: true };
}

/**
 * Finish a Clerk round-trip: exchange the Clerk session token for a WorldGuard
 * session, then report it through the normal session pipeline so the rest of the
 * UI cannot tell this apart from a password login.
 *
 * Safe to call more than once — the bridge is idempotent for a given identity
 * (api/auth/clerk-bridge.ts reuses the existing row), so a reload or a racing
 * completion cannot mint a second account.
 */
export async function completeClerkBridge(
  signal?: AbortSignal,
  label = 'Google sign-in',
  waitMs?: number,
): Promise<AuthFlowOutcome> {
  // One message, but the reason is logged: these three failures used to be
  // indistinguishable at runtime, and "did not complete" tells neither the user
  // nor the next debugger which one happened.
  const failed = (reason: string): AuthFlowOutcome => {
    console.warn(`[worldguard] clerk bridge failed: ${reason}`);
    return {
      kind: 'failed',
      code: 'not_configured',
      message: `${label} did not complete. Please try again.`,
    };
  };

  // Clerk is loaded lazily and this is a fresh page load (the popup navigated
  // us here), so nothing has initialised the SDK yet. Without this the token
  // read below always comes back null and the bridge never runs.
  try {
    await initClerk();
  } catch (error) {
    return failed(`clerk-load-failed: ${describeError(error)}`);
  }

  // Not `getClerkToken()`: this page load races Clerk's session resolution, and
  // the premium-API token path can also discard a token it already holds. See
  // waitForClerkSessionToken for why a sign-in completion must not use it.
  //
  // `waitMs` only matters when this runs behind an interactive Clerk surface: a
  // reader still has to type a password, which takes longer than the default
  // wait. The Google path arrives with the session already established, so it
  // keeps the default.
  const clerkToken = await waitForClerkSessionToken(waitMs);
  if (!clerkToken) {
    return failed('no-clerk-session-token');
  }
  let session: SessionResponse;
  try {
    session = await bridgeClerkSession(clerkToken, signal);
  } catch (error) {
    return failure(error);
  }
  if (!session.authenticated || !session.user) {
    return failed(`bridge-not-authenticated: ${JSON.stringify(session)}`);
  }
  // Same shape as a password login, so the rest of the UI cannot tell the two
  // paths apart. `plan` is not part of the bridge response: WorldGuard accounts
  // are not Pro-entitled by signing in, and the session read back from the
  // server is the authority for that field.
  return {
    kind: 'authenticated',
    user: {
      id: session.user.id,
      name: session.user.name ?? '',
      email: session.user.email,
      image: null,
      plan: 'free',
    },
  };
}

/**
 * Passwordless sign-in entry point; the challenge step is `verifyOtp`.
 *
 * The one-time-code endpoints do not exist server-side yet, so this reports the
 * missing feature rather than pretending a challenge was sent. It must not be
 * worded as "email sign-in is not available": password sign-in over
 * `/api/auth/login` works, and conflating the two sent readers with a working
 * option to an administrator for a feature that was merely never built.
 */
/**
 * Sign in with an email address and password through Clerk.
 * The password fields on this page belong to WorldGuard's own Postgres accounts
 * (`api/auth/login.js`), and those sessions are invisible to Convex. SecureScan
 * authorizes on `ctx.auth`, so it needs a Clerk session. Rather than mint our own
 * JWTs for that, this opens Clerk's own sign-in surface - which is why it reuses
 * `completeClerkBridge` and cannot drift from the Google path.
 *
 * Clerk only offers a password field when Email address is enabled on the
 * instance. When it is not, Clerk shows its own screen and the reader is told
 * the truth here instead of being left on a form that can never succeed.
 */
export async function signInWithClerkEmail(): Promise<AuthFlowOutcome> {
  // Clerk's surface resolves the moment it opens, so the bridge must stay open
  // long enough for a human to type a password and submit. Three minutes is
  // generous but bounded: past it the outcome is still terminal, so the busy
  // card can always clear.
  const CLERK_EMAIL_SIGN_IN_WAIT_MS = 180_000;
  const opened = await openSignInAndWait();
  if (!opened) {
    return {
      kind: 'failed',
      code: 'not_configured',
      message: 'Email sign-in could not open. Use your email and password instead.',
    };
  }
  // Do not inspect `getClerk().user` here. `openSignInAndWait` resolves as soon
  // as Clerk's surface opens, which is *before* anybody has typed anything, so
  // that check reported "cancelled" under a form the reader was still filling
  // in. The session wait below is the signal that matters, and it is bounded so
  // closing the surface still ends as a terminal outcome.
  return completeClerkBridge(undefined, 'Email sign-in', CLERK_EMAIL_SIGN_IN_WAIT_MS);
}

export function openSignInSurface(): AuthFlowOutcome {
  return notConfiguredOutcome(
    'One-time code sign-in is not available yet. Use your email and password instead.',
  );
}

// ---- Registration ---------------------------------------------------------

/**
 * Create a password account and sign in.
 *
 * `acceptedTerms` is forwarded, not merely checked: the form's checkbox is a UX
 * affordance and the server treats a missing/false value as invalid input, so
 * dropping it here would make every registration fail with `invalid_input`.
 */
export async function createAccount(
  email: string,
  password: string,
  name: string,
  acceptedTerms: boolean,
  signal?: AbortSignal,
): Promise<AuthFlowOutcome> {
  try {
    const response = await registerAccount(email, password, name, acceptedTerms, signal);
    const user = await currentUser();
    if (user) return { kind: 'authenticated', user };
    if (response.otpRequired && response.challengeId) {
      return {
        kind: 'needs_otp',
        challengeId: response.challengeId,
        maskedDestination: maskDestination(email),
      };
    }
    return sessionNotObservedOutcome();
  } catch (error) {
    if (isNotConfigured(error)) return notConfiguredOutcome(EMAIL_NOT_AVAILABLE);
    return failure(error);
  }
}

export function openSignUpSurface(): AuthFlowOutcome {
  return notConfiguredOutcome(
    'One-time code sign-up is not available yet. Use your email and password instead.',
  );
}

// ---- One-time codes -------------------------------------------------------

export async function requestOtp(
  identifier: string,
  channel: 'email' | 'sms' = 'email',
  signal?: AbortSignal,
): Promise<AuthFlowOutcome> {
  try {
    const challenge = await requestOtpCode(identifier, channel, signal);
    return {
      kind: 'needs_otp',
      challengeId: challenge.challengeId,
      maskedDestination: maskDestination(identifier),
    };
  } catch (error) {
    if (isNotConfigured(error)) return notConfiguredOutcome(EMAIL_NOT_AVAILABLE);
    return failure(error);
  }
}

export async function verifyOtp(
  challengeId: string,
  code: string,
  signal?: AbortSignal,
): Promise<AuthFlowOutcome> {
  try {
    await verifyOtpCode(challengeId, code, signal);
    const user = await currentUser();
    if (user) return { kind: 'authenticated', user };
    return sessionNotObservedOutcome();
  } catch (error) {
    if (isNotConfigured(error)) return notConfiguredOutcome(EMAIL_NOT_AVAILABLE);
    return failure(error);
  }
}

/** Fixed resend cooldown; the WorldGuard OTP path has no live Retry-After. */
export function otpResendDelaySeconds(): number {
  return 30;
}

// ---- Password reset -------------------------------------------------------

export async function beginPasswordReset(
  identifier: string,
  signal?: AbortSignal,
): Promise<PasswordResetOutcome> {
  try {
    await requestPasswordReset(identifier, signal);
    return { kind: 'sent' };
  } catch (error) {
    if (isNotConfigured(error)) return notConfiguredReset(EMAIL_NOT_AVAILABLE);
    return { kind: 'failed', code: errorCode(error), message: describeAuthError(error) };
  }
}

export async function completePasswordReset(
  token: string,
  password: string,
  signal?: AbortSignal,
): Promise<PasswordResetOutcome> {
  try {
    await submitPasswordReset(token, password, signal);
    return { kind: 'sent' };
  } catch (error) {
    if (isNotConfigured(error)) return notConfiguredReset(EMAIL_NOT_AVAILABLE);
    return { kind: 'failed', code: errorCode(error), message: describeAuthError(error) };
  }
}

// ---- Sign out -------------------------------------------------------------

/**
 * Sign out of WorldGuard.
 *
 * Two independent sessions are cleared, because one sign-in can have created
 * both: Clerk still holds the browser session it brokered Google with, and the
 * WorldGuard side holds the `wg-session` cookie minted by the bridge. Clearing
 * only the latter would leave the user able to re-bridge into a session by
 * reloading the page. Clerk's own session is cleared through its client API
 * rather than an endpoint of ours.
 */
export async function signOut(): Promise<void> {
  // Best effort: clear the HttpOnly session cookie and revoke any WorldGuard
  // backend session, then report anonymous locally regardless of outcome.
  try {
    await worldGuardLogout();
  } catch {
    // No WorldGuard backend session. Not an error.
  }
  try {
    const clerk = getClerk();
    if (clerk) {
      await clerk.signOut({ redirectUrl: window.location.origin });
    }
  } catch {
    // Clerk unreachable or already signed out. The WorldGuard session is still
    // cleared above, and the bridge cannot resurrect it without a new sign-in.
  }
  cachedState = { status: 'anonymous' };
}

// ---- Helpers --------------------------------------------------------------

function errorCode(error: unknown): AuthErrorCode {
  if (error instanceof Object && 'code' in error) {
    const code = (error as AuthRequestError).code;
    if (typeof code === 'string') return code as AuthErrorCode;
  }
  return 'network';
}

/**
 * Reduce an identifier to a form safe to echo back in the UI — after an OTP is
 * sent the full address should never be rendered into the DOM.
 */
export function maskDestination(identifier: string): string {
  const value = identifier.trim();
  const at = value.indexOf('@');
  if (at > 0) {
    const local = value.slice(0, at);
    const domain = value.slice(at + 1);
    const head = local.slice(0, 1);
    const domainParts = domain.split('.');
    const top = domainParts[domainParts.length - 1] ?? '';
    const maskedDomain = `${domainParts[0]?.slice(0, 1) ?? ''}${'*'.repeat(3)}`;
    return `${head}${'*'.repeat(Math.max(local.length - 1, 1))}@${maskedDomain}${top ? `.${top}` : ''}`;
  }
  if (value.length <= 4) return '*'.repeat(value.length);
  return `${value.slice(0, 2)}${'*'.repeat(Math.max(value.length - 2, 1))}`;
}

// Authenticated WorldGuard reads carry no bearer token: the session lives
// entirely in the HttpOnly `wg-session` cookie. Passing null explicitly so the
// token provider can never silently fall back to a stale credential.
setAuthTokenProvider(null);

export { describeAuthError, type AuthErrorCode };