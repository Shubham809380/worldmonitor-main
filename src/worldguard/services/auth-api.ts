/**
 * WorldGuard authentication API client.
 *
 * This is the integration point for the WorldGuard identity endpoints, served
 * by this app's own `api/auth/*` handlers (register, login, session, logout)
 * rather than by a separate service. Nothing here invents a success: a request
 * either reaches a real endpoint and returns its response, or it throws an
 * `AuthRequestError` carrying a code from the closed `AuthErrorCode` set.
 * `not_configured` means "this deployment has no such endpoint" and is what
 * drives an honest unavailable outcome in `./auth-session.ts`.
 *
 * Server text is never surfaced to the UI. A response body from an identity
 * service routinely echoes the submitted identifier back, and error strings can
 * name internal hosts, so messages are mapped from the status code instead.
 */

const DEFAULT_BASE = '/api/auth';
const REQUEST_TIMEOUT_MS = 12_000;

/** Closed set of user-visible failure modes. */
export type AuthErrorCode =
  | 'invalid_input'
  | 'invalid_credentials'
  | 'forbidden'
  | 'not_configured'
  | 'conflict'
  | 'rate_limited'
  | 'network'
  | 'service_error'
  | 'malformed_response'
  | 'aborted';

export class AuthRequestError extends Error {
  constructor(
    readonly code: AuthErrorCode,
    message: string,
    readonly status: number = 0,
    /** Seconds the caller should wait, parsed from `Retry-After`. */
    readonly retryAfterSeconds: number = 0,
  ) {
    super(message);
    this.name = 'AuthRequestError';
  }
}

/** True when the endpoint simply is not deployed, so a fallback is appropriate. */
export function isNotConfigured(error: unknown): boolean {
  return error instanceof AuthRequestError && error.code === 'not_configured';
}

const MESSAGES: Record<AuthErrorCode, string> = {
  invalid_input: 'Check the details you entered and try again.',
  invalid_credentials: 'Those credentials did not match an account.',
  forbidden: 'This account is not permitted to sign in here.',
  not_configured: 'Sign-in is not configured on this deployment. Please contact an administrator.',
  conflict: 'An account with this email already exists.',
  rate_limited: 'Too many attempts. Wait a moment before trying again.',
  network: 'We could not reach the authentication service. Check your connection.',
  service_error: 'The authentication service is having problems. Please try again shortly.',
  malformed_response: 'The authentication service returned an unexpected response.',
  aborted: 'The request was cancelled.',
};

/**
 * Machine codes the server may send that a status code alone cannot express.
 *
 * Only an enumerated identifier is ever read from a response body — never prose
 * and never an interpolated server string — so this stays consistent with the
 * "server text is never surfaced to the UI" rule above. An unrecognised code
 * falls back to the status-derived message.
 *
 * `google_only_account`: a 409 that means "this address signed up with Google and
 * has no local password", not "this address is already taken". Without this the
 * user would be told to retry a password they never set.
 */
const ERROR_CODE_MESSAGES: Record<string, string> = {
  google_only_account: 'This account uses Google sign-in. Continue with Google instead.',
};

/**
 * Server machine codes that override the status-derived outcome.
 *
 * `api/auth/clerk-bridge.ts` answers 503 for three different conditions, and
 * only two of them are worth retrying. It reports which one in the body as
 * `not_configured`, but that code was previously dropped on the floor, so a
 * deployment with no identity provider behind it was reported as a temporary
 * outage. Telling that reader to "try again shortly" is a dead end: nothing
 * about waiting can connect an absent provider.
 */
const ERROR_CODE_OVERRIDES: Readonly<Record<string, AuthErrorCode | undefined>> = {
  not_configured: 'not_configured',
};

/** Human-facing, server-text-free description of a failure. */
export function describeAuthError(error: unknown): string {
  if (error instanceof AuthRequestError) {
    if (error.code === 'rate_limited' && error.retryAfterSeconds > 0) {
      return `Too many attempts. Try again in ${error.retryAfterSeconds}s.`;
    }
    return MESSAGES[error.code] ?? MESSAGES.service_error;
  }
  // Not one of ours. A bug in our own code is not evidence about the reader's
  // connection, so it must not be reported as one — that sends people to check
  // a network that was working. The real cause is logged at the call site.
  return MESSAGES.service_error;
}

function baseUrl(): string {
  try {
    const configured = import.meta.env.VITE_WORLDGUARD_API_BASE;
    if (typeof configured === 'string' && configured.trim() !== '') {
      return configured.trim().replace(/\/+$/, '');
    }
  } catch {
    // No Vite env in this context — use the default.
  }
  return DEFAULT_BASE;
}

  function codeForStatus(status: number): AuthErrorCode {
    if (status === 400 || status === 422) return 'invalid_input';
    if (status === 401) return 'invalid_credentials';
    if (status === 403) return 'forbidden';
    if (status === 404 || status === 405 || status === 501) return 'not_configured';
    if (status === 409) return 'conflict';
    if (status === 429) return 'rate_limited';
    // A response that arrived is proof the network worked. Reporting 5xx as
    // `network` told the reader to check their connection for a fault that is
    // entirely server-side, and the only thing that fixes it is waiting.
    if (status >= 500) return 'service_error';
    // Only a status nothing else claims may fall back to `network`.
    return 'network';
  }

function parseRetryAfter(response: Response): number {
  const raw = response.headers.get('Retry-After');
  if (!raw) return 0;
  const seconds = Number.parseInt(raw, 10);
  if (!Number.isFinite(seconds) || seconds <= 0) return 0;
  return Math.min(seconds, 300);
}

function isJson(contentType: string | null): boolean {
  return Boolean(contentType && /\bjson\b/i.test(contentType));
}

/**
 * Map a recognised machine `error` code from a failed response to its own
 * message. Returns undefined for anything unrecognised, malformed, or
 * non-JSON, so the caller keeps the status-derived default. The body is read at
 * most once and only on the failure path.
 */
/** The `error` identifier a failed response carries, if it is a plain string. */
async function readServerErrorCode(response: Response): Promise<string | undefined> {
  if (!isJson(response.headers.get('content-type'))) return undefined;
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return undefined;
  }
  if (!body || typeof body !== 'object') return undefined;
  const code = (body as { error?: unknown }).error;
  return typeof code === 'string' ? code : undefined;
}

/**
 * Wording for a server machine code, if it names a known condition.
 *
 * Takes the already-read code rather than the response: a `Response` body can
 * only be consumed once, so reading it for the override check left nothing for
 * this and every server-supplied message silently reverted to the status
 * default.
 */
function messageForServerErrorCode(code: string | undefined): string | undefined {
  if (code === undefined) return undefined;
  return Object.prototype.hasOwnProperty.call(ERROR_CODE_MESSAGES, code)
    ? ERROR_CODE_MESSAGES[code]
    : undefined;
}

interface RequestOptions {
  readonly method: 'GET' | 'POST';
  readonly path: string;
  /**
   * JSON-encoded as-is. Not restricted to strings: `/auth/register` must send
   * `acceptedTerms` as a real boolean, because the server accepts only a
   * literal `true` and would reject a stringified `"true"`.
   */
  readonly body?: Record<string, unknown>;
  readonly signal?: AbortSignal;
  /** Attach the ambient session token; used for authenticated reads. */
  readonly authenticated?: boolean;
}

type TokenProvider = () => Promise<string | null>;

let tokenProvider: TokenProvider | null = null;

/**
 * Register how to obtain a bearer token for authenticated calls.
 *
 * WorldGuard's session authority is the HttpOnly `wg-session` cookie, not a
 * token this bundle can read, so there is nothing to register — the session
 * layer passes `null` to make that explicit and prevent a stale credential from
 * ever being attached silently.
 */
export function setAuthTokenProvider(provider: TokenProvider | null): void {
  tokenProvider = provider;
}

async function request<T>(options: RequestOptions): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const onExternalAbort = (): void => controller.abort();
  if (options.signal) {
    if (options.signal.aborted) controller.abort();
    else options.signal.addEventListener('abort', onExternalAbort, { once: true });
  }

  const headers: Record<string, string> = { Accept: 'application/json' };
  if (options.body) headers['Content-Type'] = 'application/json';
  if (options.authenticated && tokenProvider) {
    // Inside its own try: a token provider reads a session from a third-party
    // SDK, so it can throw or hang. Letting that escape `request()` bypassed
    // every mapping below and reached the caller as a bare error, which
    // `describeAuthError` then flattened into "check your connection" — again
    // blaming the reader for a fault on our side of the wire.
    try {
      const token = await tokenProvider();
      if (token) headers.Authorization = `Bearer ${token}`;
    } catch {
      // A missing token still produces a valid request; the server answers 401
      // and the normal mapping takes over, which is accurate.
    }
  }

  let response: Response;
  try {
    response = await fetch(`${baseUrl()}${options.path}`, {
      method: options.method,
      headers,
      ...(options.body ? { body: JSON.stringify(options.body) } : {}),
      signal: controller.signal,
      // Must be 'same-origin': sign-in endpoints answer with the HttpOnly
      // `wg-session` cookie, and 'omit' would make the browser discard the
      // Set-Cookie header. The sign-in would report success and then leave the
      // user anonymous, because /api/auth/session could not see the cookie.
      credentials: 'same-origin',
    });
  } catch (error) {
    if (isAbortError(error, options.signal)) {
      throw new AuthRequestError('aborted', MESSAGES.aborted);
    }
    throw new AuthRequestError('network', MESSAGES.network);
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', onExternalAbort);
  }

  if (!response.ok) {
    const serverCode = await readServerErrorCode(response);
    // A body code the server chose deliberately outranks the status guess, so a
    // 503 that means "nothing is configured here" is not reported as a blip.
    const override = serverCode === undefined ? undefined : ERROR_CODE_OVERRIDES[serverCode];
    const code = override ?? codeForStatus(response.status);
    throw new AuthRequestError(
      code,
      messageForServerErrorCode(serverCode) ?? MESSAGES[code],
      response.status,
      parseRetryAfter(response),
    );
  }

  if (response.status === 204) return undefined as T;
  if (!isJson(response.headers.get('content-type'))) {
    throw new AuthRequestError('malformed_response', MESSAGES.malformed_response, response.status);
  }
  try {
    return (await response.json()) as T;
  } catch {
    throw new AuthRequestError('malformed_response', MESSAGES.malformed_response, response.status);
  }
}

function isAbortError(error: unknown, external?: AbortSignal): boolean {
  if (external?.aborted) return true;
  return error instanceof DOMException && error.name === 'AbortError';
}

// ---- Wire contracts -------------------------------------------------------

export interface WorldGuardUser {
  readonly id: string;
  readonly email: string;
  readonly name: string | null;
}

export interface SessionResponse {
  readonly authenticated: boolean;
  readonly user: WorldGuardUser | null;
}

export interface LoginResponse extends SessionResponse {
  /** Set when the identity service requires a second factor before granting a session. */
  readonly otpRequired?: boolean;
  readonly challengeId?: string;
}

/**
 * Exchange a Clerk browser session for a WorldGuard session.
 *
 * Clerk owns the Google OAuth; this is the one-way bridge at the end of it. The
 * Clerk token travels as a Bearer credential in the request body rather than as
 * the ambient Authorization header, because `wg-session` — not the Clerk token —
 * is what every other WorldGuard request authorizes with. That separation is
 * deliberate: a failed bridge degrades to "sign in again" instead of leaving a
 * Clerk token attached to ordinary API traffic.
 *
 * Returns the same shape as the password flows so callers treat the three
 * sign-in paths identically.
 */
export function bridgeClerkSession(
  clerkToken: string,
  signal?: AbortSignal,
): Promise<SessionResponse> {
  return request<SessionResponse>({
    method: 'POST',
    path: '/clerk-bridge',
    body: { token: clerkToken },
    signal,
  });
}

export interface OtpChallengeResponse {
  readonly challengeId: string;
  /** Seconds until the challenge can be re-sent. */
  readonly retryAfterSeconds?: number;
}

// ---- Endpoints ------------------------------------------------------------

export function fetchSession(signal?: AbortSignal): Promise<SessionResponse> {
  return request<SessionResponse>({
    method: 'GET',
    path: '/session',
    signal,
    authenticated: true,
  });
}

export function loginWithPassword(
  identifier: string,
  password: string,
  signal?: AbortSignal,
): Promise<LoginResponse> {
  return request<LoginResponse>({
    method: 'POST',
    path: '/login',
    body: { identifier, password },
    signal,
  });
}

/**
 * Create an account and sign in.
 *
 * `acceptedTerms` is sent explicitly and re-checked by the server. The signup
 * form's checkbox is a convenience, not the control: a direct POST to
 * `/api/auth/register` would otherwise create an account without ever accepting
 * the terms, so the server treats a missing/false value as invalid input.
 */
export function registerAccount(
  email: string,
  password: string,
  name: string,
  acceptedTerms: boolean,
  signal?: AbortSignal,
): Promise<LoginResponse> {
  return request<LoginResponse>({
    method: 'POST',
    path: '/register',
    body: { email, password, name, acceptedTerms },
    signal,
  });
}

export function requestOtpCode(
  identifier: string,
  channel: 'email' | 'sms',
  signal?: AbortSignal,
): Promise<OtpChallengeResponse> {
  return request<OtpChallengeResponse>({
    method: 'POST',
    path: '/send-otp',
    body: { identifier, channel },
    signal,
  });
}

export function verifyOtpCode(
  challengeId: string,
  code: string,
  signal?: AbortSignal,
): Promise<LoginResponse> {
  return request<LoginResponse>({
    method: 'POST',
    path: '/verify-otp',
    body: { challengeId, code },
    signal,
  });
}

export function requestPasswordReset(identifier: string, signal?: AbortSignal): Promise<void> {
  return request<void>({
    method: 'POST',
    path: '/forgot-password',
    body: { identifier },
    signal,
  });
}

export function submitPasswordReset(
  token: string,
  password: string,
  signal?: AbortSignal,
): Promise<void> {
  return request<void>({
    method: 'POST',
    path: '/reset-password',
    body: { token, password },
    signal,
  });
}

export function logout(signal?: AbortSignal): Promise<void> {
  return request<void>({ method: 'POST', path: '/logout', body: {}, signal });
}
