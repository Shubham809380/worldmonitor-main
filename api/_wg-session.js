// HttpOnly cookie transport for the WorldGuard user session (api/auth/google/*).
//
// The Google OAuth callback mints a user-bound HMAC token (api/_session.js) and
// stores it in the `wg-session` cookie here. The browser never sees the token —
// /api/auth/session reads the cookie server-side and reports the user profile.
//
// Kept separate from api/wm-session.js on purpose: wm-session is the anonymous
// browser-access credential and its name/domain handling must not be coupled
// to authentication. The wg-session cookie is host-only except on the
// .worldmonitor.app parent domain, mirroring the wm-session domain policy.
// Works with the Web Crypto / fetch APIs so it runs on both Vercel Edge and
// Node via the Vite dev dispatcher.

const WG_SESSION_COOKIE = 'wg-session';
const COOKIE_MAX_AGE_SECONDS = 12 * 60 * 60;

function shouldUseSharedCookieDomain(req) {
  const host = (req.headers.get('host') || new URL(req.url).hostname).toLowerCase();
  return host === 'worldmonitor.app' || host.endsWith('.worldmonitor.app');
}

function cookieDomainAttribute(req) {
  return shouldUseSharedCookieDomain(req) ? '; Domain=.worldmonitor.app' : '';
}

export function wgSessionCookie(req, value, maxAgeSeconds = COOKIE_MAX_AGE_SECONDS) {
  return `${WG_SESSION_COOKIE}=${encodeURIComponent(value)}; Path=/; Max-Age=${maxAgeSeconds}${cookieDomainAttribute(req)}; HttpOnly; Secure; SameSite=Lax`;
}

// Max-Age=0 tombstone for the shared-domain cookie plus a host-only tombstone
// so a stale host-only cookie (older deployments without the Domain attribute)
// can never shadow the shared one when both exist.
export function clearWgSessionCookies(req) {
  const hostOnly = `${WG_SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
  if (!shouldUseSharedCookieDomain(req)) return [hostOnly];
  return [hostOnly, `${WG_SESSION_COOKIE}=; Domain=.worldmonitor.app; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`];
}

/**
 * Read one cookie off the request. Mirrors the reader in `api/_api-key.js` /
 * `api/wm-session.js`; those do not export it, so it stays local.
 */
export function readWgSessionCookie(req) {
  const raw = req.headers.get('Cookie') || req.headers.get('cookie') || '';
  if (!raw) return '';
  const prefix = `${WG_SESSION_COOKIE}=`;
  for (const part of raw.split(';')) {
    const trimmed = part.trim();
    if (!trimmed.startsWith(prefix)) continue;
    try {
      return decodeURIComponent(trimmed.slice(prefix.length));
    } catch {
      return trimmed.slice(prefix.length);
    }
  }
  return '';
}