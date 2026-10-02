// Server-side validation for the WorldGuard credential endpoints
// (api/auth/register.js, api/auth/login.js).
//
// The browser enforces the same policy in src/worldguard/services/validation.ts,
// but that is a UX affordance, not a boundary — everything is re-checked here
// because a client control's validity is never proof. The duplication is
// deliberate: legacy `api/*.js` entries are self-contained and may not import
// from `src/` (see the import-boundary rules in AGENTS.md), exactly as
// convex/worldguardUsers.ts carries its own copy of the email shape.
//
// Keep the two files in step: changing a rule on one side without the other is
// a bug (the client would accept a password the server rejects, or vice versa).

const EMAIL_RE = /^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$/;
const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 200;
const MAX_NAME_LENGTH = 120;
const MAX_EMAIL_LENGTH = 320;

export const PASSWORD_POLICY_LABEL =
  `Password must be at least ${MIN_PASSWORD_LENGTH} characters and include an uppercase letter, a lowercase letter, a number, and a symbol.`;

/** Trim and lowercase the whole address; the domain is case-insensitive. */
export function normalizeEmail(value) {
  return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

export function isValidEmail(email) {
  return email.length > 0 && email.length <= MAX_EMAIL_LENGTH && EMAIL_RE.test(email);
}

/** True when every published password requirement is satisfied. */
export function isValidPassword(password) {
  if (typeof password !== 'string') return false;
  if (password.length < MIN_PASSWORD_LENGTH || password.length > MAX_PASSWORD_LENGTH) return false;
  if (!/[a-z]/.test(password)) return false;
  if (!/[A-Z]/.test(password)) return false;
  if (!/[0-9]/.test(password)) return false;
  if (!/[^A-Za-z0-9]/.test(password)) return false;
  return true;
}

export function isValidName(name) {
  if (typeof name !== 'string') return false;
  const trimmed = name.trim();
  return trimmed.length > 0 && trimmed.length <= MAX_NAME_LENGTH;
}

/**
 * Validate a registration body. Returns `{ ok: true, value }` with normalized
 * fields, or `{ ok: false, field, message }` naming the first bad field. `field`
 * lets the UI attach the error to the right control.
 *
 * `acceptedTerms` must be present and `true`. The signup form's checkbox is a
 * convenience; without this check a direct POST to /api/auth/register could
 * create an account for an address whose owner never accepted the terms, and
 * the checkbox would still show as "required" in the UI. Anything other than a
 * literal boolean `true` is treated as a refusal.
 */
export function validateRegistration(body) {
  const email = normalizeEmail(body?.email);
  const name = typeof body?.name === 'string' ? body.name.trim() : '';
  const password = body?.password;

  if (body?.acceptedTerms !== true) {
    return { ok: false, field: 'acceptedTerms', message: 'Accept the terms and privacy policy to continue.' };
  }
  if (!isValidName(name)) {
    return { ok: false, field: 'name', message: 'Enter your name.' };
  }
  if (!isValidEmail(email)) {
    return { ok: false, field: 'email', message: 'Enter a valid email address.' };
  }
  if (!isValidPassword(password)) {
    return { ok: false, field: 'password', message: PASSWORD_POLICY_LABEL };
  }
  return { ok: true, value: { email, name, password } };
}

/**
 * Validate a sign-in body. Only presence and a sane length are checked here —
 * credential correctness is the bcrypt comparison's job, and a wrong password
 * must be reported as 401, not 400.
 */
export function validateLogin(body) {
  const identifier = normalizeEmail(body?.identifier ?? body?.email);
  const password = body?.password;

  if (!isValidEmail(identifier)) {
    return { ok: false, field: 'identifier', message: 'Enter a valid email address.' };
  }
  if (typeof password !== 'string' || password.length === 0 || password.length > MAX_PASSWORD_LENGTH) {
    return { ok: false, field: 'password', message: 'Enter your password.' };
  }
  return { ok: true, value: { identifier, password } };
}

/**
 * Parse a JSON request body with a hard size cap. Returns null when the body is
 * absent, not JSON, or larger than `maxBytes` — all of which the caller reports
 * as invalid input rather than crashing on a huge payload.
 */
export async function readJsonBody(req, maxBytes = 8 * 1024) {
  const raw = await req.text().catch(() => '');
  if (!raw || raw.length > maxBytes) return null;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}
