/**
 * Safe HTML construction for SecureScan.
 *
 * `scripts/enforce-safe-html.mjs` blocks direct `innerHTML` and
 * `insertAdjacentHTML` under `src/`, so every string is built through this
 * module and committed via the repository's audited `setTrustedHtml`. That makes
 * escaping a hard requirement rather than a review habit.
 *
 * This matters more here than in a dashboard. Almost everything rendered is
 * attacker-influenceable: assessment names, target URLs, finding titles,
 * evidence payloads, and audit details are all strings that came from a scan of
 * a target somebody else may control. A single unescaped interpolation turns a
 * finding title into script execution in an admin's session.
 */

import { setTrustedHtml, trustedHtml } from '@/utils/dom-utils';

export class SafeMarkup {
  constructor(readonly value: string) {}
}

export type SafeValue =
  | SafeMarkup
  | string
  | number
  | null
  | undefined
  | false
  | readonly SafeValue[];

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

const ESCAPE_RE = /[&<>"']/g;

export function escapeHtml(value: unknown): string {
  return String(value).replace(ESCAPE_RE, (char) => ESCAPES[char] ?? char);
}

function render(value: SafeValue): string {
  if (value === null || value === undefined || value === false) return '';
  if (value instanceof SafeMarkup) return value.value;
  if (Array.isArray(value)) return value.map((entry) => render(entry)).join('');
  return escapeHtml(value);
}

/** Build escaped markup. Interpolations are untrusted unless produced by `html` or `raw`. */
export function html(strings: TemplateStringsArray, ...values: SafeValue[]): SafeMarkup {
  let out = strings[0] ?? '';
  for (let index = 0; index < values.length; index += 1) {
    out += render(values[index]) + (strings[index + 1] ?? '');
  }
  return new SafeMarkup(out);
}

/**
 * Mark author-controlled markup as trusted so it can nest in another `html`
 * call. Only ever pass a static icon or the result of another `html` call —
 * never a value that came from the backend.
 */
export function raw(markup: string): SafeMarkup {
  return new SafeMarkup(markup);
}

const MOUNT_REASON =
  'SecureScan: assembled by html() which escapes every interpolation, or raw() over the static icon registry.';

export function mount(el: Element, markup: SafeMarkup): void {
  setTrustedHtml(el, trustedHtml(markup.value, MOUNT_REASON));
}

const SAFE_SCHEME_RE = /^(?:https?:|mailto:|tel:)/i;
const ROOT_RELATIVE_RE = /^\/(?!\/)/;

/**
 * Escape an href, or drop it entirely when the scheme is not one this
 * application links to.
 *
 * Escaping alone is not sufficient: `javascript:alert(1)` contains no character
 * that HTML-escaping touches, so it survives attribute escaping completely
 * intact. A target URL read from a stored assessment row is exactly the kind of
 * value that must not be trusted this far, so it is scheme-checked here as well
 * as at creation time. Defence in depth on a value the user can also edit.
 */
export function safeHref(value: unknown): SafeMarkup | '' {
  const url = typeof value === 'string' ? value.trim() : '';
  if (url === '') return '';
  if (ROOT_RELATIVE_RE.test(url) || url.startsWith('#')) {
    return raw(escapeHtml(url));
  }
  if (SAFE_SCHEME_RE.test(url)) {
    return raw(escapeHtml(url));
  }
  return '';
}
