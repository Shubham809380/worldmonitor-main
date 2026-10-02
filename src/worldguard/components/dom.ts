/**
 * Safe HTML construction for the WorldGuard surface.
 *
 * `scripts/enforce-safe-html.mjs` blocks every direct `innerHTML` assignment and
 * `insertAdjacentHTML()` call under `src/`, so markup is built as a string and
 * committed through `setTrustedHtml()` from the repository's audited utility.
 * That makes escaping a hard requirement rather than a review habit: this
 * module owns it.
 *
 * The `html` tagged template escapes every interpolation by default. The only
 * way to embed pre-built markup is `raw()`, which callers must justify at the
 * call site — in practice it is used for the icon registry in `./icons.ts` and
 * for the output of a nested `html` call, both of which are author-controlled.
 */

import { setTrustedHtml, trustedHtml } from '@/utils/dom-utils';

/** Markup that has been escaped (or explicitly marked raw) by this module. */
export class SafeMarkup {
  constructor(readonly value: string) {}
}

/**
 * Anything `html` will render. Arrays are accepted so a section can interpolate
 * a `.map()` result directly; each entry is rendered with the same rules as a
 * scalar, so a nested `html` result still arrives as markup and a plain string
 * is still escaped.
 */
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

/** Escape a value for interpolation into element text or a quoted attribute. */
export function escapeHtml(value: unknown): string {
  return String(value).replace(ESCAPE_RE, (char) => ESCAPES[char] ?? char);
}

function render(value: SafeValue): string {
  if (value === null || value === undefined || value === false) return '';
  if (value instanceof SafeMarkup) return value.value;
  if (Array.isArray(value)) return value.map((entry) => render(entry)).join('');
  return escapeHtml(value);
}

/**
 * Build escaped markup. Interpolated strings are treated as untrusted text, so
 * `html`<a href="${url}">` still needs `escapeAttribute(url)` semantics for
 * anything that could carry a `javascript:` scheme — use `safeHref()` for hrefs.
 */
export function html(strings: TemplateStringsArray, ...values: SafeValue[]): SafeMarkup {
  let out = strings[0] ?? '';
  for (let index = 0; index < values.length; index += 1) {
    out += render(values[index]) + (strings[index + 1] ?? '');
  }
  return new SafeMarkup(out);
}

/**
 * Mark pre-built markup as trusted so it can be nested in an `html` template.
 * Only pass author-controlled strings: the static icon registry, or the result
 * of another `html` call.
 */
export function raw(markup: string): SafeMarkup {
  return new SafeMarkup(markup);
}

const MOUNT_REASON =
  'WorldGuard: assembled by html() which escapes every interpolation, or raw() over the static icon registry.';

/** Replace an element's contents with previously-built markup. */
export function mount(el: Element, markup: SafeMarkup): void {
  setTrustedHtml(el, trustedHtml(markup.value, MOUNT_REASON));
}

const SAFE_SCHEME_RE = /^(?:https?:|mailto:|tel:)/i;
const ROOT_RELATIVE_RE = /^\/(?!\/)/;

/**
 * Escape an href and drop it entirely when the scheme is not one this
 * application links out to. Escaping alone is not enough: a `javascript:` URL
 * survives attribute escaping intact.
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

/** Render a set of strings as list items, escaping each entry. */
export function list(items: readonly string[]): SafeMarkup {
  return html`${items.map((item) => html`<li>${item}</li>`)}`;
}
