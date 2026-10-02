/**
 * Shared link rendering for SecureScan pages.
 *
 * Every in-app link in the console is a hash href produced by `hrefFor`. Keeping
 * that in one place means a page cannot accidentally hand-roll `#/findings/${id}`
 * without encoding, and a reviewer grepping for a route change finds one file.
 */

import { hrefFor, type RouteName } from '../routing';
import { html, type SafeMarkup } from './dom';

export function link(
  label: string,
  route: RouteName,
  params: Record<string, string> = {},
  className?: string
): SafeMarkup {
  // Two separate `html` branches rather than an interpolated attribute string.
  // Interpolating `class="..."` as a value makes `html` escape the quotes, so the
  // markup rendered as literal text and the anchor lost its class. Passing
  // `className` as its own interpolated value also escapes a caller-supplied
  // class, so it cannot break out of the attribute.
  return className
    ? html`<a class="${className}" href="${hrefFor(route, params)}">${label}</a>`
    : html`<a href="${hrefFor(route, params)}">${label}</a>`;
}

/** The `id · control` line under a finding title in a list. */
export function idLine(parts: readonly (string | number | null | undefined)[]): SafeMarkup {
  const text = parts.filter((part) => part !== null && part !== undefined && part !== '').join(' · ');
  return html`<div class="ss-cell-id">${text}</div>`;
}
