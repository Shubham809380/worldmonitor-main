/**
 * WorldGuard brand mark.
 *
 * A shield whose interior is a graticule — protection over a mapped world. Drawn
 * with `currentColor` strokes plus a CSS-variable accent so the same component
 * works on the dark landing page and the auth surface.
 */

import { html, raw, type SafeMarkup } from './dom';

export interface BrandOptions {
  readonly size?: number;
  /** Adds the animated draw-on + breathe cycle used in the hero. */
  readonly animated?: boolean;
}

const SHIELD_PATH = 'M16 3 5 7v10c0 6.1 4.6 11.6 11 13.4C22.4 28.6 27 23.1 27 17V7L16 3Z';

function markBody(size: number, animated: boolean): string {
  const cls = animated ? 'wg-brand__mark wg-brand__mark--animated' : 'wg-brand__mark';
  return (
    `<svg class="${cls}" width="${size}" height="${size}" viewBox="0 0 32 32" ` +
    'fill="none" role="presentation" aria-hidden="true" focusable="false">' +
    `<path class="wg-brand__shield" d="${SHIELD_PATH}" stroke="currentColor" ` +
    'stroke-width="1.7" stroke-linejoin="round" stroke-linecap="round"/>' +
    '<g class="wg-brand__graticule" stroke="currentColor" stroke-width="1.15" opacity="0.75">' +
    '<path d="M8.6 13.4h14.8"/><path d="M7.2 19.6h17.6"/>' +
    '<path d="M16 8.6c2.1 2.5 2.1 12.3 0 14.8"/>' +
    '<path d="M16 8.6c-2.1 2.5-2.1 12.3 0 14.8"/>' +
    '</g>' +
    '<circle class="wg-brand__node" cx="16" cy="16.4" r="1.7" fill="currentColor"/>' +
    '</svg>'
  );
}

export function brandMark(options: BrandOptions = {}): SafeMarkup {
  // Static, author-controlled path data — safe to mark raw.
  return raw(markBody(options.size ?? 32, options.animated ?? false));
}

export function brandLockup(options: BrandOptions & { readonly href?: string } = {}): SafeMarkup {
  const size = options.size ?? 30;
  const label = html`<span class="wg-brand__name">World<span class="wg-brand__name-accent">Guard</span></span>`;
  const mark = brandMark({ size, animated: options.animated });
  const inner = html`${mark}${label}`;
  if (!options.href) {
    return html`<span class="wg-brand">${inner}</span>`;
  }
  return html`<a class="wg-brand" href="${options.href}" aria-label="WorldGuard home">${inner}</a>`;
}
