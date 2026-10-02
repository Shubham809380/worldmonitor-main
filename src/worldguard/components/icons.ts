/**
 * WorldGuard icon registry.
 *
 * Every icon is a static, author-controlled SVG path string — no user input
 * reaches this module, which is what licenses the `raw()` calls in
 * `./dom.ts`. Icons inherit `currentColor` so callers only set a colour.
 */

import { html, raw, type SafeMarkup } from './dom';

const PATHS = {
  shield: '<path d="M12 3 5 6v6c0 4.2 2.9 7.9 7 9 4.1-1.1 7-4.8 7-9V6l-7-3Z"/><path d="m9.2 12 2 2 3.6-3.8"/>',
  shieldCheck: '<path d="M12 3 5 6v6c0 4.2 2.9 7.9 7 9 4.1-1.1 7-4.8 7-9V6l-7-3Z"/>',
  radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12 18 6"/><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none"/>',
  globe: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.6 3 2.6 15 0 18"/><path d="M12 3c-2.6 3-2.6 15 0 18"/>',
  network: '<circle cx="12" cy="5" r="2.2"/><circle cx="5" cy="18" r="2.2"/><circle cx="19" cy="18" r="2.2"/><path d="M10.4 6.9 6.3 15.9"/><path d="m13.6 6.9 4.1 9"/><path d="M7.2 18h9.6"/>',
  lock: '<rect x="4.5" y="10" width="15" height="10" rx="2"/><path d="M8 10V7.5a4 4 0 0 1 8 0V10"/><path d="M12 14v2.5"/>',
  key: '<circle cx="8" cy="12" r="3.5"/><path d="M11.5 12H21"/><path d="M17.5 12v3.2"/><path d="M14.5 12v2.2"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3.6 6.4 7.3 5.2a2 2 0 0 0 2.2 0l7.3-5.2"/>',
  user: '<circle cx="12" cy="8.5" r="3.5"/><path d="M4.5 20a7.5 7.5 0 0 1 15 0"/>',
  users: '<circle cx="9" cy="8.5" r="3.2"/><path d="M2.8 20a6.2 6.2 0 0 1 12.4 0"/><path d="M16 5.6a3.2 3.2 0 0 1 0 5.8"/><path d="M17.4 14.3A6.2 6.2 0 0 1 21.2 20"/>',
  eye: '<path d="M2.5 12S6 5.8 12 5.8 21.5 12 21.5 12 18 18.2 12 18.2 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="2.8"/>',
  eyeOff: '<path d="M9.9 5.9A9.7 9.7 0 0 1 12 5.8c6 0 9.5 6.2 9.5 6.2a17 17 0 0 1-3.2 4"/><path d="M6.2 7.6A17.4 17.4 0 0 0 2.5 12S6 18.2 12 18.2a9.6 9.6 0 0 0 3.9-.8"/><path d="m3.5 3.5 17 17"/><path d="M10 10a2.8 2.8 0 0 0 4 4"/>',
  alert: '<path d="M10.3 4.3 2.6 17.4A2 2 0 0 0 4.3 20.4h15.4a2 2 0 0 0 1.7-3L13.7 4.3a2 2 0 0 0-3.4 0Z"/><path d="M12 9.5v4"/><circle cx="12" cy="16.8" r="1" fill="currentColor" stroke="none"/>',
  checkCircle: '<circle cx="12" cy="12" r="9"/><path d="m8.3 12.2 2.5 2.5 4.9-5.1"/>',
  check: '<path d="m4.5 12.5 5 5 10-11"/>',
  close: '<path d="m6 6 12 12"/><path d="m18 6-12 12"/>',
  arrowRight: '<path d="M4 12h15.5"/><path d="m13.5 6 6 6-6 6"/>',
  chevronRight: '<path d="m9.5 5.5 6.5 6.5-6.5 6.5"/>',
  activity: '<path d="M2.5 12.5h4l2.5-7 4 14 2.5-7h6"/>',
  server: '<rect x="3" y="4" width="18" height="6.5" rx="1.8"/><rect x="3" y="13.5" width="18" height="6.5" rx="1.8"/><path d="M7 7.2h.01"/><path d="M7 16.7h.01"/>',
  database: '<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/>',
  cpu: '<rect x="7" y="7" width="10" height="10" rx="1.6"/><rect x="3.5" y="3.5" width="17" height="17" rx="3"/><path d="M9.5 1.8v1.7"/><path d="M14.5 1.8v1.7"/><path d="M9.5 20.5v1.7"/><path d="M14.5 20.5v1.7"/><path d="M1.8 9.5h1.7"/><path d="M1.8 14.5h1.7"/><path d="M20.5 9.5h1.7"/><path d="M20.5 14.5h1.7"/>',
  terminal: '<rect x="2.5" y="4" width="19" height="16" rx="2.4"/><path d="m6.5 9.5 3 2.8-3 2.8"/><path d="M12.5 15.5h5"/>',
  layers: '<path d="m12 3 9 4.8-9 4.8-9-4.8L12 3Z"/><path d="m3 12.4 9 4.8 9-4.8"/><path d="m3 16.9 9 4.8 9-4.8"/>',
  fingerprint: '<path d="M12 4.2a7.8 7.8 0 0 0-7.8 7.8v2.4"/><path d="M12 7.4a4.6 4.6 0 0 0-4.6 4.6v4.2"/><path d="M12 10.6a1.4 1.4 0 0 0-1.4 1.4v6.2"/><path d="M15.2 8.6A4.6 4.6 0 0 1 16.6 12v3.2"/><path d="M19.8 9.4A7.8 7.8 0 0 0 15.4 4.4"/><path d="M12 20.4a13 13 0 0 0 1.6-6.5"/>',
  satellite: '<path d="M6.5 10.5a5 5 0 0 1 7 0"/><path d="M3.8 7.6a9 9 0 0 1 12.4 0"/><path d="M12 13.5v7.5"/><circle cx="12" cy="11" r="1.4"/><path d="m5 21 3-3"/><path d="m19 21-3-3"/>',
  zap: '<path d="M13.2 2.5 4.5 13.4h6.2l-.9 8.1 8.7-10.9h-6.2l.9-8.1Z"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.5"/><circle cx="12" cy="7.8" r="1" fill="currentColor" stroke="none"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 6.8V12l3.4 2.2"/>',
  refresh: '<path d="M20.4 11.5a8.5 8.5 0 1 0-.6 4.5"/><path d="M20.9 5.5v6h-6"/>',
  external: '<path d="M13.5 4.5H19.5V10.5"/><path d="M19.5 4.5 11 13"/><path d="M18 14.5v4a2 2 0 0 1-2 2h-10a2 2 0 0 1-2-2v-10a2 2 0 0 1 2-2h4"/>',
  menu: '<path d="M3.5 7h17"/><path d="M3.5 12h17"/><path d="M3.5 17h17"/>',
  grid: '<rect x="3.5" y="3.5" width="7" height="7" rx="1.4"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.4"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.4"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.4"/>',
  target: '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="3.5"/><path d="M12 1.8v3.4"/><path d="M12 18.8v3.4"/><path d="M1.8 12h3.4"/><path d="M18.8 12h3.4"/>',
  fileSearch: '<path d="M13.5 3.5H7a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h6"/><path d="M13.5 3.5 19 9v3.5"/><path d="M13.5 3.5V9H19"/><circle cx="15.5" cy="15.5" r="3.2"/><path d="m18 18 2.2 2.2"/>',
  shieldAlert: '<path d="M12 3 5 6v6c0 4.2 2.9 7.9 7 9 4.1-1.1 7-4.8 7-9V6l-7-3Z"/><path d="M12 8.2v3.6"/><circle cx="12" cy="14.6" r="1" fill="currentColor" stroke="none"/>',
} as const;

export type IconName = keyof typeof PATHS;

export interface IconOptions {
  size?: number;
  className?: string;
  strokeWidth?: number;
  /** Decorative by default: pass a label to expose the icon to assistive tech. */
  label?: string;
}

function svgFrame(
  name: IconName,
  size: number,
  strokeWidth: number,
  className: string,
  a11y: SafeMarkup,
): SafeMarkup {
  // `raw()` is safe here: the path is a literal from the static registry above,
  // and every interpolated option goes through the `html` escaper.
  return html`<svg
    class="${className}"
    width="${size}"
    height="${size}"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="${strokeWidth}"
    stroke-linecap="round"
    stroke-linejoin="round"
    focusable="false"
    ${a11y}
  >${raw(PATHS[name])}</svg>`;
}

/** Build a stroked icon. `aria-hidden` unless an explicit `label` is supplied. */
export function icon(name: IconName, options: IconOptions = {}): SafeMarkup {
  const className = options.className ? `wg-icon ${options.className}` : 'wg-icon';
  const a11y = options.label
    ? html`role="img" aria-label="${options.label}"`
    : html`role="presentation" aria-hidden="true"`;
  return svgFrame(name, options.size ?? 20, options.strokeWidth ?? 1.6, className, a11y);
}

  /** Google's mark, used only for the Google sign-in hand-off button. */
export function googleMark(size = 18): SafeMarkup {
  return raw(
    `<svg width="${size}" height="${size}" viewBox="0 0 48 48" aria-hidden="true" focusable="false">` +
      '<path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5Z"/>' +
      '<path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65Z"/>' +
      '<path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24s.92 7.54 2.56 10.78l7.97-6.19Z"/>' +
      '<path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48Z"/>' +
      '</svg>',
  );
}
