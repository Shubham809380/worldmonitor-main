/**
 * WorldGuard root: the page the sign-in card sits on.
 *
 * A centred, full-height stage over a full-bleed backdrop that drifts
 * horizontally, with a soft glow and a vignette holding the card off it. The
 * card itself is rendered by `components/auth-shell.ts` into the slot below, so
 * the page owns the background and the card owns everything a reader touches.
 *
 * The backdrop is a still image, not footage. Earlier it was a screen
 * recording, which put a second login form behind the card; `01.png` has no UI
 * in it at all, so the card reads as the only form on screen.
 */

import { html, mount, type SafeMarkup } from '../components/dom';
import type { AuthViewName } from '../components/auth-shell';

export interface RootCallbacks {
  readonly openAuth: (view: AuthViewName) => void;
}

export function renderRoot(): SafeMarkup {
  return html`<div class="wg-stage">
    <div class="wg-stage__backdrop" aria-hidden="true"></div>
    <div class="wg-stage__glow" aria-hidden="true"></div>
    <div class="wg-stage__vignette" aria-hidden="true"></div>

    <div class="wg-stage__content" id="wg-main">
      <div class="wg-stage__right" data-wg-card-slot></div>
    </div>
  </div>`;
}

// ---- Behaviour ------------------------------------------------------------

const OPENABLE: readonly string[] = ['login', 'register', 'otp', 'forgot'];

function wireOpenButtons(root: ParentNode, openAuth: RootCallbacks['openAuth']): void {
  for (const trigger of root.querySelectorAll<HTMLButtonElement>('[data-wg-open]')) {
    trigger.addEventListener('click', () => {
      const view = trigger.dataset.wgOpen;
      if (view !== undefined && OPENABLE.includes(view)) {
        openAuth(view as AuthViewName);
      }
    });
  }
}

/**
 * Mount the root into `root` and return a teardown function.
 */
export function mountRoot(root: HTMLElement, callbacks: RootCallbacks): () => void {
  mount(root, renderRoot());
  wireOpenButtons(root, callbacks.openAuth);
  // Open on the sign-in view so the card is the first thing on screen.
  callbacks.openAuth('login');
  return () => {};
}
