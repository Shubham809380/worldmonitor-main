/**
 * Authentication surface chrome: the sign-in card.
 *
 * Renders the card around the form — brand tile, version pill, the form slot,
 * and the session-transition veil. The forms themselves live in
 * `./auth-forms.ts`; the slot lets the controller swap between them without
 * rebuilding the card or moving focus out from under the reader.
 *
 * The card is the page's only visual object, so it carries the brand lockup
 * itself. Everything inside shares the card's horizontal padding, which is why
 * the brand row, the form and the footer line up on one edge.
 */

import { html, type SafeMarkup } from './dom';
import { icon } from './icons';
import { STAGE } from '../data/content';

export const AUTH_HEADINGS = {
  login: { title: 'Welcome back', sub: 'Sign in to continue to your security workspace.' },
  register: { title: 'Create your account', sub: 'Start with a read-only global assessment.' },
  otp: {
    title: 'Sign in with a one-time code',
    sub: 'No password needed — we send you a six-digit code.',
  },
  forgot: { title: 'Reset your password', sub: 'We will email a reset link if the account exists.' },
} as const;

export type AuthViewName = keyof typeof AUTH_HEADINGS;

const CARD_VERSION = 'v1.0.0';

export function renderAuthShell(): SafeMarkup {
  return html`<div class="wg-page wg-page--auth">
    <a class="wg-skip-link" href="#wg-auth-form">Skip to sign-in form</a>

    <div class="wg-auth">
      <main class="wg-auth__main">
        <article class="wg-auth__card">
          <header class="wg-auth__head">
            <span class="wg-auth__mark" aria-hidden="true">
              ${icon('shieldCheck', { size: 22, strokeWidth: 1.7 })}
            </span>
            <div class="wg-auth__identity">
              <p class="wg-auth__name">WM SecureScan</p>
              <p class="wg-auth__tagline">${STAGE.eyebrow}</p>
            </div>
            <span class="wg-auth__version">${CARD_VERSION}</span>
          </header>

          <div class="wg-auth__body" id="wg-auth-form" data-wg-auth-slot></div>

          <div class="wg-veil" data-wg-veil hidden>
            <div class="wg-veil__panel" role="status" aria-live="polite">
              <span class="wg-veil__spinner" aria-hidden="true"></span>
              <p class="wg-veil__text" data-wg-veil-text>Establishing your session…</p>
            </div>
          </div>
        </article>
      </main>
    </div>
  </div>`;
}
