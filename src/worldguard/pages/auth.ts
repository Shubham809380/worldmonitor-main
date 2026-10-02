/**
 * Authentication view controller.
 *
 * Owns the form state, the submissions, the one-time-code countdown, and the
 * Google hand-off. Every path terminates in one of three honest outcomes:
 *
 *  - `authenticated` — the server observably holds a session (the HttpOnly
 *    `wg-session` cookie). Show the transition veil, then hand the user to their
 *    destination.
 *  - `handoff` — Google's own surface took over the page. Stop intercepting; the
 *    session subscription decides what happens next.
 *  - `failed` — a real, mapped error, shown verbatim from the closed message set.
 *
 * Password registration additionally requires the terms checkbox and sends
 * `acceptedTerms`; the server re-checks it, so the checkbox is not the control.
 *
 * Nothing in this file stores a credential. Field values live in the in-memory
 * state object for the lifetime of the view and are dropped when it unmounts.
 */

import { EMPTY_FORM_STATE, renderForm, type AuthFormState, type OtpStage, type ResetStep } from '../components/auth-forms';
import { renderAuthShell, type AuthViewName } from '../components/auth-shell';
import { mount } from '../components/dom';
import { focusFirst, trapFocus, type FocusTrap } from '../services/a11y';
import {
  beginPasswordReset,
  completePasswordReset,
  createAccount,
  getSession,
  isAuthAvailable,
  maskDestination,
  openSignInSurface,
  openSignUpSurface,
  primeAuth,
  completeClerkBridge,
  clearClerkBridgeFlag,
  isClerkBridgeReturn,
  requestOtp,
  signInWithClerkEmail,
  signInWithGoogle,
  signInWithPassword,
  subscribeSession,
  verifyOtp,
  type AuthFlowOutcome,
  type SessionUser,
} from '../services/auth-session';
import {
  isCompleteOtp,
  isEmail,
  isValidIdentifier,
  normaliseIdentifier,
  normaliseOtp,
  passwordRequirements,
  passwordStrength,
} from '../services/validation';

const OTP_RESEND_SECONDS = 30;
const VEIL_DELAY_MS = 900;
const VIEW_PARAM = 'view';

const BRIDGE_NOTICE = 'Finishing Google sign-in…';

/**
 * How long the bridge card waits before telling the reader that the popup never
 * came back. Generous enough for a cold Clerk load plus the bridge's own 5s
 * session wait, short enough that a stuck card is never mistaken for progress.
 */
const BRIDGE_WATCHDOG_MS = 25_000;
const HANDOFF_NOTICE = 'Continue in the secure sign-in window that just opened.';
const AUTH_UNAVAILABLE_MESSAGE =
  'This deployment has no identity provider connected, so accounts cannot be created or signed into here. Use the World Monitor dashboard instead.';

export interface AuthCallbacks {
  readonly onAuthenticated: (user: SessionUser) => void;
  readonly onBackToRoot: () => void;
}

const AUTH_VIEWS: readonly AuthViewName[] = ['login', 'register', 'otp', 'forgot'];

/** First meaningful control per view, used to place focus after a re-render. */
const FIRST_FIELD: Record<AuthViewName, string> = {
  login: '#wg-identifier',
  register: '#wg-name',
  otp: '#wg-otp-identifier',
  forgot: '#wg-identifier',
};

function readViewFromUrl(): AuthViewName {
  try {
    const requested = new URLSearchParams(window.location.search).get(VIEW_PARAM);
    if (requested && (AUTH_VIEWS as readonly string[]).includes(requested)) {
      return requested as AuthViewName;
    }
  } catch {
    // No URL access in this context; fall through to the default.
  }
  return 'login';
}

function writeViewToUrl(view: AuthViewName): void {
  try {
    const url = new URL(window.location.href);
    if (view === 'login') url.searchParams.delete(VIEW_PARAM);
    else url.searchParams.set(VIEW_PARAM, view);
    window.history.replaceState({ view }, '', url);
  } catch {
    // History is unavailable (sandboxed frame, older engine) — routing is
    // still correct in-memory, only the URL stops tracking it.
  }
}

/**
 * Mount the authentication view. Returns a teardown function.
 */
export function mountAuth(root: HTMLElement, callbacks: AuthCallbacks): () => void {
  let state: AuthFormState = { ...EMPTY_FORM_STATE, view: readViewFromUrl() };

  if (!isAuthAvailable()) {
    state = { ...state, authUnavailable: true };
  } else {
    primeAuth();
  }

  const slot = document.createElement('div');
  // The shell renders this container's class and id; carry both across the swap
  // so the card's inner padding and the skip-link target survive it.
  slot.className = 'wg-auth__body';
  slot.id = 'wg-auth-form';
  const unlockScroll = () => {};
  mount(root, renderAuthShell());
  const shellSlot = root.querySelector<HTMLElement>('[data-wg-auth-slot]');
  if (shellSlot) shellSlot.replaceWith(slot);

  const veil = root.querySelector<HTMLElement>('[data-wg-veil]');
  const backButton = root.querySelector<HTMLButtonElement>('[data-wg-auth-back]');
  const page = root.querySelector<HTMLElement>('.wg-page--auth');

  let trap: FocusTrap | null = null;
  let countdown: ReturnType<typeof setInterval> | null = null;
  let veilTimer: ReturnType<typeof setTimeout> | null = null;
  let destroyed = false;

  // ---- Rendering ----------------------------------------------------------

  /**
   * Swap the active form in place. The trap is bound to the surrounding page,
   * which is never re-rendered, so it survives every swap — only focus has to be
   * re-placed, because the node that had it was just replaced.
   */
  function render(focusTarget?: string): void {
    if (destroyed) return;
    mount(slot, renderForm(state));
    if (focusTarget && focusFirst(slot, focusTarget)) return;
    const active = document.activeElement;
    if (active && !slot.contains(active)) focusFirst(slot, FIRST_FIELD[state.view]);
  }

  function update(patch: Partial<AuthFormState>, focusTarget?: string): void {
    state = { ...state, ...patch };
    render(focusTarget);
  }

  function setError(message: string | null, notice: string | null = null): void {
    state = { ...state, error: message, notice, invalidField: null, invalidMessage: null };
    render('[data-wg-form-error], [data-wg-form-notice]');
  }

  /**
   * Report a validation failure against one field and move focus to it.
   *
   * The message is announced once, from the notice at the top of the form, which
   * is the live region. The field carries the same text as helper text, because
   * "what is wrong" and "where to fix it" are different questions and a reader
   * scanning the form should not have to answer the first before the second.
   */
  function setFieldError(fieldId: string, message: string): void {
    state = {
      ...state,
      error: message,
      notice: null,
      invalidField: fieldId,
      invalidMessage: message,
    };
    render(`#${fieldId}`);
  }

  // ---- Session ----------------------------------------------------------

  function showVeil(message: string): void {
    const text = veil?.querySelector<HTMLElement>('[data-wg-veil-text]');
    if (text) text.textContent = message;
    if (veil) veil.hidden = false;
  }

  function completeAuthentication(user: SessionUser): void {
    showVeil('Session established. Opening your workspace…');
    veilTimer = setTimeout(() => callbacks.onAuthenticated(user), VEIL_DELAY_MS);
  }

  const detachSession = subscribeSession((next) => {
    if (next.status === 'authenticated') completeAuthentication(next.user);
  });

  // ---- Clerk bridge --------------------------------------------------------

  /**
   * Clerk has just handed the session back (the page was re-entered on
   * `?clerk=bridge`). Exchange it for a WorldGuard session immediately, without
   * waiting for a click — the user already authenticated, they are only waiting
   * on us to finish.
   *
   * The flag is cleared first so a reload or a re-render cannot start a second
   * exchange. The bridge is idempotent server-side, so a duplicate would be
   * harmless, but there is no reason to spend a round trip on it.
   */
  function resumeClerkBridge(): void {
    if (!isClerkBridgeReturn()) return;
    clearClerkBridgeFlag();
    if (!isAuthAvailable()) return;

    update({ busy: true, error: null, notice: BRIDGE_NOTICE });

    // The bridge itself is bounded, but *arriving here* is not. If Clerk's popup
    // closed without handing control back (user dismissed it, Google refused,
    // or `redirectUrlComplete` is not an authorised URL for this app) then no
    // navigation happens, no promise rejects, and the card would read
    // "Finishing Google sign-in…" indefinitely with no recovery. Cap it.
    let settled = false;
    const watchdog = setTimeout(() => {
      if (settled || destroyed) return;
      settled = true;
      update({
        busy: false,
        error:
          'Google sign-in did not return to SecureScan. If a Google window is still open, close it and try again.',
        notice: null,
      });
    }, BRIDGE_WATCHDOG_MS);

    void completeClerkBridge()
      .then((outcome) => {
        settled = true;
        clearTimeout(watchdog);
        settle(outcome);
      })
      .catch(() => {
        settled = true;
        clearTimeout(watchdog);
        update({
          busy: false,
          error: 'Google sign-in did not complete. Please try again.',
          notice: null,
        });
      });
  }

  /** Route a flow outcome to the right terminal state. */
  function settle(outcome: AuthFlowOutcome): void {
    switch (outcome.kind) {
      case 'authenticated':
        completeAuthentication(outcome.user);
        return;
      case 'needs_otp':
        update(
          {
            busy: false,
            view: 'otp',
            otpStage: 'verify',
            challengeId: outcome.challengeId,
            maskedDestination: outcome.maskedDestination,
            identifier: state.identifier,
            resendInSeconds: OTP_RESEND_SECONDS,
            error: null,
            notice: null,
            values: { ...state.values, otpIdentifier: state.identifier },
          },
          '#wg-otp-0',
        );
        startCountdown();
        writeViewToUrl('otp');
        return;
      case 'handoff':
        handOff(outcome.opened);
        return;
      case 'failed':
        update({ busy: false, error: outcome.message });
        return;
    }
  }

  /**
   * The page has navigated away to the backend-owned Google flow, which now owns
   * the next steps. `alreadyOpened` means the redirect was already issued.
   *
   * This never claims a window opened unless one did: if Google sign-in is not
   * configured there is no flow to hand off to, and saying otherwise would leave
   * the user tapping a button that goes nowhere.
   */
  function handOff(alreadyOpened: boolean): void {
    if (alreadyOpened) {
      update({ busy: false, notice: HANDOFF_NOTICE });
      return;
    }
    if (!isAuthAvailable()) {
      update({ busy: false, error: AUTH_UNAVAILABLE_MESSAGE });
      return;
    }
    const opened = state.view === 'register' ? openSignUpSurface() : openSignInSurface();
    if (opened.kind === 'handoff') {
      update({ busy: false, notice: HANDOFF_NOTICE });
      return;
    }
    update({ busy: false, error: opened.kind === 'failed' ? opened.message : AUTH_UNAVAILABLE_MESSAGE });
  }

  // ---- Countdown --------------------------------------------------------

  function startCountdown(): void {
    stopCountdown();
    countdown = setInterval(() => {
      const next = state.resendInSeconds - 1;
      if (next <= 0) {
        state = { ...state, resendInSeconds: 0 };
        stopCountdown();
        repaintResendButton();
        return;
      }
      state = { ...state, resendInSeconds: next };
      repaintResendButton();
    }, 1000);
  }

  function stopCountdown(): void {
    if (countdown !== null) {
      clearInterval(countdown);
      countdown = null;
    }
  }

  /** Update just the resend control — a full re-render would steal focus. */
  function repaintResendButton(): void {
    const button = slot.querySelector<HTMLButtonElement>('[data-wg-resend]');
    if (!button) return;
    if (state.resendInSeconds === 0) {
      button.disabled = false;
      button.textContent = 'Resend code';
    } else {
      button.disabled = true;
      button.textContent = `Resend in ${state.resendInSeconds}s`;
    }
  }

  // ---- Validation --------------------------------------------------------

  /**
   * DOM `name` of each field, keyed by the `state.values` entry it feeds.
   *
   * `field()` in `./auth-forms.ts` emits the field id as the `name` attribute,
   * so the DOM name and the state key are not the same string. Capturing values
   * used to query by state key alone and therefore never matched: the
   * identifier and password reached `signInWithPassword` as empty strings, and
   * every submission stopped at validation. This table is the only place the
   * two vocabularies are reconciled.
   */
  const FIELD_NAMES = {
    identifier: 'wg-identifier',
    name: 'wg-name',
    email: 'wg-email',
    password: 'wg-password',
    newPassword: 'wg-new-password',
    confirmPassword: 'wg-confirm-password',
    resetCode: 'wg-reset-code',
    otpIdentifier: 'wg-otp-identifier',
  } as const satisfies Record<string, string>;

  type FieldKey = keyof typeof FIELD_NAMES;

  function readValue(name: string): string {
    const el = slot.querySelector<HTMLInputElement>(`[name="${name}"]`);
    return el?.value ?? '';
  }

  /**
   * Copy one typed field into `state.values` without re-rendering.
   *
   * `render()` rebuilds the form from `state.values`, so a value that only ever
   * lived in the DOM is lost on the next re-render. That included the re-render
   * triggered by clearing a validation error, which wiped the very text the
   * reader had just corrected. Syncing on `input` keeps state authoritative
   * without a re-render per keystroke.
   */
  function syncFieldValue(input: HTMLInputElement): void {
    for (const key of Object.keys(FIELD_NAMES) as FieldKey[]) {
      if (FIELD_NAMES[key] !== input.name) continue;
      state = { ...state, values: { ...state.values, [key]: input.value } };
      return;
    }
  }

  /**
   * Retire a validation error in place.
   *
   * The helper text, the red border, and the alert are removed from the live
   * DOM instead of re-rendering, because re-rendering would replace the input
   * the reader is currently typing into and throw the caret back to the start.
   */
  function clearFieldError(fieldId: string): void {
    if (state.invalidField === null && state.error === null) return;
    state = { ...state, error: null, notice: null, invalidField: null, invalidMessage: null };

    const input = slot.querySelector<HTMLInputElement>(`[id="${fieldId}"]`);
    const field = input?.closest<HTMLElement>('.wg-field');
    if (input && field) {
      field.classList.remove('wg-field--invalid');
      input.setAttribute('aria-invalid', 'false');
      const hint = field.querySelector<HTMLElement>('.wg-field__hint');
      input.setAttribute('aria-describedby', hint?.id ?? '');
      field.querySelector('.wg-field__error')?.remove();
    }
    slot.querySelector('[data-wg-form-error]')?.remove();
    slot.querySelector('[data-wg-form-notice]')?.remove();
  }

  /** Copy the named fields out of the live DOM into `state.values`. */
  function captureValues(keys: readonly FieldKey[]): void {
    const next: Record<string, string> = { ...state.values };
    for (const key of keys) {
      next[key] = readValue(FIELD_NAMES[key]);
    }
    state = { ...state, values: next };
  }

  function otpCode(): string {
    const boxes = slot.querySelectorAll<HTMLInputElement>('[data-wg-otp-index]');
    let code = '';
    for (const box of boxes) code += box.value;
    return code;
  }

  function captureOtp(): void {
    state = { ...state, values: { ...state.values, code: otpCode() } };
  }

  function readOtpBoxes(): HTMLInputElement[] {
    return Array.from(slot.querySelectorAll<HTMLInputElement>('[data-wg-otp-index]'));
  }

  // ---- Submissions -------------------------------------------------------

  async function submitLogin(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (state.busy) return;
    captureValues(['identifier', 'password']);

    const identifier = normaliseIdentifier(state.values.identifier ?? '');
    const password = state.values.password ?? '';

    if (!isValidIdentifier(identifier)) {
      setFieldError('wg-identifier', 'Enter a valid email address or phone number.');
      return;
    }
    if (password === '') {
      setFieldError('wg-password', 'Enter your password.');
      return;
    }

    update({ busy: true, error: null, notice: null, values: { ...state.values, identifier } });
    settle(await signInWithPassword(identifier, password));
  }

  async function submitRegister(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (state.busy) return;
    captureValues(['name', 'email', 'password']);

    const name = (state.values.name ?? '').trim();
    const email = normaliseIdentifier(state.values.email ?? '');
    const password = state.values.password ?? '';
    const terms = slot.querySelector<HTMLInputElement>('[name="wg-terms"]')?.checked ?? false;

    if (name === '') {
      setFieldError('wg-name', 'Enter your full name.');
      return;
    }
    if (!isEmail(email)) {
      setFieldError('wg-email', 'Enter a valid email address.');
      return;
    }
    const unmet = passwordRequirements(password).filter((requirement) => !requirement.met);
    if (unmet.length > 0) {
      setFieldError(
        'wg-password',
        `Password needs: ${unmet.map((requirement) => requirement.label.toLowerCase()).join(', ')}.`,
      );
      return;
    }
    if (!terms) {
      setError('Accept the terms and privacy policy to continue.');
      return;
    }

    update({ busy: true, error: null, notice: null, values: { ...state.values, email } });
    settle(await createAccount(email, password, name, terms));
  }

  async function submitOtp(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (state.busy) return;

    if (state.otpStage === 'request' || !state.challengeId) {
      captureValues(['otpIdentifier']);
      const identifier = normaliseIdentifier(state.values.otpIdentifier ?? '');
      if (!isValidIdentifier(identifier)) {
        setError('Enter a valid email address or phone number.');
        return;
      }
      update({
        busy: true,
        error: null,
        notice: null,
        identifier,
        values: { ...state.values, otpIdentifier: identifier },
      });
      settle(await requestOtp(identifier));
      return;
    }

    captureOtp();
    const code = state.values.code ?? '';
    if (!isCompleteOtp(code)) {
      setError('Enter all six digits.');
      focusFirst(slot, '#wg-otp-0');
      return;
    }

    update({ busy: true, error: null, notice: null });
    settle(await verifyOtp(state.challengeId, code));
  }

  async function submitForgot(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (state.busy) return;

    if (state.resetStep === 1) {
      captureValues(['identifier']);
      const identifier = normaliseIdentifier(state.values.identifier ?? '');
      if (!isValidIdentifier(identifier)) {
        setFieldError('wg-identifier', 'Enter a valid email address or phone number.');
        return;
      }
      const outcome = await beginPasswordReset(identifier);
      if (outcome.kind === 'sent') {
        update(
          {
            busy: false,
            resetStep: 2 as ResetStep,
            resetSentTo: maskDestination(identifier),
            values: { ...state.values, identifier },
          },
          '#wg-reset-code',
        );
        return;
      }
      update({ busy: false, error: outcome.message });
      return;
    }

    if (state.resetStep === 2) {
      captureValues(['resetCode']);
      const code = (state.values.resetCode ?? '').trim();
      if (code.length < 4) {
        setFieldError('wg-reset-code', 'Enter the reset code from the email.');
        return;
      }
      update({
        busy: false,
        resetStep: 3 as ResetStep,
        resetToken: code,
        values: { ...state.values, resetCode: code },
      });
      focusFirst(slot, '#wg-new-password');
      return;
    }

    captureValues(['newPassword', 'confirmPassword']);
    const password = state.values.newPassword ?? '';
    const confirm = state.values.confirmPassword ?? '';
    if (password !== confirm) {
      setFieldError('wg-confirm-password', 'The two passwords do not match.');
      return;
    }
    const unmet = passwordRequirements(password).filter((requirement) => !requirement.met);
    if (unmet.length > 0) {
      setFieldError(
        'wg-new-password',
        `Password needs: ${unmet.map((requirement) => requirement.label.toLowerCase()).join(', ')}.`,
      );
      return;
    }

    update({ busy: true, error: null, notice: null });
    const outcome = await completePasswordReset(state.resetToken, password);
    if (outcome.kind === 'sent') {
      update(
        {
          busy: false,
          view: 'login',
          resetStep: 1 as ResetStep,
          resetToken: '',
          notice: 'Password updated. Sign in with your new password.',
          values: { ...state.values, newPassword: '', confirmPassword: '' },
        },
        '#wg-identifier',
      );
      writeViewToUrl('login');
      return;
    }
    update({ busy: false, error: outcome.message });
  }

  function onSubmit(event: Event): void {
    const target = event.target;
    if (!(target instanceof HTMLFormElement)) return;
    const submitEvent = event as SubmitEvent;    switch (target.dataset.wgForm) {
      case 'login':
        void submitLogin(submitEvent);
        break;
      case 'register':
        void submitRegister(submitEvent);
        break;
      case 'otp':
        void submitOtp(submitEvent);
        break;
      case 'forgot':
        void submitForgot(submitEvent);
        break;
      default:
        break;
    }
  }

  // ---- Navigation between views ------------------------------------------

  function goto(view: AuthViewName, options: { readonly reset?: boolean } = {}): void {
    stopCountdown();
    const base: AuthFormState = options.reset
      ? { ...EMPTY_FORM_STATE, authUnavailable: state.authUnavailable }
      : state;
    state = {
      ...base,
      view,
      error: null,
      notice: null,
      invalidField: null,
      invalidMessage: null,
      otpStage: 'request',
      challengeId: '',
      resendInSeconds: 0,
      identifier: state.identifier,
      values: options.reset ? {} : { ...state.values, password: '', newPassword: '', confirmPassword: '' },
    };
    writeViewToUrl(view);
    render(`#wg-identifier, #wg-otp-identifier, #wg-name`);
  }

  // ---- Event delegation ---------------------------------------------------

  slot.addEventListener('submit', onSubmit);

  slot.addEventListener('click', (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;

    const gotoButton = target.closest<HTMLElement>('[data-wg-goto]');
    if (gotoButton) {
      const view = gotoButton.dataset.wgGoto;
      if (view === 'login' || view === 'register' || view === 'otp' || view === 'forgot') {
        goto(view);
      }
      return;
    }

    if (target.closest('[data-wg-email]')) {
      // Awaited for the same reason as the Google arm below: the busy card only
      // clears on a terminal outcome, so a fire-and-forget promise would leave
      // the form spinning forever on every Clerk failure.
      void signInWithClerkEmail().then(settle, (error) => {
        console.warn('[worldguard] email sign-in threw unexpectedly:', error);
        settle({
          kind: 'failed',
          code: 'network',
          message: 'Email sign-in could not start. Please try again.',
        });
      });
      return;
    }

    if (target.closest('[data-wg-google]')) {
      // Awaited: `signInWithGoogle` reports a blocked popup or a Clerk
          // error as a terminal failure, and the busy card only clears on a
          // terminal outcome. Firing and forgetting left it spinning forever.
          //
          // The rejection arm is now a genuine last resort rather than the normal
          // path. `signInWithGoogle` handles every known failure internally and
          // opens Clerk's own sign-in surface, so reaching here means something
          // threw outside that contract.
          void signInWithGoogle().then(settle, (error) => {
            console.warn('[worldguard] google sign-in threw unexpectedly:', error);
            settle({
              kind: 'failed',
              code: 'network',
              message: 'Google sign-in could not start. Please try again.',
            });
          });
      return;
    }

    const toggle = target.closest<HTMLElement>('[data-wg-toggle-password]');
    if (toggle) {
      const revealed = !state.passwordRevealed;
      // Only capture from the DOM while the field is masked. A revealed field
      // renders empty on purpose — the password is never echoed into markup as
      // text — so re-reading it here would overwrite the value held in state
      // with an empty string and lose what the reader typed. `syncFieldValue()`
      // keeps state current while they type in the revealed field.
      if (!state.passwordRevealed) {
        captureValues(['password', 'newPassword', 'confirmPassword']);
      }
      state = { ...state, passwordRevealed: revealed };
      const fieldId = toggle.dataset.wgTogglePassword;
      render(fieldId ? `#${fieldId}` : undefined);
      return;
    }

    if (target.closest('[data-wg-resend]')) {
      const identifier = state.identifier || (state.values.otpIdentifier ?? '');
      if (state.resendInSeconds > 0 || !isValidIdentifier(normaliseIdentifier(identifier))) return;
      update({ busy: true, error: null, notice: null });
      void requestOtp(normaliseIdentifier(identifier)).then((outcome) => {
        if (outcome.kind === 'needs_otp') {
          state = {
            ...state,
            busy: false,
            otpStage: 'verify' as OtpStage,
            challengeId: outcome.challengeId,
            maskedDestination: outcome.maskedDestination,
          };
          startCountdown();
          render('#wg-otp-0');
          return;
        }
        settle(outcome);
      });
      return;
    }
  });

  // One-time-code boxes: auto-advance, backspace-to-previous, and paste.
  slot.addEventListener('input', (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement)) return;

    if (target.dataset.wgOtpIndex !== undefined) {
      const index = Number(target.dataset.wgOtpIndex);
      const boxes = readOtpBoxes();
      const digit = normaliseOtp(target.value);
      target.value = digit;
      state = { ...state, values: { ...state.values, code: otpCode() } };
      if (digit !== '' && index < boxes.length - 1) boxes[index + 1]?.focus();
      if (isCompleteOtp(state.values.code ?? '')) slot.querySelector<HTMLFormElement>('form')?.requestSubmit();
      return;
    }

    syncFieldValue(target);
    if (state.invalidField === target.id) clearFieldError(target.id);

    // Live password strength feedback while typing on the register form. Matched
    // on the DOM name, not the state key — see FIELD_NAMES above.
    if (target.name === FIELD_NAMES.password) {
      const value = target.value;
      const track = slot.querySelector<HTMLElement>('[data-wg-strength] .wg-meter__track');
      const fill = slot.querySelector<HTMLElement>('.wg-meter__fill');
      if (track && fill) {
        const strength = passwordStrength(value);
        track.setAttribute('aria-valuenow', String(strength.score));
        track.setAttribute('aria-label', `Password strength: ${strength.level}`);
        fill.className = `wg-meter__fill wg-meter__fill--${strength.level}`;
        fill.style.setProperty('--fill', `${strength.score * 25}%`);
        for (const item of slot.querySelectorAll<HTMLElement>('[data-requirement]')) {
          const met = passwordRequirements(value).some(
            (requirement) => requirement.id === item.dataset.requirement && requirement.met,
          );
          item.classList.toggle('is-met', met);
        }
      }
    }
  });

  slot.addEventListener('keydown', (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement) || event.key !== 'Backspace') return;
    if (target.dataset.wgOtpIndex === undefined) return;
    if (target.value !== '') return;
    const index = Number(target.dataset.wgOtpIndex);
    const boxes = readOtpBoxes();
    const previous = boxes[index - 1];
    if (previous) {
      event.preventDefault();
      previous.value = '';
      previous.focus();
      state = { ...state, values: { ...state.values, code: otpCode() } };
    }
  });

  slot.addEventListener('paste', (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement) || target.dataset.wgOtpIndex === undefined) return;
    const pasted = normaliseOtp(event.clipboardData?.getData('text') ?? '');
    if (pasted === '') return;
    event.preventDefault();
    const boxes = readOtpBoxes();
    const start = Number(target.dataset.wgOtpIndex);
    for (let offset = 0; offset < boxes.length; offset += 1) {
      const box = boxes[start + offset];
      if (!box) break;
      box.value = pasted[offset] ?? '';
    }
    state = { ...state, values: { ...state.values, code: otpCode() } };
    const lastFilled = boxes[Math.min(start + pasted.length, boxes.length) - 1];
    lastFilled?.focus();
    if (isCompleteOtp(state.values.code ?? '')) slot.querySelector<HTMLFormElement>('form')?.requestSubmit();
  });

  backButton?.addEventListener('click', () => callbacks.onBackToRoot());

  // ---- Boot ---------------------------------------------------------------

  writeViewToUrl(state.view);
  render(FIRST_FIELD[state.view]);
  if (page) trap = trapFocus(page, slot.querySelector<HTMLElement>('input, button') ?? undefined);

  // Already signed in when the view opens (cookie-backed session).
  const existing = getSession();
  if (existing.status === 'authenticated') {
    showVeil('Session already active. Opening your workspace…');
    veilTimer = setTimeout(() => callbacks.onAuthenticated(existing.user), VEIL_DELAY_MS);
  } else {
    // Only when there is no WorldGuard session already: a returning Clerk user
    // with a live session must land in the workspace, not start an exchange
    // whose result would be discarded.
    resumeClerkBridge();
  }

  return () => {
    destroyed = true;
    stopCountdown();
    if (veilTimer !== null) clearTimeout(veilTimer);
    detachSession();
    trap?.release();
    unlockScroll();
  };
}
