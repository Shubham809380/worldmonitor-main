/**
 * WorldGuard authentication forms.
 *
 * Pure renderers: each takes an `AuthFormState` and returns markup. Submission,
 * validation and timers live in `../pages/auth.ts` — keeping them apart means a
 * re-render (e.g. after an error) never disturbs in-flight submission state.
 *
 * Field values round-trip through `state.values` so a failed attempt does not
 * clear what the user already typed.
 *
 * Boolean attributes are emitted only when true. Rendering `disabled="false"`
 * would disable the control, since HTML treats presence as truth.
 */

import {
  MIN_PASSWORD_LENGTH,
  OTP_LENGTH,
  passwordRequirements,
  passwordStrength,
} from '../services/validation';
import { AUTH_HEADINGS, type AuthViewName } from './auth-shell';
import { html, safeHref, type SafeMarkup } from './dom';
import { googleMark, icon, type IconName } from './icons';

export type ResetStep = 1 | 2 | 3;
/** One-time-code sign-in is two submissions: request a code, then verify it. */
export type OtpStage = 'request' | 'verify';

/** Public destination offered when no identity provider is configured. */
const PUBLIC_DASHBOARD_HREF = '/dashboard';

/** Id of the "auth not configured" notice, used to describe the locked form. */
const UNAVAILABLE_ALERT_ID = 'wg-auth-unavailable';

export interface AuthFormState {
  readonly view: AuthViewName;
  readonly busy: boolean;
  readonly error: string | null;
  readonly notice: string | null;
  /** Id of the field currently in error, for the red border + helper text. */
  readonly invalidField: string | null;
  /** Helper text shown under `invalidField`. */
  readonly invalidMessage: string | null;
  readonly identifier: string;
  readonly maskedDestination: string;
  readonly challengeId: string;
  readonly otpStage: OtpStage;
  /** Seconds until an OTP resend is permitted; 0 means available now. */
  readonly resendInSeconds: number;
  readonly passwordRevealed: boolean;
  readonly resetStep: ResetStep;
  readonly resetToken: string;
  readonly resetSentTo: string;
  readonly values: Readonly<Record<string, string>>;
  /** True when no identity provider at all is configured. */
  readonly authUnavailable: boolean;
}

export const EMPTY_FORM_STATE: AuthFormState = {
  view: 'login',
  busy: false,
  error: null,
  notice: null,
  invalidField: null,
  invalidMessage: null,
  identifier: '',
  maskedDestination: '',
  challengeId: '',
  otpStage: 'request',
  resendInSeconds: 0,
  passwordRevealed: false,
  resetStep: 1,
  resetToken: '',
  resetSentTo: '',
  values: {},
  authUnavailable: false,
};

// ---- Field primitives -----------------------------------------------------

interface FieldOptions {
  readonly id: string;
  readonly label: string;
  readonly value: string;
  readonly type?: 'text' | 'email' | 'tel' | 'password';
  readonly iconName?: IconName;
  readonly placeholder?: string;
  readonly autocomplete?: string;
  readonly inputmode?: string;
  readonly maxlength?: number;
  readonly required?: boolean;
  readonly disabled?: boolean;
  readonly hint?: string;
  /** Helper text plus a red border and `aria-invalid`. */
  readonly error?: string | null;
  /** Turns the control into a password field with a show/hide affix. */
  readonly secret?: boolean;
  readonly revealed?: boolean;
}

function field(options: FieldOptions): SafeMarkup {
  const disabled = options.disabled ?? false;
  const required = options.required ?? true;
  const isSecret = options.secret ?? false;
  const revealed = isSecret && (options.revealed ?? false);
  const type = isSecret ? (revealed ? 'text' : 'password') : (options.type ?? 'text');
  // A revealed password must not be echoed into the DOM as text, so the field
  // is left empty and the value is re-entered if it is hidden again.
  const value = revealed ? '' : options.value;
  const error = options.error ?? null;

  const hintId = options.hint ? `${options.id}-hint` : null;
  const errorId = error ? `${options.id}-error` : null;
  const describedBy = [hintId, errorId].filter((id) => id !== null).join(' ');

  const trailing = isSecret
    ? html`<button
        type="button"
        class="wg-field__affix"
        data-wg-toggle-password="${options.id}"
        aria-label="${revealed ? 'Hide password' : 'Show password'}"
        aria-pressed="${revealed ? 'true' : 'false'}"
      >${icon(revealed ? 'eyeOff' : 'eye', { size: 18 })}</button>`
    : '';

  const iconSlot = options.iconName
    ? html`<span class="wg-field__icon" aria-hidden="true">${icon(options.iconName, { size: 18 })}</span>`
    : '';

  return html`<div class="wg-field${error ? ' wg-field--invalid' : ''}">
    <label class="wg-field__label" for="${options.id}">${options.label}</label>
    <div class="wg-field__control">
      ${iconSlot}
      <input
        class="wg-field__input"
        id="${options.id}"
        name="${options.id}"
        type="${type}"
        value="${value}"
        placeholder="${options.placeholder ?? ''}"
        autocomplete="${options.autocomplete ?? 'off'}"
        inputmode="${options.inputmode ?? 'text'}"
        maxlength="${options.maxlength ?? 128}"
        spellcheck="false"
        autocapitalize="none"
        ${required ? 'required' : ''}
        ${disabled ? 'disabled' : ''}
        aria-invalid="${error ? 'true' : 'false'}"
        aria-describedby="${describedBy}"
      />
      ${trailing}
    </div>
    ${options.hint ? html`<p class="wg-field__hint" id="${hintId}">${options.hint}</p>` : ''}
    ${error ? html`<p class="wg-field__error" id="${errorId}">${error}</p>` : ''}
  </div>`;
}

/** The field-level error for `id`, or null when that field is not in error. */
function fieldError(state: AuthFormState, id: string): string | null {
  return state.invalidField === id ? state.invalidMessage : null;
}

function statusRegion(state: AuthFormState): SafeMarkup {
  if (state.authUnavailable) {
    // Announced once on load: this is a hard blocker, not a transient status.
    return html`<div
      class="wg-alert wg-alert--warn"
      id="${UNAVAILABLE_ALERT_ID}"
      role="alert"
      aria-live="assertive"
    >
      <span class="wg-alert__icon" aria-hidden="true">${icon('alert', { size: 16 })}</span>
      <div class="wg-alert__content">
        <p class="wg-alert__title">Authentication not configured</p>
        <p class="wg-alert__body">
          Sign-in is unavailable. No identity provider is configured for this
          deployment. The World Monitor dashboard remains public.
        </p>
        <a class="wg-alert__link" href="${safeHref(PUBLIC_DASHBOARD_HREF)}">
          View public dashboard ${icon('arrowRight', { size: 14, strokeWidth: 2 })}
        </a>
      </div>
    </div>`;
  }
  if (state.error) {
    return html`<div class="wg-alert wg-alert--danger" role="alert" data-wg-form-error>
      <span class="wg-alert__icon" aria-hidden="true">${icon('alert', { size: 16 })}</span>
      <p class="wg-alert__body">${state.error}</p>
    </div>`;
  }
  if (state.notice) {
    return html`<div class="wg-alert wg-alert--ok" role="status" data-wg-form-notice>
      <span class="wg-alert__icon" aria-hidden="true">${icon('checkCircle', { size: 16 })}</span>
      <p class="wg-alert__body">${state.notice}</p>
    </div>`;
  }
  return html`<div data-wg-form-status hidden></div>`;
}

/**
 * Wrap a view's interactive body.
 *
 * When no identity provider is configured, the wrapper goes `inert` and dims:
 * a credential form that looks live but cannot succeed is a worse message than
 * one that plainly reads as unavailable. The notice above it keeps its link.
 *
 * The dev server is the one exception. Locking there would make the whole
 * surface impossible to exercise — no clicking, no typing, no validation —
 * for a deployment problem the developer did not choose. The form is released
 * in dev only, and submitting still fails through `handOff()`'s
 * `AUTH_UNAVAILABLE_MESSAGE`, so it never pretends to have signed anyone in.
 * Production builds keep the lock untouched.
 */
function section(state: AuthFormState, children: SafeMarkup[]): SafeMarkup {
  const locked = state.authUnavailable && !import.meta.env.DEV;
  return html`<div class="wg-form__section${locked ? ' is-locked' : ''}" ${locked ? 'inert' : ''}>
    ${children}
  </div>`;
}

function submitButton(
  state: AuthFormState,
  label: string,
  options: { readonly trailingIcon?: IconName } = {},
): SafeMarkup {
  const busy = state.busy;
  return html`<button
    type="submit"
    class="wg-btn wg-btn--primary wg-btn--block"
    data-wg-submit
    ${busy ? 'disabled' : ''}
  >
    ${busy
      ? html`<span class="wg-btn__spinner" aria-hidden="true"></span>`
      : options.trailingIcon
        ? icon(options.trailingIcon, { size: 16, strokeWidth: 2 })
        : ''}
    <span>${busy ? 'Working…' : label}</span>
  </button>`;
}

function heading(state: AuthFormState): SafeMarkup {
  const copy = AUTH_HEADINGS[state.view];
  return html`<header class="wg-form__head">
    <h1 class="wg-form__title">${copy.title}</h1>
    <p class="wg-form__sub">${copy.sub}</p>
  </header>`;
}

function dividerRow(state: AuthFormState): SafeMarkup {
  if (state.authUnavailable || !import.meta.env.VITE_CLERK_PUBLISHABLE_KEY) return html``;
    return html`<div class="wg-divider">OR</div>
    <button type="button" class="wg-btn wg-btn--secondary wg-btn--block" data-wg-email
      ${state.busy ? 'disabled' : ''}>
      ${icon('mail', { size: 16, strokeWidth: 2 })} Continue with email
    </button>
    <div class="wg-divider">OR</div>
    <button type="button" class="wg-btn wg-btn--secondary wg-btn--block" data-wg-google
      ${state.busy ? 'disabled' : ''}>
      ${googleMark()} Continue with Google
    </button>`;
}

// ---- Views ----------------------------------------------------------------

export function renderLoginForm(state: AuthFormState): SafeMarkup {
  return html`<form
    class="wg-form"
    data-wg-form="login"
    novalidate
    aria-describedby="${state.authUnavailable ? UNAVAILABLE_ALERT_ID : ''}"
  >
    ${heading(state)}
    ${statusRegion(state)}

    ${section(state, [
      field({
        id: 'wg-identifier',
        label: 'Email address',
        value: state.values.identifier ?? state.identifier,
        iconName: 'mail',
        placeholder: 'you@company.com',
        autocomplete: 'email',
        inputmode: 'email',
        disabled: state.busy,
        error: fieldError(state, 'wg-identifier'),
      }),
      field({
        id: 'wg-password',
        label: 'Password',
        value: state.values.password ?? '',
        iconName: 'lock',
        placeholder: 'Enter your password',
        autocomplete: 'current-password',
        secret: true,
        revealed: state.passwordRevealed,
        disabled: state.busy,
        error: fieldError(state, 'wg-password'),
      }),
      html`<div class="wg-form__row wg-form__row--between">
        <label class="wg-check">
          <input type="checkbox" name="wg-remember" checked />
          <span class="wg-check__box" aria-hidden="true">${icon('check', { size: 12, strokeWidth: 2.6 })}</span>
          <span class="wg-check__label">Remember me</span>
        </label>
        <button type="button" class="wg-form__link wg-form__link--accent" data-wg-goto="forgot">Forgot password?</button>
      </div>`,
      submitButton(state, 'Sign in', { trailingIcon: 'arrowRight' }),
      dividerRow(state),
      html`<p class="wg-form__alt">
        Don't have an account?
        <button type="button" class="wg-form__link wg-form__link--accent" data-wg-goto="register">Create account</button>
      </p>`,
    ])}
  </form>`;
}

export function renderRegisterForm(state: AuthFormState): SafeMarkup {
  const password = state.values.password ?? '';
  const strength = passwordStrength(password);
  const requirements = passwordRequirements(password);

  return html`<form class="wg-form" data-wg-form="register" novalidate aria-describedby="${state.authUnavailable ? UNAVAILABLE_ALERT_ID : ''}">
    ${heading(state)}
    ${statusRegion(state)}

    ${section(state, [
      field({
        id: 'wg-name',
        label: 'Full name',
        value: state.values.name ?? '',
        iconName: 'user',
        placeholder: 'Ada Lovelace',
        autocomplete: 'name',
        disabled: state.busy,
        error: fieldError(state, 'wg-name'),
      }),
      field({
        id: 'wg-email',
        label: 'Work email',
        value: state.values.email ?? '',
        iconName: 'mail',
        placeholder: 'you@organisation.com',
        autocomplete: 'email',
        inputmode: 'email',
        disabled: state.busy,
        error: fieldError(state, 'wg-email'),
      }),
      field({
        id: 'wg-password',
        label: 'Password',
        value: password,
        iconName: 'lock',
        placeholder: `At least ${MIN_PASSWORD_LENGTH} characters`,
        autocomplete: 'new-password',
        secret: true,
        revealed: state.passwordRevealed,
        disabled: state.busy,
        error: fieldError(state, 'wg-password'),
      }),
      html`<div class="wg-meter" data-wg-strength>
        <div class="wg-meter__track" role="meter" aria-valuemin="0" aria-valuemax="4"
          aria-valuenow="${strength.score}" aria-label="Password strength: ${strength.level}">
          <span
            class="wg-meter__fill wg-meter__fill--${strength.level}"
            style="--fill: ${strength.score * 25}%"
          ></span>
        </div>
        <ul class="wg-meter__requirements">
          ${requirements.map(
            (requirement) => html`<li
              class="wg-meter__requirement${requirement.met ? ' is-met' : ''}"
              data-requirement="${requirement.id}"
            >
              <span class="wg-meter__tick" aria-hidden="true">
                ${icon('check', { size: 11, strokeWidth: 2.6 })}
              </span>
              <span>${requirement.label}</span>
            </li>`,
          )}
        </ul>
      </div>`,
      html`<label class="wg-check wg-check--block">
        <input type="checkbox" name="wg-terms" data-wg-terms required />
        <span class="wg-check__box" aria-hidden="true">${icon('check', { size: 12, strokeWidth: 2.6 })}</span>
        <span class="wg-check__label">
          I accept the
          <a href="${safeHref('/docs/terms')}">terms</a>
          and
          <a href="${safeHref('/docs/privacy')}">privacy policy</a>
        </span>
      </label>`,
      submitButton(state, 'Create account'),
      dividerRow(state),
      html`<p class="wg-form__alt">
        Already have an account?
        <button type="button" class="wg-form__link" data-wg-goto="login">Sign in</button>
      </p>`,
    ])}
  </form>`;
}

function stepIndicator(current: ResetStep): SafeMarkup {
  const steps = [1, 2, 3] as const;
  return html`<div class="wg-steps" role="list" aria-label="Password reset progress">
    ${steps.map((step, index) => html`<div class="wg-steps__item" role="listitem">
      ${index > 0 ? html`<span class="wg-steps__line${step <= current ? ' is-active' : ''}"></span>` : ''}
      <span class="wg-steps__dot${step <= current ? ' is-active' : ''}">
        ${step < current ? icon('check', { size: 11, strokeWidth: 2.6 }) : step}
      </span>
      <span class="wg-visually-hidden">
        Step ${step} of 3${step === current ? ', current' : step < current ? ', complete' : ''}
      </span>
    </div>`)}
  </div>`;
}

export function renderForgotForm(state: AuthFormState): SafeMarkup {
  if (state.resetStep === 2) {
    return html`<form class="wg-form" data-wg-form="forgot" novalidate aria-describedby="${state.authUnavailable ? UNAVAILABLE_ALERT_ID : ''}">
      ${heading(state)}
      ${statusRegion(state)}

      ${section(state, [
        stepIndicator(2),
        html`<p class="wg-form__sent">
          ${icon('mail', { size: 15 })}
          <span>
            Reset code sent to
            <strong class="wg-mono">${state.resetSentTo || 'your address'}</strong>
          </span>
        </p>`,
        field({
          id: 'wg-reset-code',
          label: 'Reset code',
          value: state.values.resetCode ?? '',
          iconName: 'key',
          placeholder: 'Paste the code from the email',
          autocomplete: 'one-time-code',
          disabled: state.busy,
          error: fieldError(state, 'wg-reset-code'),
        }),
        submitButton(state, 'Continue'),
        html`<button type="button" class="wg-form__link wg-form__link--block" data-wg-goto="login">
          Back to sign in
        </button>`,
      ])}
    </form>`;
  }

  if (state.resetStep === 3) {
    return html`<form class="wg-form" data-wg-form="forgot" novalidate aria-describedby="${state.authUnavailable ? UNAVAILABLE_ALERT_ID : ''}">
      ${heading(state)}
      ${statusRegion(state)}

      ${section(state, [
        stepIndicator(3),
        field({
          id: 'wg-new-password',
          label: 'New password',
          value: state.values.newPassword ?? '',
          iconName: 'lock',
          placeholder: `At least ${MIN_PASSWORD_LENGTH} characters`,
          autocomplete: 'new-password',
          secret: true,
          revealed: state.passwordRevealed,
          disabled: state.busy,
          error: fieldError(state, 'wg-new-password'),
        }),
        field({
          id: 'wg-confirm-password',
          label: 'Confirm new password',
          value: state.values.confirmPassword ?? '',
          iconName: 'lock',
          placeholder: 'Re-enter your new password',
          autocomplete: 'new-password',
          secret: true,
          revealed: state.passwordRevealed,
          disabled: state.busy,
          error: fieldError(state, 'wg-confirm-password'),
        }),
        submitButton(state, 'Set new password'),
        html`<button type="button" class="wg-form__link wg-form__link--block" data-wg-goto="login">
          Back to sign in
        </button>`,
      ])}
    </form>`;
  }

  return html`<form class="wg-form" data-wg-form="forgot" novalidate aria-describedby="${state.authUnavailable ? UNAVAILABLE_ALERT_ID : ''}">
    ${heading(state)}
    ${statusRegion(state)}

    ${section(state, [
      stepIndicator(1),
      field({
        id: 'wg-identifier',
        label: 'Email or phone',
        value: state.values.identifier ?? state.identifier,
        iconName: 'mail',
        placeholder: 'you@organisation.com',
        autocomplete: 'username',
        inputmode: 'email',
        disabled: state.busy,
        error: fieldError(state, 'wg-identifier'),
      }),
      submitButton(state, 'Send reset link'),
      html`<p class="wg-form__alt">
        Remembered it?
        <button type="button" class="wg-form__link" data-wg-goto="login">Back to sign in</button>
      </p>`,
    ])}
  </form>`;
}

export function renderOtpForm(state: AuthFormState): SafeMarkup {
  if (state.otpStage === 'request' || !state.challengeId) {
    return html`<form class="wg-form" data-wg-form="otp" novalidate aria-describedby="${state.authUnavailable ? UNAVAILABLE_ALERT_ID : ''}">
      ${heading(state)}
      ${statusRegion(state)}

      ${section(state, [
        html`<p class="wg-form__sent">
          ${icon('info', { size: 15 })}
          <span>We will email or text you a six-digit code. No password required.</span>
        </p>`,
        field({
          id: 'wg-otp-identifier',
          label: 'Email or phone',
          value: state.values.otpIdentifier ?? state.identifier,
          iconName: 'mail',
          placeholder: 'you@organisation.com',
          autocomplete: 'username',
          inputmode: 'email',
          disabled: state.busy,
          error: fieldError(state, 'wg-otp-identifier'),
        }),
        submitButton(state, 'Send code'),
        html`<p class="wg-form__alt">
          <button type="button" class="wg-form__link" data-wg-goto="login">Use a password instead</button>
        </p>`,
      ])}
    </form>`;
  }

  const code = state.values.code ?? '';
  const canResend = state.resendInSeconds === 0 && !state.busy;

  const boxes = Array.from({ length: OTP_LENGTH }, (_, index) => {
    const digit = code[index] ?? '';
    return html`<input
      class="wg-otp__box"
      id="wg-otp-${index}"
      name="wg-otp-${index}"
      type="text"
      inputmode="numeric"
      pattern="[0-9]*"
      autocomplete="${index === 0 ? 'one-time-code' : 'off'}"
      maxlength="1"
      value="${digit}"
      aria-label="Digit ${index + 1} of ${OTP_LENGTH}"
      data-wg-otp-index="${index}"
      ${state.busy ? 'disabled' : ''}
    />`;
  });

  return html`<form class="wg-form" data-wg-form="otp" novalidate aria-describedby="${state.authUnavailable ? UNAVAILABLE_ALERT_ID : ''}">
    ${heading(state)}
    ${statusRegion(state)}

    ${section(state, [
      html`<p class="wg-form__sent">
        ${icon('mail', { size: 15 })}
        <span>
          Code sent to
          <strong class="wg-mono">${state.maskedDestination}</strong>
        </span>
      </p>`,
      html`<div class="wg-otp" role="group" aria-label="One-time code, 6 digits" data-wg-otp-group>
        ${boxes}
      </div>`,
      submitButton(state, 'Verify code'),
      html`<div class="wg-form__row wg-form__row--center">
        <span class="wg-form__hint">Did not get it?</span>
        <button type="button" class="wg-form__link wg-form__link--accent" data-wg-resend ${canResend ? '' : 'disabled'}>
          ${canResend ? 'Resend code' : `Resend in ${state.resendInSeconds}s`}
        </button>
      </div>`,
      html`<p class="wg-form__alt">
        <button type="button" class="wg-form__link" data-wg-goto="login">Use a password instead</button>
      </p>`,
    ])}
  </form>`;
}

export function renderForm(state: AuthFormState): SafeMarkup {
  switch (state.view) {
    case 'register':
      return renderRegisterForm(state);
    case 'otp':
      return renderOtpForm(state);
    case 'forgot':
      return renderForgotForm(state);
    default:
      // 'login', and any unrecognised view, falls back to the sign-in form
      // rather than rendering nothing.
      return renderLoginForm(state);
  }
}
