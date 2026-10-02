/**
 * Client-side validation for the WorldGuard authentication forms.
 *
 * These checks exist to give fast, accessible feedback — they are not a
 * security boundary. The identity service re-validates everything, and no
 * control's validity in the browser should be taken as proof.
 */

const EMAIL_RE = /^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$/;
const PHONE_RE = /^\+?[0-9][0-9\s().-]{6,19}$/;

export const OTP_LENGTH = 6;
export const MIN_PASSWORD_LENGTH = 12;

export function isEmail(value: string): boolean {
  return EMAIL_RE.test(value.trim());
}

export function isPhone(value: string): boolean {
  return PHONE_RE.test(value.trim());
}

export function looksLikePhone(value: string): boolean {
  return !value.includes('@') && /[0-9]/.test(value);
}

/** Trim, and lowercase the local part only — the domain is case-insensitive. */
export function normaliseIdentifier(value: string): string {
  const trimmed = value.trim();
  const at = trimmed.lastIndexOf('@');
  if (at <= 0) return trimmed;
  return `${trimmed.slice(0, at).toLowerCase()}@${trimmed.slice(at + 1).toLowerCase()}`;
}

export function isValidIdentifier(value: string): boolean {
  const trimmed = value.trim();
  return looksLikePhone(trimmed) ? isPhone(trimmed) : isEmail(trimmed);
}

export interface PasswordRequirement {
  readonly id: string;
  readonly label: string;
  readonly met: boolean;
}

export function passwordRequirements(password: string): readonly PasswordRequirement[] {
  return [
    { id: 'length', label: `${MIN_PASSWORD_LENGTH} characters or more`, met: password.length >= MIN_PASSWORD_LENGTH },
    { id: 'case', label: 'Upper and lower case', met: /[a-z]/.test(password) && /[A-Z]/.test(password) },
    { id: 'number', label: 'A number', met: /[0-9]/.test(password) },
    { id: 'symbol', label: 'A symbol', met: /[^A-Za-z0-9]/.test(password) },
  ];
}

export type PasswordStrength = 'empty' | 'weak' | 'fair' | 'strong' | 'excellent';

/** 0–4 meter value plus its label, derived from the unmet requirement count. */
export function passwordStrength(password: string): { readonly level: PasswordStrength; readonly score: number } {
  if (password === '') return { level: 'empty', score: 0 };
  const unmet = passwordRequirements(password).filter((requirement) => !requirement.met).length;
  const score = Math.max(1, 4 - unmet);
  const levels: readonly PasswordStrength[] = ['empty', 'weak', 'fair', 'strong', 'excellent'];
  return { level: levels[score] ?? 'weak', score };
}

/** Strip everything but digits and cap the length — paste tolerance for OTPs. */
export function normaliseOtp(value: string): string {
  return value.replace(/\D/g, '').slice(0, OTP_LENGTH);
}

export function isCompleteOtp(value: string): boolean {
  return value.length === OTP_LENGTH;
}

export function maskOtp(value: string): string {
  return value.replace(/\d/g, '•');
}
