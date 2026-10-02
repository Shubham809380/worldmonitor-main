/**
 * SecureScan UI primitives.
 *
 * The status vocabulary is the most security-sensitive part of this file, so it
 * is centralised here rather than written per page. Three rules hold across
 * every component:
 *
 *  1. **Severity and validation are separate axes.** A `CANDIDATE` is not a
 *     "low severity finding"; it is an unjudged observation. Collapsing them is
 *     how a scanner's unvalidated guess gets presented as a confirmed weakness,
 *     so a finding always shows both, side by side.
 *  2. **No fabricated absolutes.** There is no component here that renders a
 *     score, a grade, a percentage, or a "secure" claim, because the backend
 *     does not produce one and inventing it client-side would be the single most
 *     damaging thing this UI could do.
 *  3. **Colour is never the only signal.** Every badge carries a text label, and
 *     the dot is a redundant cue, so the state survives greyscale,
 *     colour-blindness, and forced-colours mode.
 */

import { html, type SafeMarkup, type SafeValue } from './dom';

export type Severity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

const SEVERITY_TONE: Record<Severity, string> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  NONE: 'muted',
};

/**
 * Severity badge.
 *
 * `NONE` renders as "Unscored", not "Informational". The server's label map maps
 * `NONE` to `INFORMATIONAL` because it is the closest product word, but a
 * finding nobody has scored is a *pending judgement*, not a judgement that came
 * out "informational". Using the server's label here would present an empty slot
 * as a considered result.
 */
export function severityBadge(severity: Severity): SafeMarkup {
  const tone = SEVERITY_TONE[severity] ?? 'muted';
  const label = severity === 'NONE' ? 'UNSCORED' : severity;
  return html`<span class="ss-badge ss-badge--${tone}">${label}</span>`;
}

type StateTone =
  | 'candidate'
  | 'validated'
  | 'remediation'
  | 'inconclusive'
  | 'regression'
  | 'verified'
  | 'closed';

/**
 * Validation-state badge, using the server's product labels.
 *
 * `POTENTIAL` is deliberately not `VERIFIED`: validation means an analyst
 * confirmed the weakness, verification means a retest confirmed a fix. A static
 * candidate that a human read once must never share a word with a fix that was
 * tested and passed.
 */
export function stateBadge(state: string, stateLabel?: string): SafeMarkup {
  const tone = stateTone(state);
  const label = stateLabel ?? state;
  return html`<span class="ss-badge ss-badge--${tone}">${label}</span>`;
}

function stateTone(state: string): StateTone {
  switch (state) {
    case 'CANDIDATE':
    case 'VALIDATING':
      return 'candidate';
    case 'VALIDATED':
      return 'validated';
    case 'REMEDIATION':
    case 'RETEST_REQUIRED':
    case 'RETESTING':
      return 'remediation';
    case 'INCONCLUSIVE':
      return 'inconclusive';
    case 'REGRESSION':
      return 'regression';
    case 'VERIFIED':
    case 'FIXED':
      return 'verified';
    default:
      return 'closed';
  }
}

/** Test-status badge. PASS is the only state that spends the green accent here. */
export function testStatusBadge(status: string): SafeMarkup {
  if (status === 'PASS') return html`<span class="ss-badge ss-badge--good">PASS</span>`;
  if (status === 'FAIL') return html`<span class="ss-badge ss-badge--high">FAIL</span>`;
  if (status === 'INCONCLUSIVE') return html`<span class="ss-badge ss-badge--muted">INCONCLUSIVE</span>`;
  if (status === 'NOT_TESTED') return html`<span class="ss-badge ss-badge--muted">NOT TESTED</span>`;
  if (status === 'SKIPPED_OUT_OF_SCOPE') return html`<span class="ss-badge ss-badge--muted">OUT OF SCOPE</span>`;
  return html`<span class="ss-badge ss-badge--muted">${status}</span>`;
}

/** Audit outcome badge. A denial is as reportable as an allowance. */
export function outcomeBadge(outcome: string): SafeMarkup {
  if (outcome === 'ALLOWED') return html`<span class="ss-badge ss-badge--good">ALLOWED</span>`;
  return html`<span class="ss-badge ss-badge--medium">DENIED</span>`;
}

/** Role badge, so a reader can tell an admin action from an analyst action. */
export function roleBadge(role: string): SafeMarkup {
  if (role === 'ADMIN') return html`<span class="ss-badge ss-badge--medium">ADMIN</span>`;
  if (role === 'SECURITY_ANALYST') return html`<span class="ss-badge ss-badge--low">ANALYST</span>`;
  if (role === 'VIEWER') return html`<span class="ss-badge ss-badge--muted">VIEWER</span>`;
  if (role === 'SYSTEM') return html`<span class="ss-badge ss-badge--muted">ENGINE</span>`;
  return html`<span class="ss-badge ss-badge--muted">${role}</span>`;
}

/* -------------------------------------------------------------------------
 * Layout
 * ---------------------------------------------------------------------- */

export function panel(title: string, body: SafeValue, actions?: SafeValue): SafeMarkup {
  return html`
    <section class="ss-panel">
      <div class="ss-panel__head">
        <h2 class="ss-panel__title">${title}</h2>
        ${actions ?? ''}
      </div>
      ${body}
    </section>
  `;
}

export function metric(label: string, value: string | number, hint?: string): SafeMarkup {
  return html`
    <div class="ss-metric">
      <span class="ss-metric__label">${label}</span>
      <span class="ss-metric__value">${value}</span>
      ${hint ? html`<span class="ss-metric__hint">${hint}</span>` : ''}
    </div>
  `;
}

/**
 * Severity mix.
 *
 * Buckets with a count of zero are deliberately omitted. A row of
 * "CRITICAL 0 · HIGH 0 · MEDIUM 1 · LOW 0" is eight facts where two matter, and
 * a permanently-zero column reads as a measurement that was taken and found
 * nothing. Omitting it is also the honest reading: these are the severities
 * actually present.
 */
export function severityMix(mix: Record<string, number>): SafeMarkup {
  const order: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const present = order.filter((key) => (mix[key] ?? 0) > 0);
  if (present.length === 0) {
    return html`<p class="ss-field__hint">No scored findings in this assessment.</p>`;
  }
  return html`
    <div class="ss-mix">
      ${present.map(
        (key) => html`
          <div class="ss-mix__item">
            <span class="ss-mix__n">${mix[key]}</span>
            <span class="ss-mix__label">${key}</span>
          </div>
        `,
      )}
    </div>
  `;
}

/* -------------------------------------------------------------------------
 * States
 * ---------------------------------------------------------------------- */

export function loadingState(message = 'Loading SecureScan data'): SafeMarkup {
  return html`
    <div class="ss-state" role="status" aria-live="polite">
      <div class="ss-progress" aria-hidden="true"><div class="ss-progress__bar"></div></div>
      <p class="ss-state__body">${message}</p>
    </div>
  `;
}

export function emptyState(title: string, body: string, action?: SafeValue): SafeMarkup {
  return html`
    <div class="ss-state">
      <div class="ss-state__icon" aria-hidden="true">—</div>
      <h3 class="ss-state__title">${title}</h3>
      <p class="ss-state__body">${body}</p>
      ${action ?? ''}
    </div>
  `;
}

export function errorState(title: string, body: string, action?: SafeValue): SafeMarkup {
  return html`
    <div class="ss-state ss-state--error" role="alert">
      <div class="ss-state__icon" aria-hidden="true">!</div>
      <h3 class="ss-state__title">${title}</h3>
      <p class="ss-state__body">${body}</p>
      ${action ?? ''}
    </div>
  `;
}

export function deniedState(title: string, body: string): SafeMarkup {
  return html`
    <div class="ss-state ss-state--denied" role="alert">
      <div class="ss-state__icon" aria-hidden="true">\u{2298}</div>
      <h3 class="ss-state__title">${title}</h3>
      <p class="ss-state__body">${body}</p>
    </div>
  `;
}

export function notice(tone: 'warn' | 'danger' | 'good' | 'neutral', title: string, body: string): SafeMarkup {
  const cls = tone === 'neutral' ? 'ss-notice' : `ss-notice ss-notice--${tone}`;
  return html`
    <div class="${cls}" role="${tone === 'good' ? 'status' : 'note'}">
      <div>
        <div class="ss-notice__title">${title}</div>
        <div>${body}</div>
      </div>
    </div>
  `;
}

/**
 * The "no data yet" state for a report.
 *
 * The wording is the point. An assessment with no completed run must never
 * render as an empty findings list, because an empty findings list is how a
 * reader concludes there is nothing to fix.
 */
export function noRunState(): SafeMarkup {
  return emptyState(
    'NO COMPLETED RUN',
    'This assessment does not have a completed run yet. Nothing has been assessed, so there is no result to report — which is not the same as a clean result.',
  );
}

/* -------------------------------------------------------------------------
 * Formatting
 * ---------------------------------------------------------------------- */

const DATE_FMT = new Intl.DateTimeFormat('en-GB', {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  timeZone: 'UTC',
});

/** ISO timestamp, or an em dash when the value is absent rather than zero. */
export function formatTime(ms: number | null | undefined): string {
  if (typeof ms !== 'number' || !Number.isFinite(ms)) return '-';
  // A finite number can still be outside the range `Date` can represent (the
  // ECMAScript limit is +/-8.64e15 ms), and `Intl.DateTimeFormat#format` throws a
  // RangeError on an invalid date rather than rendering something. That throw
  // would take the whole view down, so the value is checked before formatting.
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return '-';
  return `${DATE_FMT.format(date)} UTC`;
}

/** Duration in words. A fabricated "0s" for an unknown start is avoided. */
export function formatDuration(fromMs: number | null, toMs: number | null): string {
  if (typeof fromMs !== 'number' || typeof toMs !== 'number') return '—';
  const seconds = Math.max(0, Math.round((toMs - fromMs) / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

/** Shortens an opaque subject id for display without pretending it is a name. */
export function shortSubject(subject: string): string {
  if (!subject) return 'unknown';
  if (subject.length <= 22) return subject;
  return `${subject.slice(0, 10)}…${subject.slice(-6)}`;
}

export { html };
export type { SafeMarkup, SafeValue };
