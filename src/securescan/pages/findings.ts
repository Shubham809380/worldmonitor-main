/**
 * Findings across the workspace.
 *
 * Filters are real query parameters, so a filtered view is a shareable URL and
 * the browser's back button behaves. Every filter value is validated against the
 * server's union before it is sent: an unknown state would come back as a Convex
 * argument-validation error, which is a worse experience than a filter that
 * simply reports no matches.
 *
 * The filter is applied by writing the hash, not by submitting a form. This used to
 * be a native `<form method="get" action="#/findings">`, which was broken in two
 * ways at once: a GET submit to a fragment-only action performs a full document
 * navigation (confirmed in Chromium: the document reloads), and it writes the
 * values into the *document* query string rather than the hash. `parseRoute` reads
 * only the hash, so the page came back unfiltered. The user pressed Apply, watched
 * the page reload, and saw the same unfiltered list.
 *
 * Filtering is a server query, not a client-side hide: the row count in the panel
 * title is `data.total` as the backend reported it. `activateFindingsFilters`
 * routes through `hrefFor`, so a filter never bypasses the shell's route handling
 * and never hands a value to the backend that `isState`/`isSev` did not accept.
 */

import { html, type SafeMarkup } from '../components/dom';
import { link } from '../components/links';
import { hrefFor } from '../routing';
import { emptyState, formatTime, panel, severityBadge, stateBadge } from '../components/ui';
import type { FindingListReadModel } from '../services/api';

/** Mirrors the server unions. A filter outside these cannot be sent at all. */
export const STATE_OPTIONS = [
  'CANDIDATE',
  'VALIDATING',
  'VALIDATED',
  'REMEDIATION',
  'RETEST_REQUIRED',
  'VERIFIED',
  'REGRESSION',
  'INCONCLUSIVE',
  'INFORMATIONAL',
  'FALSE_POSITIVE',
  'ACCEPTED_RISK',
  'FIXED',
] as const;

export const SEVERITY_OPTIONS = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;

type State = (typeof STATE_OPTIONS)[number];
type Sev = (typeof SEVERITY_OPTIONS)[number];

export function isState(value: string | undefined): value is State {
  return STATE_OPTIONS.includes(value as State);
}

export function isSev(value: string | undefined): value is Sev {
  return SEVERITY_OPTIONS.includes(value as Sev);
}

/**
 * The filter controls.
 *
 * A `<form>` is deliberately not used. A GET submit to a fragment-only `action`
 * reloads the document and puts the values in `location.search`, which this app's
 * hash router never reads, so the filters came back cleared. Intercepting `submit`
 * and writing `location.hash` would also work but leaves a real form whose native
 * behaviour is one click away, so the selects navigate directly instead.
 *
 * The selects carry `aria-controls` pointing at the results table so a screen
 * reader is told which region the control affects, and the results panel is
 * announced politely after a filter change.
 */
function renderFilters(state: State | undefined, severity: Sev | undefined, isFiltered: boolean): SafeMarkup {
  return html`
    <div class="ss-filters" role="group" aria-label="Filter findings">
      <div class="ss-field">
        <label class="ss-label" for="ss-filter-state">Validation state</label>
        <select class="ss-select" id="ss-filter-state" data-filter="state" aria-controls="ss-findings-results">
          <option value="" ${state ? '' : html`selected`}>All states</option>
          ${STATE_OPTIONS.map(
            (option) => html`<option value="${option}" ${state === option ? html`selected` : ''}>${option}</option>`,
          )}
        </select>
      </div>

      <div class="ss-field">
        <label class="ss-label" for="ss-filter-severity">Severity</label>
        <select class="ss-select" id="ss-filter-severity" data-filter="severity" aria-controls="ss-findings-results">
          <option value="" ${severity ? '' : html`selected`}>All severities</option>
          ${SEVERITY_OPTIONS.map(
            (option) => html`<option value="${option}" ${severity === option ? html`selected` : ''}>${option}</option>`,
          )}
        </select>
      </div>

      <div class="ss-btn-row">
        <button class="ss-btn" type="button" id="ss-filter-clear" ${isFiltered ? '' : html`disabled`}>Clear</button>
      </div>
    </div>
    <div class="ss-form-status" role="status" aria-live="polite" id="ss-filter-status"></div>
  `;
}

/**
 * Wire the selects to the hash router.
 *
 * Assigning `location.hash` fires `hashchange`, which the shell already listens to,
 * so there is no second navigation path to keep in sync and back/forward work
 * because these are ordinary history entries.
 *
 * Values are re-validated here as well as at render. The select can only produce a
 * value from its own options, but the URL is attacker-reachable via the address
 * bar, and this is the last client-side hop before the backend is asked to run a
 * query. Validation here narrows what is sent; it is not the authorization check,
 * which remains the server's.
 */
export function activateFindingsFilters(view: HTMLElement): void {
  const stateSelect = view.querySelector<HTMLSelectElement>('[data-filter="state"]');
  const sevSelect = view.querySelector<HTMLSelectElement>('[data-filter="severity"]');
  if (!stateSelect && !sevSelect) return;

  const status = view.querySelector<HTMLElement>('#ss-filter-status');

  const apply = (): void => {
    const rawState = stateSelect?.value ?? '';
    const rawSeverity = sevSelect?.value ?? '';
    const nextState = isState(rawState) ? rawState : '';
    const nextSeverity = isSev(rawSeverity) ? rawSeverity : '';

    const params: Record<string, string> = {};
    if (nextState) params.state = nextState;
    if (nextSeverity) params.severity = nextSeverity;

    const target = hrefFor('findings', params);
    if (target === window.location.hash) return;
    window.location.hash = target.slice(1);
    if (status) {
      status.textContent =
        params.state || params.severity ? 'Filters applied.' : 'Filters cleared.';
    }
  };

  stateSelect?.addEventListener('change', apply);
  sevSelect?.addEventListener('change', apply);

  view.querySelector<HTMLButtonElement>('#ss-filter-clear')?.addEventListener('click', () => {
    if (stateSelect) stateSelect.value = '';
    if (sevSelect) sevSelect.value = '';
    apply();
  });
}

export function renderFindings(data: FindingListReadModel, params: Record<string, string>): SafeMarkup {
  const state = isState(params.state) ? params.state : undefined;
  const severity = isSev(params.severity) ? params.severity : undefined;
  const active = state ?? severity;

  return html`
    <div class="ss-grid">
      ${renderFilters(state, severity, Boolean(active))}

      ${panel(
        active
          ? `Findings — ${data.findings.length} of ${data.total} matching`
          : `All findings — ${data.total}`,
        data.findings.length === 0
          ? emptyState(
              active ? 'NO MATCHING FINDINGS' : 'NO FINDINGS RECORDED',
              active
                ? 'No finding in this workspace matches the current filter. That is a statement about the filter, not about the security of the target.'
                : 'No run has produced a finding yet. Open an assessment and run a scan to generate one.',
              active ? html`<a class="ss-btn" href="${hrefFor('findings')}">Clear filter</a>` : '',
            )
          : html`
              <div class="ss-table-wrap" id="ss-findings-results">
                <table class="ss-table ss-table--stack">
                  <thead>
                    <tr>
                      <th scope="col">Finding</th>
                      <th scope="col">Severity</th>
                      <th scope="col">State</th>
                      <th scope="col">Confidence</th>
                      <th scope="col">Evidence</th>
                      <th scope="col">Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${data.findings.map(
                      (f) => html`
                        <tr>
                          <td data-label="Finding">
                            ${link(f.title, 'findings-detail', { findingId: f.findingId })}
                            <div class="ss-cell-id">${f.findingId} · ${f.control}</div>
                          </td>
                          <td data-label="Severity">${severityBadge(f.severity)}</td>
                          <td data-label="State">${stateBadge(f.state, f.stateLabel)}</td>
                          <td data-label="Confidence" class="ss-cell-id">${f.confidence}</td>
                          <td data-label="Evidence" class="ss-cell-num">${f.evidenceCount}</td>
                          <td data-label="Updated" class="ss-cell-id">${formatTime(f.updatedAt)}</td>
                        </tr>
                      `,
                    )}
                  </tbody>
                </table>
              </div>
            `,
      )}

      <p class="ss-field__hint">
        A scanner <code>FAIL</code> produces a <strong>candidate</strong>, not a confirmed vulnerability.
        Severity and validation state are recorded separately: a finding can be <code>HIGH</code>
        severity and still be an unvalidated candidate.
      </p>
    </div>
  `;
}