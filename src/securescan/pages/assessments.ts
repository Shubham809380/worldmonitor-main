/**
 * Assessments list.
 *
 * Owner-scoped by design: the server returns the caller's own assessments, so
 * this page shows a person's work rather than every in-flight investigation in
 * the workspace. An empty list is rendered as an empty list with the reason
 * stated, never as "all clear" — no assessments means nothing has been assessed.
 */

import { html, type SafeMarkup } from '../components/dom';
import { idLine, link } from '../components/links';
import { emptyState, formatTime, metric, notice, panel, stateBadge } from '../components/ui';
import type { AssessmentListReadModel } from '../services/api';

export function renderAssessmentList(data: AssessmentListReadModel): SafeMarkup {
  const rows = data.assessments;
  const ready = rows.filter((row) => row.state === 'READY').length;
  const running = rows.filter((row) => row.state === 'RUNNING').length;
  const completed = rows.filter((row) => row.state === 'COMPLETED').length;
  const failed = rows.filter((row) => row.state === 'FAILED').length;

  return html`
    <div class="ss-grid">
      ${notice(
        'neutral',
        'READY means a run has not been submitted yet',
        'A run is executed by the runner, not by this page. An assessment stays READY until a completed run is submitted for it, so the absence of a run is shown as such rather than as a finished assessment with no problems.',
      )}

      <div class="ss-grid ss-grid--metrics">
        ${metric('Assessments', rows.length, 'You own these')}
        ${metric('Ready', ready, 'Awaiting a submitted run')}
        ${metric('Running', running, 'A partial run was recorded')}
        ${metric('Completed', completed, 'A run finished')}
        ${metric('Failed', failed, 'The run reported a failure')}
      </div>

      ${panel(
        'Your assessments',
        rows.length === 0
          ? emptyState(
              'NO ASSESSMENTS YET',
              'You have not opened an assessment. Register an authorized target to start one — the authorization you record is written into the audit chain permanently.',
              html`<a class="ss-btn ss-btn--primary" href="#/assessments/new">New assessment</a>`,
            )
          : html`
              <div class="ss-table-wrap">
                <table class="ss-table ss-table--stack">
                  <thead>
                    <tr>
                      <th scope="col">Assessment</th>
                      <th scope="col">State</th>
                      <th scope="col">Latest run</th>
                      <th scope="col">Updated</th>
                      <th scope="col">Report</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${rows.map(
                      (row) => html`
                        <tr>
                          <td data-label="Assessment">
                            ${link(row.name, 'assessments-detail', { assessmentId: row.assessmentId })}
                            ${idLine([row.assessmentId, row.state])}
                          </td>
                          <td data-label="State">
                            ${stateBadge(row.state)}
                            ${row.abortReason ? html`<div class="ss-field__hint">${row.abortReason}</div>` : ''}
                          </td>
                          <td data-label="Latest run" class="ss-cell-id">
                            ${row.latestRunId ?? 'none recorded'}
                          </td>
                          <td data-label="Updated" class="ss-cell-id">${formatTime(row.updatedAt)}</td>
                          <td data-label="Report">
                            ${row.latestRunId
                              ? link('View report', 'report', { assessmentId: row.assessmentId })
                              : html`<span class="ss-meta">no run yet</span>`}
                          </td>
                        </tr>
                      `,
                    )}
                  </tbody>
                </table>
              </div>
            `,
      )}

      <p class="ss-field__hint">
        Findings across every assessment are on the
        ${link('findings', 'findings')} page. This list is scoped to you because it is how you find your own work.
      </p>
    </div>
  `;
}
