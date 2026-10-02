/**
 * SecureScan dashboard.
 *
 * The counts here come straight from `console.dashboard`, which counts stored
 * rows. There is no posture score, no "security rating", and no percentage,
 * because the backend does not produce one and a number that looks like a grade
 * without a published methodology behind it is a lie told in a typeface that
 * makes it look authoritative.
 *
 * The unjudged-work callout is placed above the severity mix deliberately. The
 * most misleading thing a security dashboard can do is show a tidy severity
 * distribution while the triage queue is full of things nobody has looked at.
 */

import { html, type SafeMarkup } from '../components/dom';
import {
  emptyState,
  formatTime,
  metric,
  notice,
  panel,
  severityBadge,
  stateBadge,
} from '../components/ui';
import type { DashboardReadModel } from '../services/api';
import { hrefFor } from '../routing';

/** Links are plain anchors: the shell router is hash-based. */
function link(
  label: string,
  route: Parameters<typeof hrefFor>[0],
  params: Record<string, string> = {},
  className?: string,
): SafeMarkup {
  return className
    ? html`<a class="${className}" href="${hrefFor(route, params)}">${label}</a>`
    : html`<a href="${hrefFor(route, params)}">${label}</a>`;
}

export function renderDashboard(data: DashboardReadModel): SafeMarkup {
  const { totals } = data;
  const candidates = data.recentFindings.filter((f) => f.severity === 'NONE');

  return html`
    <div class="ss-grid">
      <!-- The unjudged queue leads, because it is the work that a severity
           distribution would otherwise hide. -->
      ${totals.unscoredCandidates > 0
        ? notice(
            'warn',
            `${totals.unscoredCandidates} finding${totals.unscoredCandidates === 1 ? '' : 's'} awaiting an analyst judgement`,
            'These carry no severity. A scanner observation is a candidate, not a confirmed weakness, until somebody scores it. They are excluded from the severity mix rather than counted as low.',
          )
        : ''}

      <div class="ss-grid ss-grid--metrics">
        ${metric('Assessments', totals.assessments, `${totals.assessmentsByState.COMPLETED ?? 0} completed`)}
        ${metric('Runs recorded', totals.runs, `${totals.tests} checks, ${totals.evidence} evidence records`)}
        ${metric('Open findings', totals.openFindings, `${totals.closedFindings} reached a decision`)}
        ${metric('Awaiting judgement', totals.unscoredCandidates, 'Not yet scored')}
        ${metric('Members', totals.members, `${data.role.replace('_', ' ')} as your role`)}
      </div>

      <div class="ss-grid ss-grid--2">
        ${panel(
          'Latest run',
          data.lastRun
            ? html`
                <div class="ss-panel__body">
                  <dl class="ss-kv">
                    <dt>Run</dt><dd class="ss-meta">${data.lastRun.runId}</dd>
                    <dt>State</dt><dd>${stateBadge(data.lastRun.state)}</dd>
                    <dt>Assessment</dt><dd>${link('open', 'assessments-detail', { assessmentId: data.lastRun.assessmentId })}</dd>
                    <dt>Finished</dt><dd class="ss-meta">${formatTime(data.lastRun.finishedAt)}</dd>
                    <dt>Tool</dt><dd class="ss-meta">${data.lastRun.toolVersion}</dd>
                    <dt>Checks</dt>
                    <dd>
                      <span class="ss-meta">${data.lastRun.counts.pass} pass · ${data.lastRun.counts.fail} fail · ${data.lastRun.counts.inconclusive} inconclusive · ${data.lastRun.counts.notTested} not tested</span>
                    </dd>
                  </dl>
                </div>
              `
            : emptyState(
                'NO RUNS RECORDED',
                'Nothing has been assessed in this workspace yet. A run is what produces findings, coverage, and evidence — without one there is no result to report.',
              ),
        )}

        ${panel(
          'Severity mix',
          html`
            <div class="ss-panel__body">
              ${severityDistribution(totals.findingsBySeverity)}
              <p class="ss-field__hint" style="margin-top:12px">
                Counts stored severities. Unscored candidates are not included, because no analyst has assigned them one.
              </p>
            </div>
          `,
        )}
      </div>

      ${panel(
        'Findings requiring judgement',
        candidates.length === 0
          ? emptyState(
              'NO CANDIDATES AWAITING JUDGEMENT',
              'Every finding in the recent list has been scored. This says nothing about the rest of the workspace - check the Findings view for the full queue.',
              // The copy tells the reader to check another view; without a link it
              // is an instruction the reader cannot follow.
              link('Open the findings queue', 'findings', {}, 'ss-btn ss-btn--primary'),
            )
          : html`
              <div class="ss-table-wrap">
                <table class="ss-table ss-table--stack">
                  <thead>
                    <tr>
                      <th scope="col">Finding</th>
                      <th scope="col">Severity</th>
                      <th scope="col">State</th>
                      <th scope="col">Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${candidates.map(
                      (f) => html`
                        <tr>
                          <td data-label="Finding">
                            ${link(f.title, 'findings-detail', { findingId: f.findingId })}
                            <div class="ss-cell-id">${f.findingId}</div>
                          </td>
                          <td data-label="Severity">${severityBadge('NONE')}</td>
                          <td data-label="State">${stateBadge(f.state, f.stateLabel)}</td>
                          <td data-label="Updated" class="ss-cell-id">${formatTime(f.updatedAt)}</td>
                        </tr>
                      `,
                    )}
                  </tbody>
                </table>
              </div>
            `,
      )}

      ${panel(
        'Recent assessments',
        data.recentAssessments.length === 0
          ? emptyState(
              'NO ASSESSMENTS YET',
              'Open your first authorized security assessment to begin analysing the target.',
              html`<a class="ss-btn ss-btn--primary" href="#/assessments/new">Create assessment</a>`,
            )
          : html`
              <div class="ss-table-wrap">
                <table class="ss-table ss-table--stack">
                  <thead>
                    <tr>
                      <th scope="col">Assessment</th>
                      <th scope="col">State</th>
                      <th scope="col">Updated</th>
                      <th scope="col">Report</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${data.recentAssessments.map(
                      (a) => html`
                        <tr>
                          <td data-label="Assessment">
                            ${link(a.name, 'assessments-detail', { assessmentId: a.assessmentId })}
                            <div class="ss-cell-id">${a.assessmentId}</div>
                          </td>
                          <td data-label="State">${stateBadge(a.state)}</td>
                          <td data-label="Updated" class="ss-cell-id">${formatTime(a.updatedAt)}</td>
                          <td data-label="Report">
                            ${a.latestRunId
                              ? link('View report', 'report', { assessmentId: a.assessmentId })
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

      ${panel(
        'Recent activity',
        data.recentFindings.length === 0
          ? emptyState('NO FINDINGS RECORDED', 'No finding has been produced by a run in this workspace yet.')
          : html`
              <div class="ss-table-wrap">
                <table class="ss-table ss-table--stack">
                  <thead>
                    <tr>
                      <th scope="col">Finding</th>
                      <th scope="col">Severity</th>
                      <th scope="col">State</th>
                      <th scope="col">Confidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${data.recentFindings.map(
                      (f) => html`
                        <tr>
                          <td data-label="Finding">
                            ${link(f.title, 'findings-detail', { findingId: f.findingId })}
                          </td>
                          <td data-label="Severity">${severityBadge(f.severity)}</td>
                          <td data-label="State">${stateBadge(f.state, f.stateLabel)}</td>
                          <td data-label="Confidence" class="ss-cell-id">${f.confidence}</td>
                        </tr>
                      `,
                    )}
                  </tbody>
                </table>
              </div>
            `,
      )}
    </div>
  `;
}

/**
 * Renders only the severities that actually occur.
 *
 * A row of zero-valued buckets would be eight facts where two matter, and
 * "MEDIUM 0" reads as a measurement taken and found clean rather than as an
 * absence.
 */
function severityDistribution(mix: Record<string, number>): SafeMarkup {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
  const present = order.filter((key) => (mix[key] ?? 0) > 0);
  if (present.length === 0) {
    return html`<p class="ss-field__hint">No scored findings in this workspace yet.</p>`;
  }
  return html`
    <div class="ss-mix">
      ${present.map(
        (key) => html`
          <div class="ss-mix__item">
            <span class="ss-mix__n">${mix[key]}</span>
            <span class="ss-mix__label">${key}</span>
            ${severityBadge(key as 'LOW')}
          </div>
        `,
      )}
    </div>
  `;
}
