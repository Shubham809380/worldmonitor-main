/**
 * Assessment report.
 *
 * The report has two jobs that pull against each other and this page resolves
 * the tension by keeping them visually separate:
 *
 *  - It is a **rendering of what was recorded**. Coverage, findings, evidence,
 *    gaps, and audit integrity are shown with their recorded numbers.
 *  - It must **not produce a grade**. There is no overall security score,
 *    because a scan produces evidence and coverage, not a verdict. The absence
 *    of the score is a design decision, not an omission.
 *
 * The page also refuses to let "no run" read as "no problems". When `hasRun` is
 * false the coverage block states that nothing was assessed, because an empty
 * findings list would otherwise be read as a clean result.
 */

import { html, type SafeMarkup } from '../components/dom';
import { idLine, link } from '../components/links';
import {
  emptyState,
  formatDuration,
  formatTime,
  notice,
  panel,
  severityBadge,
  severityMix,
  stateBadge,
} from '../components/ui';
import type { ReportReadModel } from '../services/api';

export function renderReport(data: ReportReadModel, _params: Record<string, string>): SafeMarkup {
  return html`
    <div class="ss-grid">
      <div class="ss-report__header">
        <h2 class="ss-report__title">${data.assessment.name}</h2>
        ${idLine([data.assessment.assessmentId, data.assessment.state])}
      </div>

      ${data.integrity.problems.length > 0
        ? notice(
            'danger',
            'Audit chain verification failed',
            `The report cannot be treated as a trusted record: ${data.integrity.problems.join('; ')}`,
          )
        : ''}
      ${!data.hasRun
        ? notice(
            'neutral',
            'Nothing has been assessed yet',
            'This assessment has no completed run. Coverage, evidence, and findings below are all absent because no check has run.',
          )
        : ''}

${renderCoverage(data)}
  ${renderFindings(data)}
  ${renderIntegrity(data)}
    </div>
  `;
}

function renderCoverage(data: ReportReadModel): SafeMarkup {
  const run = data.run;
  if (!data.hasRun && !run) return html``;

  return panel(
    'Run and coverage',
    html`
      <div class="ss-panel__body">
        ${run
          ? html`
              <dl class="ss-kv">
                <dt>Run</dt><dd class="ss-meta">${run.runId}</dd>
                <dt>Status</dt><dd>${stateBadge(run.state)}</dd>
                <dt>Started</dt><dd class="ss-meta">${formatTime(run.startedAt)}</dd>
                <dt>Duration</dt><dd class="ss-meta">${formatDuration(run.startedAt, run.finishedAt)}</dd>
                <dt>Modules</dt><dd class="ss-meta">${run.modulesRun.join(', ') || '—'}</dd>
                <dt>Tool</dt><dd class="ss-meta">${run.toolVersion}</dd>
                <dt>Target revision</dt><dd class="ss-cell-id">${run.targetRevision ?? '—'}</dd>
                ${run.abortReason ? html`<dt>Abort reason</dt><dd>${run.abortReason}</dd>` : ''}
                <dt>Runs this assessment</dt><dd class="ss-meta">${run.runCount}</dd>
              </dl>
            `
          : ''}

        <div class="ss-grid ss-grid--metrics">
          ${data.hasRun ? miscMetric('Tests observed', data.coverage.observedTests) : miscMetric('Tests observed', 0)}
          <div class="ss-metric">
            <span class="ss-metric__label">Not tested / out of scope</span>
            <span class="ss-metric__value">${data.coverage.notTestedTests}</span>
            <span class="ss-metric__hint">Recorded as not tested, never as a pass</span>
          </div>
          <div class="ss-metric">
            <span class="ss-metric__label">Evidence records</span>
            <span class="ss-metric__value">${data.coverage.evidenceCount}</span>
          </div>
        </div>

        ${data.coverage.notTested.length === 0
          ? ''
          : html`
              <details class="ss-details">
                <summary class="ss-details__summary">Why ${data.coverage.notTested.length} check(s) were not tested</summary>
                <div class="ss-table-wrap">
                  <table class="ss-table ss-table--stack">
                    <thead>
                      <tr>
                        <th scope="col">Test</th>
                        <th scope="col">Module / control</th>
                        <th scope="col">Why not tested</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${data.coverage.notTested.map(
                        (row) => html`
                          <tr>
                            <td data-label="Test" class="ss-cell-id">${row.testId}</td>
                            <td data-label="Module / control" class="ss-cell-id">${row.module} · ${row.control}</td>
                            <td data-label="Why not tested" class="ss-cell-id">${row.reason}</td>
                          </tr>
                        `,
                      )}
                    </tbody>
                  </table>
                </div>
              </details>
            `}
      </div>
    `,
  );
}

function renderFindings(data: ReportReadModel): SafeMarkup {
  const findings = data.findings;

  return panel(
    `Findings (${findings.length})`,
    findings.length === 0
      ? emptyState(
          data.hasRun ? 'NO FINDINGS IN THIS ASSESSMENT' : 'NOTHING ASSESSED',
          data.hasRun
            ? 'Every check that ran recorded no finding. This describes what was checked, not the security position of the target as a whole.'
            : 'No run has been submitted, so no check has run and no finding has been looked for. This is not a clean result.',
        )
      : html`
          <div class="ss-grid">
            <div class="ss-panel__body">
              <h4 class="ss-panel__subtitle">Severity mix</h4>
              ${severityMix(data.severityMix)}
            </div>
            <div class="ss-panel__body">
              <h4 class="ss-panel__subtitle">State mix</h4>
              <div class="ss-cell-id">${Object.entries(data.stateMix).filter(([, n]) => n > 0).map(([state, n]) => `${state} ${n}`).join(' · ') || 'none'}</div>
            </div>
          </div>

          <div class="ss-table-wrap">
            <table class="ss-table ss-table--stack">
              <thead>
                <tr>
                  <th scope="col">Finding</th>
                  <th scope="col">Severity</th>
                  <th scope="col">State</th>
                  <th scope="col">Confidence</th>
                  <th scope="col">Evidence</th>
                </tr>
              </thead>
              <tbody>
                ${findings.map(
                  (finding) => html`
                    <tr>
                      <td data-label="Finding">
                        ${link(finding.title, 'findings-detail', { findingId: finding.findingId })}
                        ${idLine([finding.findingId, finding.control, finding.component])}
                      </td>
                      <td data-label="Severity">${severityBadge(finding.severity)}</td>
                      <td data-label="State">${stateBadge(finding.state, finding.stateLabel)}</td>
                      <td data-label="Confidence" class="ss-cell-id">${finding.confidence}</td>
                      <td data-label="Evidence" class="ss-cell-num">${finding.evidenceIds.length}</td>
                    </tr>
                  `,
                )}
              </tbody>
            </table>
          </div>
        `,
    html`
      <span class="ss-meta">${data.basis.evidenceRecords} evidence · ${data.basis.testsObserved} observed · ${data.basis.testsNotTested} not tested</span>
    `,
  );
}

function renderIntegrity(data: ReportReadModel): SafeMarkup {
  return panel(
    'Audit integrity',
    html`
      <div class="ss-panel__body">
        <dl class="ss-kv">
          <dt>Chain</dt>
          <dd>
            ${data.integrity.intact
              ? html`<span class="ss-badge ss-badge--good">INTACT</span>`
              : html`<span class="ss-badge ss-badge--high">BROKEN</span>`}
          </dd>
          <dt>Entries</dt><dd class="ss-meta">${data.integrity.entryCount}</dd>
          <dt>Head hash</dt><dd class="ss-cell-id ss-cell-id--wrap">${data.integrity.headHash}</dd>
        </dl>
      </div>
    `,
  );
}

function miscMetric(label: string, value: number | string): SafeMarkup {
  return html`
    <div class="ss-metric">
      <span class="ss-metric__label">${label}</span>
      <span class="ss-metric__value">${value}</span>
    </div>
  `;
}