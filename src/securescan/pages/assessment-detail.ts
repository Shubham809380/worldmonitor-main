/**
 * One assessment in full.
 *
 * The target block is the part that matters most for scope: it is the recorded
 * address, the recorded allowlist, and the recorded request budget for
 * everything below. A reader checking "was this in scope?" is reading those
 * three fields, so they are shown rather than summarised.
 *
 * An assessment with no runs renders a `no run` state, not an empty findings
 * table. "Nothing found" and "nothing looked" are different sentences and the
 * difference is the whole point of the product.
 */

import { html, safeHref, type SafeMarkup } from '../components/dom';
import { idLine, link } from '../components/links';
import {
  emptyState,
  formatDuration,
  formatTime,
  notice,
  panel,
  severityBadge,
  stateBadge,
} from '../components/ui';
import type { AssessmentDetailReadModel } from '../services/api';

export function renderAssessmentDetail(data: AssessmentDetailReadModel, assessmentId: string): SafeMarkup {
  const { assessment, target, runs, findings, testCounts } = data;

  return html`
    <div class="ss-grid">
      ${assessment.abortReason
        ? notice('warn', 'The latest run did not complete', assessment.abortReason)
        : ''}
      ${!runs.length
        ? notice(
            'neutral',
            'No run has been submitted for this assessment',
            'The target is registered and the authorization is on record, but nothing has been assessed. Coverage, evidence, and findings all require a submitted run.',
          )
        : ''}

      <div class="ss-grid ss-grid--2">
        ${panel(
          'Assessment',
          html`
            <div class="ss-panel__body">
              <dl class="ss-kv">
                <dt>Id</dt><dd class="ss-meta">${assessment.assessmentId}</dd>
                <dt>State</dt><dd>${stateBadge(assessment.state)}</dd>
                <dt>Owner</dt><dd class="ss-meta">${assessment.ownerUserId}</dd>
                <dt>Opened</dt><dd class="ss-meta">${formatTime(assessment.createdAt)}</dd>
                <dt>Updated</dt><dd class="ss-meta">${formatTime(assessment.updatedAt)}</dd>
                <dt>Latest run</dt>
                <dd class="ss-meta">${assessment.latestRunId ?? 'none recorded'}</dd>
                <dt>Audit</dt>
                <dd class="ss-meta">${assessment.auditEntryCount} entries · head ${assessment.auditHeadHash.slice(0, 16)}…</dd>
              </dl>
            </div>
          `,
          link('Report', 'report', { assessmentId }),
        )}

        ${panel(
          'Target and scope',
          target
            ? html`
                <div class="ss-panel__body">
                  <dl class="ss-kv">
                    <dt>Name</dt><dd>${target.name}</dd>
                    <dt>Kind</dt><dd class="ss-meta">${target.kind}</dd>
                    <dt>State</dt><dd class="ss-meta">${target.state}</dd>
                    ${target.repositoryUrl
                      ? html`
                          <dt>Repository</dt>
                          <dd>${externalLink(target.repositoryUrl)}</dd>
                        `
                      : ''}
                    ${target.baseUrl
                      ? html`
                          <dt>Base URL</dt>
                          <dd>${externalLink(target.baseUrl)}</dd>
                        `
                      : ''}
                    <dt>Allowlist</dt>
                    <dd>
                      ${target.allowlistedPaths.length === 0
                        ? html`<span class="ss-field__hint">No paths allowlisted.</span>`
                        : html`
                            <ul class="ss-plain-list">
                              ${target.allowlistedPaths.map(
                                (path) => html`<li class="ss-meta">${path}</li>`,
                              )}
                            </ul>
                          `}
                    </dd>
                    <dt>Budget</dt>
                    <dd class="ss-meta">${target.maxRuntimeRequests} requests</dd>
                  </dl>
                  <p class="ss-field__hint" style="margin-top: var(--ss-space-3)">
                    These are the recorded boundaries. Every run below was checked against them by the engine, and
                    anything outside them is recorded as out of scope rather than silently skipped.
                  </p>
                </div>
              `
            : emptyState(
                'TARGET RECORD MISSING',
                'The target row for this assessment is absent. Without it there is no recorded scope, so nothing recorded below can be shown to have stayed in bounds.',
              ),
        )}
      </div>

      ${panel(
        'Runs',
        runs.length === 0
          ? emptyState(
              'NO RUNS',
              'No run has been submitted. The engine produces findings, evidence, and coverage; none of those exist yet.',
            )
          : html`
              <div class="ss-table-wrap">
                <table class="ss-table ss-table--stack">
                  <thead>
                    <tr>
                      <th scope="col">Run</th>
                      <th scope="col">State</th>
                      <th scope="col">Started</th>
                      <th scope="col">Duration</th>
                      <th scope="col">Checks</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${runs.map(
                      (run) => html`
                        <tr>
                          <td data-label="Run">
                            <span class="ss-meta">${run.runId}</span>
                            ${idLine([run.toolVersion, run.modulesRun.join(', ')])}
                          </td>
                          <td data-label="State">
                            ${stateBadge(run.state)}
                            ${run.abortReason ? html`<div class="ss-field__hint">${run.abortReason}</div>` : ''}
                          </td>
                          <td data-label="Started" class="ss-cell-id">${formatTime(run.startedAt)}</td>
                          <td data-label="Duration" class="ss-cell-id">
                            ${formatDuration(run.startedAt, run.finishedAt)}
                          </td>
                          <td data-label="Checks" class="ss-meta">
                            ${run.counts.pass} pass · ${run.counts.fail} fail ·
                            ${run.counts.inconclusive} inconclusive · ${run.counts.notTested} not tested ·
                            ${run.counts.skippedOutOfScope} out of scope
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
        'Check outcomes',
        html`
          <div class="ss-panel__body">
            <dl class="ss-kv">
              <dt>Total</dt><dd class="ss-meta">${testCounts.total}</dd>
              <dt>Pass</dt><dd class="ss-meta">${testCounts.pass}</dd>
              <dt>Fail</dt><dd class="ss-meta">${testCounts.fail}</dd>
              <dt>Inconclusive</dt><dd class="ss-meta">${testCounts.inconclusive}</dd>
              <dt>Not tested</dt><dd class="ss-meta">${testCounts.notTested}</dd>
            </dl>
            <p class="ss-field__hint" style="margin-top: var(--ss-space-3)">
              Counts stored test rows, not a stored summary, so a run written by an older engine version cannot
              disagree with the checks actually recorded.
            </p>
          </div>
        `,
      )}

      ${panel(
        `Findings (${findings.length})`,
        findings.length === 0
          ? emptyState(
              runs.length === 0 ? 'NOTHING ASSESSED' : 'NO FINDINGS IN THIS ASSESSMENT',
              runs.length === 0
                ? 'No run has been submitted, so no check has run and no weakness has been looked for. This is not a clean result.'
                : 'Every check that ran produced no candidate finding. This describes what was checked, not the security of the target as a whole.',
            )
          : html`
              <div class="ss-table-wrap">
                <table class="ss-table ss-table--stack">
                  <thead>
                    <tr>
                      <th scope="col">Finding</th>
                      <th scope="col">Severity</th>
                      <th scope="col">State</th>
                      <th scope="col">Evidence</th>
                      <th scope="col">Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${findings.map(
                      (finding) => html`
                        <tr>
                          <td data-label="Finding">
                            ${link(finding.title, 'findings-detail', { findingId: finding.findingId })}
                            ${idLine([finding.findingId, finding.control])}
                          </td>
                          <td data-label="Severity">${severityBadge(finding.severity)}</td>
                          <td data-label="State">${stateBadge(finding.state, finding.stateLabel)}</td>
                          <td data-label="Evidence" class="ss-cell-num">${finding.evidenceCount}</td>
                          <td data-label="Updated" class="ss-cell-id">${formatTime(finding.updatedAt)}</td>
                        </tr>
                      `,
                    )}
                  </tbody>
                </table>
              </div>
            `,
      )}

      <p class="ss-field__hint">
        <a href="#/findings?assessmentId=${encodeURIComponent(assessmentId)}"
          >Open this assessment's findings in the workspace list</a
        >.
      </p>
    </div>
  `;
}

/**
 * Renders a stored target URL as a link, or as plain text when the scheme is
 * not one this application navigates to.
 *
 * `safeHref` returns empty for a refused scheme, and rendering an empty anchor
 * would be worse than rendering the text: it would look like a link that does
 * nothing. So the value falls back to escaped text, which is still readable and
 * still cannot be activated.
 */
function externalLink(url: string): SafeMarkup {
  const href = safeHref(url);
  if (!href) {
    return html`<span class="ss-meta">${url}</span>`;
  }
  return html`<a href="${href}" target="_blank" rel="noopener noreferrer nofollow">${url}</a>`;
}
