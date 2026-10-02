/**
 * One evidence record on its own.
 *
 * The payload block is the sensitive part of this page. It is rendered as text,
 * never as markup, because a payload read from a scan target is attacker-typed
 * data. The hash is shown so a reader can compare the exact bytes the engine
 * recorded; the "cited by" list completes the traceability in the other
 * direction from a finding page.
 */

import { html, type SafeMarkup } from '../components/dom';
import { idLine, link } from '../components/links';
import { formatTime, panel, severityBadge, stateBadge } from '../components/ui';
import type { EvidenceReadModel } from '../services/api';

export function renderEvidence(data: EvidenceReadModel, _params: Record<string, string>): SafeMarkup {
  const row = data.evidence;

  return html`
    <div class="ss-grid">
      ${panel(
        'Evidence',
        html`
          <div class="ss-panel__body">
            <h3 class="ss-panel__subtitle">${row.description}</h3>
            ${idLine([row.evidenceId, row.type, row.targetEnvironment])}

            <dl class="ss-kv">
              <dt>Produced by</dt><dd class="ss-meta">${row.producedBy}</dd>
              <dt>Location</dt><dd class="ss-meta">${row.sourceLocation ?? '—'}</dd>
              <dt>Collected</dt><dd class="ss-meta">${formatTime(row.collectedAt)}</dd>
              <dt>Test</dt>
              <dd>${row.testId ? html`<span class="ss-meta">${row.testId}</span>` : '—'}</dd>
            </dl>
          </div>
        `,
      )}

      ${panel(
        'Payload',
        html`
          <div class="ss-panel__body">
            <p class="ss-field__hint" style="margin-top: 0">
              Recorded data, rendered as inert text. It may contain exact
              environment values; do not treat it as sanitised output.
            </p>
            <pre class="ss-pre ss-pre--scroll"><code>${row.payload}</code></pre>
            <div class="ss-cell-id ss-cell-id--wrap">sha256 ${row.sha256}</div>
          </div>
        `,
      )}

      ${data.citedBy.length === 0
        ? ''
        : panel(
            'Cited by',
            html`
              <div class="ss-table-wrap">
                <table class="ss-table ss-table--stack">
                  <thead>
                    <tr>
                      <th scope="col">Finding</th>
                      <th scope="col">Severity</th>
                      <th scope="col">State</th>
                    </tr>
                  </thead>
                  <tbody>
                    ${data.citedBy.map(
                      (finding) => html`
                        <tr>
                          <td data-label="Finding">
                            ${link(finding.title, 'findings-detail', { findingId: finding.findingId })}
                            ${idLine([finding.findingId])}
                          </td>
                          <td data-label="Severity">${severityBadge(finding.severity)}</td>
                          <td data-label="State">${stateBadge(finding.state, finding.stateLabel)}</td>
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