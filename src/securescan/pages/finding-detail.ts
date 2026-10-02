/**
 * One finding in full.
 *
 * This page is organised around two separations the rest of the product insists
 * on:
 *
 *  - **Severity and validation state stay separate.** The header shows both with
 *    their own badges. A `HIGH`-severity `CANDIDATE` is a strong unvalidated
 *    suggestion, and this layout does not let it masquerade as a confirmed high
 *    severity vulnerability.
 *  - **A finding is only as good as its evidence.** The evidence table is not a
 *    tally badge the way it is in list views; it is the whole body. The
 *    "evidence cited" block names the exact records and the tests that produced
 *    them, because a finding an analyst cannot trace to a record is a finding
 *    that has not been shown to exist.
 *
 * The lifecycle forms on this page call the *existing* `findings.*` mutations —
 * there is no duplicate API. Whether a form is rendered is not an authorization
 * decision: they are shown to every role and the server refuses what a role may
 * not do. A successful write tells the shell to re-read the finding, so nothing
 * is shown that was not re-read from the server.
 */

import { html, type SafeMarkup } from '../components/dom';
import { idLine, link } from '../components/links';
import {
  emptyState,
  formatTime,
  panel,
  roleBadge,
  severityBadge,
  shortSubject,
  stateBadge,
  testStatusBadge,
} from '../components/ui';
import {
  offeredTransitions,
  isScoreable,
  remediationPrecursor,
  retestEligible,
  nextLifecycleStep,
} from './finding-lifecycle';
import type { SecureScanView } from '../app';
import {
  recordRemediation,
  requestRetest,
  scoreFinding,
  transitionFinding,
} from '../services/api';
import type {
  FindingDetailReadModel,
  FindingDetailRow,
  FindingEventReadModel,
  FindingWriteResult,
  Result,
  ScoreFindingInput,
} from '../services/api';

const RISK_FACTORS: [string, string][] = [
  ['Risk methodology', 'See the assessed methodology version in the risk breakdown below.'],
];

export function renderFindingDetail(data: FindingDetailReadModel, _params: Record<string, string>): SecureScanView {
  const finding = data.finding;

  return {
    body: html`
      <div class="ss-grid">
        <div class="ss-grid ss-grid--2">
          ${panel(
            'Finding',
            html`
              <div class="ss-panel__body">
                <h3 class="ss-panel__subtitle">${finding.title}</h3>
                ${idLine([finding.findingId, finding.control, finding.category, `run ${finding.runId}`])}

                <div class="ss-badges ss-badges--gap">
                  ${severityBadge(finding.severity)}
                  ${stateBadge(finding.state, finding.stateLabel)}
                  <span class="ss-meta">confidence ${finding.confidence}</span>
                </div>

                <p class="ss-paragraph">${finding.description}</p>

                <dl class="ss-kv">
                  <dt>Category</dt><dd class="ss-meta">${finding.category}</dd>
                  <dt>Component</dt><dd class="ss-meta">${finding.component ?? '—'}</dd>
                  <dt>Node</dt><dd class="ss-meta">${finding.node ?? '—'}</dd>
                  <dt>Boundary</dt><dd class="ss-meta">${finding.boundary ?? '—'}</dd>
                  <dt>Control</dt><dd class="ss-meta">${finding.control ?? '—'}</dd>
                  <dt>Fingerprint</dt><dd class="ss-cell-id">${finding.fingerprint}</dd>
                </dl>
              </div>
            `,
            link('Assessment', 'assessments-detail', { assessmentId: finding.assessmentId }),
          )}

          ${panel(
            'Assessment context',
            html`
              <div class="ss-panel__body">
                <dl class="ss-kv">
                  <dt>Assessment</dt>
                  <dd class="ss-meta">${finding.assessmentId}</dd>
                  <dt>Run</dt><dd class="ss-meta">${finding.runId}</dd>
                  <dt>Updated</dt><dd class="ss-meta">${formatTime(finding.updatedAt)}</dd>
                  <dt>Report</dt>
                  <dd>
                    ${link('Open the assessment report', 'report', { assessmentId: finding.assessmentId })}
                  </dd>
                </dl>

                <h4 class="ss-panel__subtitle">Root cause</h4>
                <p class="ss-paragraph">${finding.rootCause}</p>
                ${finding.rootCauseId ? html`<div class="ss-cell-id">root cause ${finding.rootCauseId}</div>` : ''}
                ${finding.businessImpact ? html`
                  <h4 class="ss-panel__subtitle">Business impact</h4>
                  <p class="ss-paragraph">${finding.businessImpact}</p>
                ` : ''}
              </div>
            `,
          )}
        </div>

        ${renderRisk(finding.risk)}

        ${renderActions(data)}

        ${renderTimeline(data)}

        ${panel(
          'Evidence cited',
          data.evidence.length === 0
            ? emptyState(
                'NO EVIDENCE CITED',
                'This finding does not cite any evidence record.',
              )
            : html`
                <div class="ss-table-wrap">
                  <table class="ss-table ss-table--stack">
                    <thead>
                      <tr>
                        <th scope="col">Evidence</th>
                        <th scope="col">Type</th>
                        <th scope="col">Collected</th>
                        <th scope="col">View</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${data.evidence.map(
                        (row) => html`
                          <tr>
                            <td data-label="Evidence">
                              <span class="ss-meta">${row.evidenceId}</span>
                              ${idLine([row.description])}
                            </td>
                            <td data-label="Type"><span class="ss-meta">${row.type}</span></td>
                            <td data-label="Collected" class="ss-cell-id">${formatTime(row.collectedAt)}</td>
                            <td data-label="View">
                              ${link('Open', 'evidence', { evidenceId: row.evidenceId })}
                            </td>
                          </tr>
                        `,
                      )}
                    </tbody>
                  </table>
                </div>
              `,
        )}

        ${renderTests(data)}

        ${finding.remediationSummary
          ? panel(
              'Remediation',
              html`
                <div class="ss-panel__body">
                  <p class="ss-paragraph">${finding.remediationSummary}</p>
                  <dl class="ss-kv">
                    <dt>Recorded</dt><dd class="ss-meta">${formatTime(finding.remediatedAt)}</dd>
                    <dt>Last retest</dt>
                    <dd class="ss-meta">
                      ${finding.lastRetestState ? stateBadge(finding.lastRetestState) : '—'}
                      ${finding.lastRetestedAt ? ` · ${formatTime(finding.lastRetestedAt)}` : ''}
                    </dd>
                    ${finding.regressionTestId
                      ? html`<dt>Regression test</dt><dd class="ss-meta">${finding.regressionTestId}</dd>`
                      : ''}
                  </dl>
                </div>
              `,
            )
          : ''}
      </div>
    `,
    activate(root) {
      activateActions(root, finding);
    },
  };
}

/** Renders the parsed risk record, or states its absence. */
function renderRisk(risk: unknown): SafeMarkup {
  if (risk === null || typeof risk !== 'object') {
    return panel(
      'Risk assessment',
      emptyState(
        'NOT SCORED',
        'No analyst risk assessment exists for this finding yet. A candidate without a severity score remains reporting as unscored.',
      ),
    );
  }
  const record = risk as Record<string, unknown>;
  return panel(
    'Risk assessment',
    html`
      <div class="ss-panel__body">
        ${record.severityRationale
          ? html`
              <h4 class="ss-panel__subtitle">Rationale</h4>
              <ul class="ss-plain-list">
                ${(record.severityRationale as string[]).map((line) => html`<li class="ss-paragraph">${line}</li>`)}
              </ul>
            `
          : ''}
        ${RISK_FACTORS.map(
          ([label, hint]) => html`
            <div>
              <div class="ss-meta">${label}</div>
              <div class="ss-field__hint">${hint}</div>
            </div>
          `,
        )}
        ${typeof record.severityMethodologyVersion === 'string'
          ? html`<div class="ss-cell-id">methodology ${record.severityMethodologyVersion}</div>`
          : ''}
      </div>
    `,
  );
}

function renderTimeline(data: FindingDetailReadModel): SafeMarkup {
  const events = data.events;
  if (events.length === 0) return html``;
  return panel(
    `History (${events.length})`,
    html`
      <ol class="ss-timeline">
        ${events.map((event) => timelineEvent(event))}
      </ol>
    `,
  );
}

function timelineEvent(event: FindingEventReadModel): SafeMarkup {
  // `stateBadge` returns SafeMarkup, so the from/to pair has to be composed
  // inside an `html` template. Building it with a plain template literal
  // stringified each badge to "[object Object]".
  const label =
    event.fromState && event.toState
      ? html`${stateBadge(event.fromState)} <span class="ss-meta">→</span> ${stateBadge(event.toState)}`
      : html`${event.kind}`;
  return html`
    <li class="ss-timeline__item">
      <div class="ss-timeline__meta">
        <span class="ss-meta">${event.kind}</span>
        <time class="ss-meta" datetime="${event.at}">${formatTime(event.at)}</time>
      </div>
      <div class="ss-timeline__body">
        <div class="ss-badges ss-badges--gap">${label}</div>
        ${event.note ? html`<p class="ss-paragraph">${event.note}</p>` : ''}
        <div class="ss-cell-id">by ${shortSubject(event.actorUserId)}</div>
      </div>
    </li>
  `;
}

function renderTests(data: FindingDetailReadModel): SafeMarkup {
  if (data.tests.length === 0) return html``;
  return panel(
    'Supporting tests',
    html`
      <div class="ss-table-wrap">
        <table class="ss-table ss-table--stack">
          <thead>
            <tr>
              <th scope="col">Test</th>
              <th scope="col">Status</th>
              <th scope="col">Expected</th>
              <th scope="col">Observed</th>
            </tr>
          </thead>
          <tbody>
            ${data.tests.map((test) => html`
              <tr>
                <td data-label="Test">
                  <span class="ss-meta">${test.testId}</span>
                  ${idLine([test.module, test.control, test.target])}
                </td>
                <td data-label="Status">${testStatusBadge(test.status)}</td>
                <td data-label="Expected" class="ss-cell-id">${test.expected}</td>
                <td data-label="Observed" class="ss-cell-id">${test.observed}</td>
              </tr>
            `)}
          </tbody>
        </table>
      </div>
    `,
  );
}

/* ---------------------------------------------------------------------------
 * Lifecycle action forms.
 *
 * Each form posts to an existing `findings.*` mutation. The server decides who
 * may run it and what each move means; the page only renders the moves the
 * engine's own transition table permits for the current state, then re-reads
 * the finding after a successful write so what is shown comes from the server.
 * ------------------------------------------------------------------------ */

function renderActions(data: FindingDetailReadModel): SafeMarkup {
  const row = data.finding;
  const panels: SafeMarkup[] = [];

  const offered = offeredTransitions(row.state);
  if (offered.length > 0) {
    panels.push(renderTransitionForm(row, offered));
  }

  if (isScoreable(row.state)) {
    panels.push(renderScoreForm(row));
  }

  if (remediationPrecursor(row.state)) {
    panels.push(renderRemediationForm(row));
  }

  if (retestEligible(row.state)) {
    panels.push(renderRetestForm(row));
  }

  // A state can be a dead end even when controls are present: REMEDIATION offers
  // neither the remediation form nor the retest form, so the handoff from "a human
  // described a fix" to "the engine checks it" happened silently. The step note
  // keeps that leg of the workflow legible.
  const nextStep = nextLifecycleStep(row.state);

  if (panels.length === 0 && !nextStep) return html``;

  return html`
    <section class="ss-grid" aria-label="Lifecycle actions">
      <div class="ss-panel__body ss-badges ss-badges--gap">
        ${roleBadge(data.role)}
        <span class="ss-meta">
          Controls are shown for your role and every role. If an action is refused,
          the server records the refusal in the audit chain.
        </span>
      </div>
      ${nextStep
        ? html`
            <p class="ss-paragraph" role="note" data-next-step="${row.state}">
              <strong>Next:</strong> ${nextStep}
            </p>
          `
        : ''}
      ${panels}
    </section>
  `;
}

function renderTransitionForm(row: FindingDetailRow, offered: readonly string[]): SafeMarkup {
  const unscored = row.severity === 'NONE';
  return panel(
    'Advance finding',
    html`
      <form class="ss-form" id="ss-fd-transition" novalidate>
        <div class="ss-field">
          <label class="ss-label" for="ss-fd-transition-to">Move to</label>
          <select id="ss-fd-transition-to" name="to" class="ss-select">
            ${offered.map((to) => html`<option value="${to}">${to}</option>`)}
          </select>
          ${unscored
            ? html`
                <p class="ss-field__hint">
                  This finding has not been scored (severity NONE). A move to VALIDATED is refused until an analyst
                  records the risk judgements, because a validated finding must carry the reasoning behind it.
                </p>
              `
            : html`
                <p class="ss-field__hint">
                  Legal next moves from ${row.state}, from the engine's transition table. VERIFIED and FIXED are not
                  offered here: a verified resolution comes from a recorded retest.
                </p>
              `}
        </div>
        <div class="ss-field">
          <label class="ss-label" for="ss-fd-transition-reason">Reason</label>
          <textarea
            id="ss-fd-transition-reason"
            name="reason"
            class="ss-input ss-input--textarea"
            rows="3"
            spellcheck="true"
          ></textarea>
          <p class="ss-field__hint">
            False-positive and accepted-risk decisions need at least 12 characters. Every advance is written to the
            audit chain with your identity.
          </p>
        </div>
        <div id="ss-fd-transition-status" class="ss-form-status" role="status" aria-live="polite"></div>
        <div class="ss-btn-row">
          <button class="ss-btn ss-btn--primary" type="submit">Advance finding</button>
        </div>
      </form>
    `,
  );
}

function renderScoreForm(row: FindingDetailRow): SafeMarkup {
  const rescore = row.severity !== 'NONE';
  return panel(
    rescore ? 'Re-score this finding' : 'Score this finding',
    html`
      <p class="ss-paragraph">
        Severity is never inferred by a scan. It is a judgement a person makes from the evidence, recorded here with
        the reasoning, so a reader can argue with the inputs rather than guess at the band.
      </p>
      <form class="ss-form" id="ss-fd-score" novalidate>
        <div class="ss-grid ss-grid--2">
          <div class="ss-field">
            <label class="ss-label" for="ss-fd-score-exposure">Exposure</label>
            <select id="ss-fd-score-exposure" name="exposure" class="ss-select">
              <option value="PUBLIC_INTERNET">Public internet</option>
              <option value="UNAUTHENTICATED_REMOTE">Unauthenticated remote</option>
              <option value="AUTHENTICATED_REMOTE">Authenticated remote</option>
              <option value="SAME_ORIGIN">Same origin</option>
              <option value="INTERNAL_ONLY">Internal only</option>
              <option value="BUILD_TIME">Build time</option>
            </select>
          </div>
          <div class="ss-field">
            <label class="ss-label" for="ss-fd-score-privileges">Privileges required</label>
            <select id="ss-fd-score-privileges" name="privilegesRequired" class="ss-select">
              <option value="NONE">None</option>
              <option value="USER">User</option>
              <option value="PRIVILEGED">Privileged</option>
            </select>
          </div>
          <div class="ss-field">
            <label class="ss-label" for="ss-fd-score-interaction">User interaction</label>
            <select id="ss-fd-score-interaction" name="userInteraction" class="ss-select">
              <option value="NONE">None</option>
              <option value="REQUIRED">Required</option>
            </select>
          </div>
          <div class="ss-field">
            <label class="ss-label" for="ss-fd-score-dataclass">Data class</label>
            <select id="ss-fd-score-dataclass" name="dataClass" class="ss-select">
              <option value="PUBLIC">Public</option>
              <option value="INTERNAL">Internal</option>
              <option value="CONFIDENTIAL">Confidential</option>
              <option value="REGULATED">Regulated</option>
            </select>
          </div>
          <div class="ss-field">
            <label class="ss-label" for="ss-fd-score-confidentiality">Confidentiality impact</label>
            <select id="ss-fd-score-confidentiality" name="confidentiality" class="ss-select">
              <option value="NONE">None</option>
              <option value="LOW">Low</option>
              <option value="HIGH">High</option>
            </select>
          </div>
          <div class="ss-field">
            <label class="ss-label" for="ss-fd-score-integrity">Integrity impact</label>
            <select id="ss-fd-score-integrity" name="integrity" class="ss-select">
              <option value="NONE">None</option>
              <option value="LOW">Low</option>
              <option value="HIGH">High</option>
            </select>
          </div>
          <div class="ss-field">
            <label class="ss-label" for="ss-fd-score-availability">Availability impact</label>
            <select id="ss-fd-score-availability" name="availability" class="ss-select">
              <option value="NONE">None</option>
              <option value="LOW">Low</option>
              <option value="HIGH">High</option>
            </select>
          </div>
          <div class="ss-field">
            <label class="ss-label" for="ss-fd-score-strength">Evidence strength</label>
            <select id="ss-fd-score-strength" name="evidenceStrength" class="ss-select">
              <option value="INFERENCE">Inference</option>
              <option value="SOURCE">Source</option>
              <option value="CONFIGURATION">Configuration</option>
              <option value="RUNTIME">Runtime</option>
            </select>
          </div>
          <div class="ss-field">
            <label class="ss-label" for="ss-fd-score-correlated">Correlated sources</label>
            <input
              id="ss-fd-score-correlated"
              name="correlatedSources"
              class="ss-input"
              type="number"
              inputmode="numeric"
              min="1"
              value="1"
            />
          </div>
          <div class="ss-field">
            <label class="ss-label">
              <input type="checkbox" name="boundaryCrossed" class="ss-checkbox" /> A trust boundary was crossed
            </label>
            <p class="ss-field__hint">Whether the behaviour crosses into a higher-trust zone.</p>
          </div>
          <div class="ss-field">
            <label class="ss-label">
              <input type="checkbox" name="runtimeValidated" class="ss-checkbox" /> Runtime-validated
            </label>
            <p class="ss-field__hint">
              True only when a runtime test actually demonstrated the behaviour. Setting it is an assertion the analyst
              makes in full view of the evidence.
            </p>
          </div>
        </div>
        <div class="ss-field">
          <label class="ss-label" for="ss-fd-score-justification">Justification</label>
          <textarea
            id="ss-fd-score-justification"
            name="justification"
            class="ss-input ss-input--textarea"
            rows="4"
            spellcheck="true"
          ></textarea>
          <p class="ss-field__hint">
            At least 20 characters explaining why these inputs produce this band. Stored alongside the engine's
            derivation.
          </p>
        </div>
        <div id="ss-fd-score-status" class="ss-form-status" role="status" aria-live="polite"></div>
        <div class="ss-btn-row">
          <button class="ss-btn ss-btn--primary" type="submit">${rescore ? 'Record new severity' : 'Record severity'}</button>
        </div>
      </form>
    `,
  );
}

function renderRemediationForm(row: FindingDetailRow): SafeMarkup {
  return panel(
    'Record remediation',
    html`
      <p class="ss-paragraph">
        Recording a remediation moves this finding to REMEDIATION. Only a retest that passes resolves it; a fix is
        never declared on the strength of a description of one.
      </p>
      <form class="ss-form" id="ss-fd-remediation" novalidate>
        <div class="ss-field">
          <label class="ss-label" for="ss-fd-remediation-summary">What was done</label>
          <textarea
            id="ss-fd-remediation-summary"
            name="summary"
            class="ss-input ss-input--textarea"
            rows="4"
            spellcheck="true"
          ></textarea>
          <p class="ss-field__hint">
            ${row.remediationSummary ? 'A remediation is already recorded for this finding; this replaces it only if the move is still legal.' : 'No remediation is recorded yet.'}
          After this, the finding sits in REMEDIATION and the retest form appears once it reaches RETEST_REQUIRED.
          </p>
        </div>
        <div id="ss-fd-remediation-status" class="ss-form-status" role="status" aria-live="polite"></div>
        <div class="ss-btn-row">
          <button class="ss-btn ss-btn--primary" type="submit">Record remediation</button>
        </div>
      </form>
    `,
  );
}

function renderRetestForm(row: FindingDetailRow): SafeMarkup {
  return panel(
    'Request a retest',
    html`
      <p class="ss-paragraph">
        A retest is a re-execution of the assessment engine against this finding's control, not a judgement you
        type in. Requesting one moves the finding to RETEST_REQUIRED, where it stays until a run reports what it
        found. Only the engine's recorded checks can resolve it, to VERIFIED or REGRESSION.
      </p>
      <form class="ss-form" id="ss-fd-retest" novalidate>
        <div class="ss-field">
          <label class="ss-label" for="ss-fd-retest-notes">What should the retest check?</label>
          <textarea
            id="ss-fd-retest-notes"
            name="notes"
            class="ss-input ss-input--textarea"
            rows="3"
            spellcheck="true"
          ></textarea>
          <p class="ss-field__hint">
            Required. Recorded in the audit chain so whoever runs the retest knows what this finding needs checked.
          </p>
        </div>
        <div id="ss-fd-retest-status" class="ss-form-status" role="status" aria-live="polite"></div>
        <div class="ss-btn-row">
          <button class="ss-btn ss-btn--primary" type="submit">Request retest</button>
        </div>
      </form>
      ${row.state === 'VERIFIED'
        ? html`<p class="ss-field__hint">
            A verified finding can only regress from here. Requesting a retest re-opens it, and a later failure moves
            it to REGRESSION.
          </p>`
        : ''}
    `,
  );
}

function activateActions(root: HTMLElement, row: FindingDetailRow): void {
  const transition = root.querySelector<HTMLFormElement>('#ss-fd-transition');
  transition?.addEventListener('submit', (event) => {
    event.preventDefault();
    const status = root.querySelector<HTMLElement>('#ss-fd-transition-status');
    if (!status) return;
    const to = fieldValue(transition, 'to');
    if (to === 'VALIDATED' && row.severity === 'NONE') {
      setStatus(
        status,
        'warn',
        'This finding has not been scored. Record the risk judgements with the scoring form before validating it.',
      );
      return;
    }
    const reason = fieldValue(transition, 'reason').trim();
    void runWrite(transition, status, () => transitionFinding(row.findingId, to, reason), 'Advancing…');
  });

  const score = root.querySelector<HTMLFormElement>('#ss-fd-score');
  score?.addEventListener('submit', (event) => {
    event.preventDefault();
    const status = root.querySelector<HTMLElement>('#ss-fd-score-status');
    if (!status) return;
    void runWrite(score, status, () => scoreFinding(readScoreInput(score, row.findingId)), 'Scoring…');
  });

  const remediation = root.querySelector<HTMLFormElement>('#ss-fd-remediation');
  remediation?.addEventListener('submit', (event) => {
    event.preventDefault();
    const status = root.querySelector<HTMLElement>('#ss-fd-remediation-status');
    if (!status) return;
    const summary = fieldValue(remediation, 'summary').trim();
    void runWrite(remediation, status, () => recordRemediation(row.findingId, summary), 'Recording…');
  });

  const retest = root.querySelector<HTMLFormElement>('#ss-fd-retest');
  retest?.addEventListener('submit', (event) => {
    event.preventDefault();
    const status = root.querySelector<HTMLElement>('#ss-fd-retest-status');
    if (!status) return;
    // No verdict is read or sent. The analyst describes what needs checking; the
    // engine's recorded result is the only thing that can resolve the finding.
    const notes = fieldValue(retest, 'notes').trim();
    void runWrite(retest, status, () => requestRetest(row.findingId, notes), 'Requesting…');
  });
}

function readScoreInput(form: HTMLFormElement, findingId: string): ScoreFindingInput {
  return {
    findingId,
    exposure: fieldValue(form, 'exposure') as ScoreFindingInput['exposure'],
    privilegesRequired: fieldValue(form, 'privilegesRequired') as ScoreFindingInput['privilegesRequired'],
    userInteraction: fieldValue(form, 'userInteraction') as ScoreFindingInput['userInteraction'],
    dataClass: fieldValue(form, 'dataClass') as ScoreFindingInput['dataClass'],
    boundaryCrossed: checkedValue(form, 'boundaryCrossed'),
    confidentiality: fieldValue(form, 'confidentiality') as ScoreFindingInput['confidentiality'],
    integrity: fieldValue(form, 'integrity') as ScoreFindingInput['integrity'],
    availability: fieldValue(form, 'availability') as ScoreFindingInput['availability'],
    runtimeValidated: checkedValue(form, 'runtimeValidated'),
    evidenceStrength: fieldValue(form, 'evidenceStrength') as ScoreFindingInput['evidenceStrength'],
    correlatedSources: Number(fieldValue(form, 'correlatedSources')) || 0,
    justification: fieldValue(form, 'justification').trim(),
  };
}

/**
 * Runs a write, renders its Result, and on success asks the shell to re-read
 * the route so what is on screen comes from the server again.
 */
async function runWrite(
  form: HTMLFormElement,
  status: HTMLElement,
  work: () => Promise<Result<FindingWriteResult>>,
  busy: string,
): Promise<void> {
  const submit = form.querySelector<HTMLButtonElement>('button[type="submit"]');
  if (submit) submit.disabled = true;
  setStatus(status, 'plain', busy);
  try {
    const result = await work();
    if (!result.ok) {
      setStatus(status, 'danger', result.message);
      return;
    }
    const written = result.value;
    if (!written.ok) {
      setStatus(status, 'danger', written.reason);
      return;
    }
    const movedTo = written.state ? ` now ${written.state}` : '';
    setStatus(status, 'plain', `Recorded${movedTo}. Re-reading the finding…`);
    window.dispatchEvent(new CustomEvent('securescan:refresh'));
  } catch {
    setStatus(status, 'danger', 'The request could not be completed. Check the console and retry.');
  } finally {
    if (submit) submit.disabled = false;
  }
}

function fieldValue(form: HTMLFormElement, name: string): string {
  const el = form.elements.namedItem(name);
  if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement) {
    return el.value;
  }
  return '';
}

function checkedValue(form: HTMLFormElement, name: string): boolean {
  const el = form.elements.namedItem(name);
  return el instanceof HTMLInputElement ? el.checked : false;
}

function setStatus(status: HTMLElement, tone: 'plain' | 'warn' | 'danger', message: string): void {
  status.textContent = message;
  status.className = tone === 'plain' ? 'ss-form-status' : `ss-form-status ss-form-status--${tone}`;
}