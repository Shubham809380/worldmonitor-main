/**
 * Audit Center — the append-only trail, and the integrity check on its chain.
 *
 * This surface exists because the chain was being written and verified with no
 * reader: `audit:list` and `audit:verify` were reachable from the API client and
 * consumed by nothing, so the one thing an auditor would want — "show me what
 * happened, and prove it has not been edited" — had no place in the product.
 *
 * Three constraints shape the page:
 *
 *  - **It is admin-only, but it does not decide that.** The server refuses
 *    non-admins at `admin:audit`, and this page renders the refusal. The route
 *    is listed for every role, because a hidden link is a courtesy rather than a
 *    control and someone can always arrive at the URL directly.
 *  - **An empty chain is not a clean chain.** When an assessment has recorded
 *    nothing, the page says so and shows the head hash rather than rendering an
 *    empty table that reads as "nothing happened".
 *  - **Denials are first-class entries.** A refused write is on the chain exactly
 *    like an allowed one, and a filter that hid them would quietly turn an audit
 *    log into a list of successes.
 *
 * The chain is assessment-scoped, so the page is an assessment picker plus a
 * read of one chain. Filtering by outcome is a display filter over records that
 * have already been fetched — it never changes which entries the server
 * considers part of the chain, and the count shown next to the filter is the
 * fetched count, not the filtered one.
 */

import { html, type SafeMarkup } from '../components/dom';
import type { SecureScanView } from '../app';
import {
  deniedState,
  emptyState,
  errorState,
  formatTime,
  metric,
  notice,
  outcomeBadge,
  panel,
  roleBadge,
  shortSubject,
  stateBadge,
} from '../components/ui';
import { link } from '../components/links';
import { hrefFor } from '../routing';
import { listAudit, listMyAssessments, verifyAudit } from '../services/api';
import type {
  AssessmentListReadModel,
  AuditEntryReadModel,
  AuditVerifyReadModel,
} from '../services/api';

/** The server caps `limit` at 500; asking for more is silently clamped. */
const DEFAULT_LIMIT = 200;

type OutcomeFilter = 'ALL' | 'ALLOWED' | 'DENIED';

export async function renderAudit(params: Record<string, string>): Promise<SecureScanView> {
  const assessmentsResult = await listMyAssessments();
  if (!assessmentsResult.ok) {
    return { body: failureState(assessmentsResult.kind, assessmentsResult.message) };
  }
  const assessments = assessmentsResult.value;

  const selectedId = params.assessmentId ?? '';
  if (!selectedId) {
    return { body: renderChooser(assessments) };
  }

  // An assessment id that is not in the readable set is a bad link, not a
  // server failure. Saying "not found" here would send an admin looking for a
  // backend problem that does not exist.
  if (!isSelected(assessments, selectedId)) {
    return { body: renderChooser(assessments, selectedId) };
  }

  const [entriesResult, integrityResult] = await Promise.all([
    listAudit(selectedId, DEFAULT_LIMIT),
    verifyAudit(selectedId),
  ]);

  if (!entriesResult.ok) {
    return { body: failureState(entriesResult.kind, entriesResult.message) };
  }
  if (!integrityResult.ok) {
    return { body: failureState(integrityResult.kind, integrityResult.message) };
  }

  const entries = entriesResult.value;
  const integrity = integrityResult.value;

  return {
    body: html`
      <div class="ss-grid">
        ${renderChooser(assessments, selectedId)}
        ${integrity.intact
          ? notice(
              'good',
              'Chain verified',
              `All ${integrity.entryCount} entries recompute to the stored head hash. Nothing in this chain has been altered or removed.`,
            )
          : notice(
              'danger',
              'Chain verification failed',
              `This chain cannot be treated as a trusted record: ${integrity.problems.join('; ')}`,
            )}
        ${renderIntegrity(integrity)}
        ${renderEntries(entries, integrity.entryCount)}
      </div>
    `,
    activate(root) {
      activateEntries(root, entries, integrity);
    },
  };
}

/* ---------------------------------------------------------------------------
 * Assessment chooser
 * ------------------------------------------------------------------------ */

function renderChooser(assessments: AssessmentListReadModel, selectedId = ''): SafeMarkup {
  const rows = assessments.assessments.map(
    (assessment) => html`
      <tr>
        <td data-label="Assessment">
          <span class="ss-cell-id">${assessment.name}</span>
          ${assessment.assessmentId === selectedId
            ? html`<span class="ss-badge ss-badge--good">SELECTED</span>`
            : ''}
        </td>
        <td data-label="Id" class="ss-cell-id">${shortSubject(assessment.assessmentId)}</td>
        <td data-label="State">${stateBadge(assessment.state)}</td>
        <td data-label="Entries">${link('Open chain', 'audit', { assessmentId: assessment.assessmentId })}</td>
      </tr>
    `,
  );

  return panel(
    'Assessment',
    html`
      <div class="ss-panel__body">
        <p class="ss-paragraph">
          The audit chain belongs to a single assessment. Choose one to read its entries and verify its integrity.
        </p>
        <form class="ss-form" id="ss-audit-picker">
          <div class="ss-field">
            <label class="ss-label" for="ss-audit-assessment">Assessment</label>
            <select id="ss-audit-assessment" class="ss-select" name="assessmentId">
              <option value="">Select an assessment…</option>
              ${assessments.assessments.map(
                (assessment) => html`
                  <option value="${assessment.assessmentId}" ${assessment.assessmentId === selectedId ? html`selected` : ''}>
                    ${assessment.name} · ${shortSubject(assessment.assessmentId)}
                  </option>
                `,
              )}
            </select>
            <p class="ss-field__hint">
              Only assessments readable by your account are listed. This is a navigation aid; the server decides
              whether a chain may be read.
            </p>
          </div>
          <div class="ss-btn-row">
            <button class="ss-btn ss-btn--primary" type="submit">Open chain</button>
          </div>
        </form>
      </div>
      ${assessments.assessments.length === 0
      ? emptyState(
          'NO ASSESSMENTS',
          'You cannot read an audit chain until you own or administer an assessment. Open one to create the first entry.',
          // Without this the copy says "Open one" with nothing to open, which is a
          // dead end: the audit center is not the place assessments are created.
          link('New assessment', 'assessments-new', {}, 'ss-btn ss-btn--primary'),
        )
        : html`
            <div class="ss-table-wrap">
              <table class="ss-table ss-table--stack">
                <thead>
                  <tr>
                    <th scope="col">Assessment</th>
                    <th scope="col">Id</th>
                    <th scope="col">State</th>
                    <th scope="col">Chain</th>
                  </tr>
                </thead>
                <tbody>${rows}</tbody>
              </table>
            </div>
          `}
    `,
  );
}

function isSelected(assessments: AssessmentListReadModel, assessmentId: string): boolean {
  return assessments.assessments.some((assessment) => assessment.assessmentId === assessmentId);
}

/* ---------------------------------------------------------------------------
 * Integrity
 * ------------------------------------------------------------------------ */

function renderIntegrity(integrity: AuditVerifyReadModel): SafeMarkup {
  return panel(
    'Chain integrity',
    html`
      <div class="ss-panel__body">
        <div class="ss-grid ss-grid--metrics">
          ${metric('Entries', integrity.entryCount, 'Server-recorded chain length')}
          ${metric('Verification', integrity.intact ? 'INTACT' : 'BROKEN', 'Recomputed against the stored head')}
          ${metric('Head hash', shortSubject(integrity.headHash), 'Digest the next entry must chain from')}
        </div>
        ${integrity.problems.length > 0
          ? html`
              <ul class="ss-list ss-list--problems">
                ${integrity.problems.map((problem) => html`<li>${problem}</li>`)}
              </ul>
            `
          : html`
              <p class="ss-paragraph">
                Each entry's digest was recomputed from its own content and its predecessor's digest, and the result
                matches the head hash stored on the assessment.
              </p>
            `}
      </div>
    `,
  );
}

/* ---------------------------------------------------------------------------
 * Entries
 * ------------------------------------------------------------------------ */

function renderEntries(entries: AuditEntryReadModel[], chainLength: number): SafeMarkup {
  if (entries.length === 0) {
    return panel(
      'Chain',
      emptyState(
        'NO ENTRIES RECORDED',
        'Nothing has been written to this assessment\'s audit chain. An empty chain carries no evidence that nothing was hidden from it.',
      ),
    );
  }

  const counts = countOutcomes(entries);
  const truncated = chainLength > entries.length;

  return panel(
    `Chain (${entries.length})`,
    html`
      <div class="ss-panel__body">
        <div class="ss-grid ss-grid--metrics">
          ${metric('Fetched', entries.length, truncated ? `of ${chainLength} on the chain` : 'the whole chain')}
          ${metric('Allowed', counts.ALLOWED, 'Writes the server permitted')}
          ${metric('Denied', counts.DENIED, 'Writes the server refused')}
        </div>
        ${truncated
          ? notice(
              'warn',
              'Showing the first entries',
              `This chain holds ${chainLength} entries and ${entries.length} were fetched. Older entries are not shown; use the JSON export to take a copy for review.`,
            )
          : ''}
        <div class="ss-badges ss-badges--gap" role="group" aria-label="Filter by outcome">
          <button class="ss-btn ss-btn--sm" type="button" data-outcome-filter="ALL" aria-pressed="true">
            All ${entries.length}
          </button>
          <button class="ss-btn ss-btn--sm" type="button" data-outcome-filter="ALLOWED" aria-pressed="false">
            Allowed ${counts.ALLOWED}
          </button>
          <button class="ss-btn ss-btn--sm" type="button" data-outcome-filter="DENIED" aria-pressed="false">
            Denied ${counts.DENIED}
          </button>
        </div>
        <div class="ss-btn-row">
          <button class="ss-btn ss-btn--sm" type="button" id="ss-audit-export">Export JSON</button>
        </div>
        <div id="ss-audit-status" class="ss-form-status" role="status" aria-live="polite"></div>
      </div>
      <div class="ss-table-wrap">
        <table class="ss-table ss-table--stack" id="ss-audit-table">
          <thead>
            <tr>
              <th scope="col">Seq</th>
              <th scope="col">When</th>
              <th scope="col">Actor</th>
              <th scope="col">Action</th>
              <th scope="col">Resource</th>
              <th scope="col">Outcome</th>
              <th scope="col">Reason</th>
            </tr>
          </thead>
          <tbody>${entries.map(renderEntryRow)}</tbody>
        </table>
      </div>
    `,
  );
}

function renderEntryRow(entry: AuditEntryReadModel): SafeMarkup {
  return html`
    <tr data-outcome="${entry.outcome}">
      <td data-label="Seq" class="ss-cell-id">${entry.seq}</td>
      <td data-label="When" class="ss-meta">${formatTime(entry.at)}</td>
      <td data-label="Actor">
        ${roleBadge(entry.actorRole)}
        <div class="ss-cell-id">${shortSubject(entry.actorUserId)}</div>
      </td>
      <td data-label="Action">
        ${entry.action}
        ${entry.detail ? html`<div class="ss-meta">${entry.detail}</div>` : ''}
      </td>
      <td data-label="Resource">
        <span class="ss-cell-id">${entry.resourceType}</span>
        <div class="ss-cell-id">${shortSubject(entry.resourceId)}</div>
      </td>
      <td data-label="Outcome">${outcomeBadge(entry.outcome)}</td>
      <td data-label="Reason">
        <span class="ss-cell-id">${entry.reasonCode}</span>
        ${entry.sourceIp ? html`<div class="ss-meta">${entry.sourceIp}</div>` : ''}
      </td>
    </tr>
  `;
}

function countOutcomes(entries: AuditEntryReadModel[]): { ALLOWED: number; DENIED: number } {
  let allowed = 0;
  let denied = 0;
  for (const entry of entries) {
    if (entry.outcome === 'ALLOWED') allowed += 1;
    else denied += 1;
  }
  return { ALLOWED: allowed, DENIED: denied };
}

/* ---------------------------------------------------------------------------
 * Activation
 *
 * The shell remounts the whole view on every paint, so listeners are attached
 * once here and the table body is re-rendered in place rather than replaced,
 * which keeps the filter buttons and the export button live.
 * ------------------------------------------------------------------------ */

function activateEntries(root: HTMLElement, entries: AuditEntryReadModel[], integrity: AuditVerifyReadModel): void {
  const table = root.querySelector<HTMLTableElement>('#ss-audit-table');
  const status = root.querySelector<HTMLElement>('#ss-audit-status');
  if (!table) return;

  const picker = root.querySelector<HTMLFormElement>('#ss-audit-picker');
  picker?.addEventListener('submit', (event) => {
    event.preventDefault();
    const select = picker.querySelector<HTMLSelectElement>('select[name="assessmentId"]');
    const assessmentId = select?.value ?? '';
    if (!assessmentId) {
      if (status) setStatus(status, 'warn', 'Choose an assessment to open its chain.');
      return;
    }
    window.location.hash = hrefFor('audit', { assessmentId }).slice(1);
  });

  const applyFilter = (filter: OutcomeFilter): void => {
    const body = table.querySelector('tbody');
    if (!body) return;
    let shown = 0;
    for (const row of Array.from(body.querySelectorAll<HTMLTableRowElement>('tr'))) {
      const matches = filter === 'ALL' || row.dataset.outcome === filter;
      row.hidden = !matches;
      if (matches) shown += 1;
    }
    if (status) {
      setStatus(
        status,
        'plain',
        filter === 'ALL'
          ? `Showing all ${shown} entries.`
          : `Showing ${shown} of ${entries.length} entries with outcome ${filter}.`,
      );
    }
  };

  for (const button of Array.from(root.querySelectorAll<HTMLButtonElement>('[data-outcome-filter]'))) {
    button.addEventListener('click', () => {
      const filter = (button.dataset.outcomeFilter ?? 'ALL') as OutcomeFilter;
      for (const other of Array.from(root.querySelectorAll<HTMLButtonElement>('[data-outcome-filter]'))) {
        other.setAttribute('aria-pressed', String(other === button));
      }
      applyFilter(filter);
    });
  }

  const exportButton = root.querySelector<HTMLButtonElement>('#ss-audit-export');
  exportButton?.addEventListener('click', () => {
    try {
      // Exactly what was read, plus the verification that was computed on it.
      // Re-verifying in the browser would let a client claim integrity it did
      // not check, so the server's verdict travels with the export.
      const payload = {
        exportedFrom: 'WM SecureScan Audit Center',
        assessmentId: integrity.assessmentId,
        chain: integrity,
        entries,
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `securescan-audit-${integrity.assessmentId}.json`;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
      if (status) setStatus(status, 'good', `Exported ${entries.length} entries as JSON.`);
    } catch {
      if (status) setStatus(status, 'danger', 'The export could not be produced in this browser.');
    }
  });
}

function setStatus(status: HTMLElement, tone: 'plain' | 'warn' | 'good' | 'danger', message: string): void {
  status.textContent = message;
  status.className = tone === 'plain' ? 'ss-form-status' : `ss-form-status ss-form-status--${tone}`;
}

/* ------------------------------------------------------------------------- */

function failureState(kind: string, message: string): SafeMarkup {
  if (kind === 'forbidden') {
    return deniedState(
      'NOT PERMITTED',
      message || 'Reading the audit trail is an administrative action. The server refused this request and recorded the refusal.',
    );
  }
  if (kind === 'no_membership') {
    return deniedState('NO SECURESCAN MEMBERSHIP', 'Your account has no SecureScan membership. An administrator has to grant one.');
  }
  if (kind === 'unauthenticated') {
    return deniedState('AUTHENTICATION REQUIRED', 'Sign in to your World Monitor account to read the audit trail.');
  }
  if (kind === 'not_found') {
    return errorState('NOT FOUND', 'That assessment or audit chain does not exist.');
  }
  if (kind === 'unavailable') {
    return errorState('BACKEND UNAVAILABLE', 'The SecureScan backend could not be reached. Nothing is being shown.');
  }
  return errorState('UNEXPECTED ERROR', 'The request could not be completed. The details were logged server-side.');
}
