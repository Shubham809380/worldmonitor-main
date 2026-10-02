/**
 * New assessment.
 *
 * The interactive part of this page is a form whose submission goes through the
 * typed API. Two properties are worth stating:
 *
 *  - Whether this form is *shown* is not an authorization decision. The server
 *    decides who may open an assessment, and it answers the same way whether
 *    the caller walked through this form or hit the mutation directly.
 *  - Every field is validated by the server, and its problems are rendered
 *    back. Client-side checks are convenience (an empty field blocks nothing,
 *    it just posts), never the enforcement layer.
 *
 * The authorization note is treated as a record: it is written to the audit
 * chain when the assessment is created, so it should state who authorized the
 * engagement rather than a freeform justification.
 */

import { html } from '../components/dom';
import type { SecureScanView } from '../app';
import { startAssessment } from '../services/api';
import type {
  StartAssessmentInput,
  StartAssessmentResult,
} from '../services/api';

type Kind = StartAssessmentInput['targetKind'];

const KINDS: { value: Kind; label: string; hint: string }[] = [
  { value: 'REPOSITORY', label: 'Source repository', hint: 'A git repository the engine can clone and check' },
  { value: 'DEPLOYED_APPLICATION', label: 'Deployed application', hint: 'A running service, checked over its base URL' },
  { value: 'API', label: 'API', hint: 'An API surface checked over its base URL with the recorded budget' },
];

export function renderNewAssessment(): SecureScanView {
  return {
    body: html`
      <div class="ss-grid ss-grid--2">
        <form class="ss-form" id="ss-new-assessment" novalidate>
          <h3 class="ss-panel__subtitle">Target</h3>

          <div class="ss-field">
            <label class="ss-label" for="ss-na-name">Assessment name</label>
            <input id="ss-na-name" name="name" class="ss-input" type="text" required autocomplete="off" />
            <p class="ss-field__hint">A name your team will recognise. Recorded once, at creation.</p>
          </div>

          <div class="ss-field">
            <label class="ss-label" for="ss-na-target-name">Target name</label>
            <input id="ss-na-target-name" name="targetName" class="ss-input" type="text" required autocomplete="off" />
            <p class="ss-field__hint">The human name of the system being assessed, e.g. an application or service name.</p>
          </div>

          <div class="ss-field">
            <label class="ss-label" for="ss-na-kind">Target kind</label>
            <select id="ss-na-kind" name="targetKind" class="ss-select">
              ${KINDS.map((kind) => html`<option value="${kind.value}">${kind.label}</option>`)}
            </select>
            <p class="ss-field__hint" id="ss-na-kind-hint">${KINDS[0]?.hint}</p>
          </div>

          <div class="ss-field" id="ss-na-repo-field">
            <label class="ss-label" for="ss-na-repo">Repository URL</label>
            <input id="ss-na-repo" name="repositoryUrl" class="ss-input" type="url" autocomplete="off" />
          </div>

          <div class="ss-field" id="ss-na-base-field" hidden>
            <label class="ss-label" for="ss-na-base">Base URL</label>
            <input id="ss-na-base" name="baseUrl" class="ss-input" type="url" autocomplete="off" />
          </div>

          <div class="ss-field">
            <label class="ss-label" for="ss-na-paths">Allowlisted paths</label>
            <textarea
              id="ss-na-paths"
              name="allowlistedPaths"
              class="ss-input ss-input--textarea"
              rows="3"
              spellcheck="false"
              placeholder="One relative or absolute path per line. Empty posts an open target."
            ></textarea>
            <p class="ss-field__hint">Scope boundaries for the run. Anything outside them is recorded out of scope.</p>
          </div>

          <div class="ss-field">
            <label class="ss-label" for="ss-na-budget">Max runtime requests</label>
            <input id="ss-na-budget" name="maxRuntimeRequests" class="ss-input" type="number" inputmode="numeric" min="1" value="200" />
          </div>

          <div class="ss-field">
            <label class="ss-label" for="ss-na-authz">Authorization note</label>
            <textarea
              id="ss-na-authz"
              name="authorizationNote"
              class="ss-input ss-input--textarea"
              rows="4"
              spellcheck="true"
            ></textarea>
            <p class="ss-field__hint">
              Who authorized this engagement and on what authority. Written to the audit chain permanently.
            </p>
          </div>

          <div id="ss-na-status" class="ss-form-status" role="status" aria-live="polite"></div>

          <div class="ss-btn-row">
            <button class="ss-btn ss-btn--primary" type="submit">Open assessment</button>
            <button class="ss-btn" type="reset">Reset</button>
          </div>
        </form>

        <div>
          <h3 class="ss-panel__subtitle">What gets recorded</h3>
          <ol class="ss-plain-list ss-paragraph">
            <li>The target, its kind, the allowlist, and the request budget.</li>
            <li>Your authorized identity and the authorization note, in the audit chain.</li>
            <li>Nothing is scanned at this point. A run is submitted separately and is what produces evidence and findings.</li>
          </ol>
        </div>
      </div>
    `,
    activate(root) {
      activateForm(root);
    },
  };
}

function activateForm(root: HTMLElement): void {
  const form = root.querySelector<HTMLFormElement>('#ss-new-assessment');
  const kindSelect = root.querySelector<HTMLSelectElement>('#ss-na-kind');
  const repoField = root.querySelector<HTMLElement>('#ss-na-repo-field');
  const baseField = root.querySelector<HTMLElement>('#ss-na-base-field');
  const status = root.querySelector<HTMLElement>('#ss-na-status');
  if (!form || !kindSelect || !repoField || !baseField || !status) return;

  const hints = new Map(KINDS.map((kind) => [kind.value, kind.hint]));

  const syncFields = (): void => {
    const kind = kindSelect.value as Kind;
    const repository = kind === 'REPOSITORY';
    const base = kind !== 'REPOSITORY';
    repoField.hidden = !repository;
    baseField.hidden = !base;
    const hint = root.querySelector<HTMLElement>('#ss-na-kind-hint');
    if (hint) hint.textContent = hints.get(kind) ?? '';
  };

  kindSelect.addEventListener('change', syncFields);
  syncFields();

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const submit = form.querySelector<HTMLButtonElement>('button[type="submit"]');
    if (submit) {
      submit.disabled = true;
      status.textContent = 'Opening the assessment…';
    }

    void submitAssessment(form, status)
      .catch(() => {
        setStatus(status, 'warn', 'The request could not be completed. Check the console and retry.');
      })
      .finally(() => {
        if (submit) submit.disabled = false;
      });
  });
}

async function submitAssessment(
  form: HTMLFormElement,
  status: HTMLElement,
): Promise<void> {
  const value = (name: string): string => {
    const el = form.elements.namedItem(name);
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement || el instanceof HTMLSelectElement) {
      return el.value;
    }
    return '';
  };

  const rawPaths = value('allowlistedPaths')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const kind = value('targetKind') as Kind;

  const input: StartAssessmentInput = {
    name: value('name').trim(),
    targetName: value('targetName').trim(),
    targetKind: kind,
    repositoryUrl: kind === 'REPOSITORY' ? value('repositoryUrl').trim() : undefined,
    baseUrl: kind === 'REPOSITORY' ? undefined : value('baseUrl').trim(),
    allowlistedPaths: rawPaths,
    maxRuntimeRequests: Number(value('maxRuntimeRequests')) || 0,
    authorizationNote: value('authorizationNote').trim(),
  };

  const result = await startAssessment(input);
  if (!result.ok) {
    setStatus(status, 'danger', result.message);
    return;
  }
  const started = result.value;
  if (started.ok) {
    window.location.hash = `#/assessments/${encodeURIComponent(started.assessmentId)}`;
    return;
  }
  renderProblems(status, started);
}

function renderProblems(
  status: HTMLElement,
  result: Extract<StartAssessmentResult, { ok: false }>,
): void {
  if (result.problems.length === 0) {
    setStatus(status, 'warn', result.reason);
    return;
  }
  status.textContent = 'The assessment was not opened:';
  result.problems.forEach((problem) => {
    const line = document.createElement('div');
    line.textContent = `${problem.field === 'root' ? 'general' : problem.field}: ${problem.message}`;
    status.appendChild(line);
  });
  status.className = 'ss-form-status ss-form-status--warn';
}

function setStatus(status: HTMLElement, tone: 'warn' | 'danger', message: string): void {
  status.textContent = message;
  status.className = `ss-form-status ss-form-status--${tone}`;
}