/**
 * Administration — membership, roles, and the audit trail.
 *
 * Two honest constraints shape this page:
 *
 *  - **It is admin-only, but it does not decide that.** The server refuses
 *    non-admins at `admin:users`, and this page renders the refusal. A VIEWER
 *    who navigates here sees the server's answer, not a hidden link.
 *  - **A role change is audited against a specific assessment.** The admin
 *    supplies the assessment whose audit chain the change is written to, and
 *    the server requires it — a role change with no recorded context is
 *    indistinguishable from one that never happened.
 *
 * Self-grant and last-admin removal are refused by the server, and the problem
 * is rendered back; this page never re-implements those rules.
 *
 * Forms are wired once on the members container as a delegated submit listener,
 * so a successful change can repaint the panel without losing its handlers.
 */

import { html, mount, type SafeMarkup } from '../components/dom';
import type { SecureScanView } from '../app';
import { deniedState, emptyState, errorState, formatTime, metric, notice, panel, roleBadge } from '../components/ui';
import { listMembers, setMemberRole } from '../services/api';
import type { MemberReadModel, MemberWriteResult, Result, Role } from '../services/api';

const ROLES: Role[] = ['ADMIN', 'SECURITY_ANALYST', 'VIEWER'];

export async function renderAdmin(): Promise<SecureScanView> {
  const membersResult = await listMembers();
  if (!membersResult.ok) {
    return { body: failureState(membersResult.kind, membersResult.message) };
  }
  const members = membersResult.value;

  return {
    body: html`
      <div class="ss-grid">
        ${notice(
          'neutral',
          'Changes are written to an assessment audit chain',
          'Supply the assessment this administrative change belongs to. The server refuses a role change without one, and the whole change — who, to whom, what, when, and why — is recorded there permanently.',
        )}

        <div class="ss-grid ss-grid--metrics">
          ${metric('Members', members.length, 'SecureScan membership only')}
          ${metric('Admins', members.filter((m) => m.role === 'ADMIN').length, 'Self-grant is refused server-side')}
          ${metric('Analysts', members.filter((m) => m.role === 'SECURITY_ANALYST').length, 'Can triage and score')}
          ${metric('Viewers', members.filter((m) => m.role === 'VIEWER').length, 'Read-only')}
        </div>

        <form class="ss-form" id="ss-admin-context" novalidate>
          <div class="ss-field">
            <label class="ss-label" for="ss-admin-assessment">Assessment for the audit context</label>
            <input
              id="ss-admin-assessment"
              name="assessmentId"
              class="ss-input"
              type="text"
              autocomplete="off"
              required
              placeholder="ASM-…"
            />
            <p class="ss-field__hint">The assessment whose audit chain each change below is attached to.</p>
          </div>
        </form>

        <div id="ss-admin-members">${renderMembers(members)}</div>

        <div class="ss-form-status" id="ss-admin-status" role="status" aria-live="assertive"></div>
      </div>
    `,
    activate(root) {
      const status = root.querySelector<HTMLElement>('#ss-admin-status');
      const contextInput = root.querySelector<HTMLInputElement>('#ss-admin-assessment');
      const panelEl = root.querySelector<HTMLElement>('#ss-admin-members');
      if (!status || !contextInput || !panelEl) return;

      panelEl.addEventListener('submit', (event) => {
        const form = (event.target as HTMLElement).closest<HTMLFormElement>('.ss-admin-form');
        if (!form || !panelEl.contains(form)) return;

        event.preventDefault();
        const userId = form.dataset.user ?? '';
        const reasonInput = form.querySelector<HTMLInputElement>('input[name="reason"]');
        const roleSelect = form.querySelector<HTMLSelectElement>('select[name="role"]');
        const revokeInput = form.querySelector<HTMLInputElement>('input[name="revoke"]');
        if (!reasonInput || !roleSelect || !userId) return;

        const assessmentId = contextInput.value.trim();
        if (!assessmentId) {
          setStatus(status, 'warn', 'Enter the assessment that will carry this audit entry.');
          return;
        }
        const reason = reasonInput.value.trim();
        if (!reason) return;

        void setMemberRole({
          userId,
          role: roleSelect.value as Role,
          assessmentId,
          reason,
          revoke: revokeInput?.checked,
        })
          .then((result: Result<MemberWriteResult>) => {
            if (!result.ok) {
              setStatus(status, 'danger', result.message);
              return undefined;
            }
            const outcome = result.value;
            if (!outcome.ok) {
              setStatus(status, 'danger', outcome.reason);
              return undefined;
            }
            setStatus(status, 'good', `${outcome.action} for ${shortId(outcome.userId)}.`);
            return listMembers().then((res) => {
              if (res.ok) mount(panelEl, renderMembers(res.value));
            });
          })
          .catch(() => {
            setStatus(status, 'danger', 'The change could not be recorded. The details were logged server-side.');
          });
      });
    },
  };
}

function renderMembers(members: MemberReadModel[]): SafeMarkup {
  if (members.length === 0) {
    return panel(
      'Members',
      emptyState(
        'NO MEMBERS',
        'No SecureScan memberships exist. Profile provisioning requires a trusted bootstrap step outside this console.',
      ),
    );
  }
  return panel(
    'Members',
    html`
      <div class="ss-table-wrap">
        <table class="ss-table ss-table--stack">
          <thead>
            <tr>
              <th scope="col">Member</th>
              <th scope="col">Role</th>
              <th scope="col">Granted</th>
              <th scope="col">Change role</th>
            </tr>
          </thead>
          <tbody>
            ${members.map((member) => renderMemberRow(member))}
          </tbody>
        </table>
      </div>
      <p class="ss-field__hint">
        Self-service role changes are refused by the server. Out-of-band bootstrap grants an initial admin; this page
        changes existing memberships only.
      </p>
    `,
  );
}

function renderMemberRow(member: MemberReadModel): SafeMarkup {
  return html`
    <tr>
      <td data-label="Member">
        <span class="ss-cell-id">${member.userId}</span>
        ${member.grantedByUserId ? html`<div class="ss-meta">granted by ${member.grantedByUserId}</div>` : ''}
      </td>
      <td data-label="Role">${roleBadge(member.role)}</td>
      <td data-label="Granted" class="ss-cell-id">${formatTime(member.grantedAt)}</td>
      <td data-label="Change role">
        <form class="ss-inline-form ss-admin-form" data-user="${member.userId}">
          <select class="ss-select ss-select--sm" name="role">
            ${ROLES.map(
              (role) => html`<option value="${role}" ${member.role === role ? html`selected` : ''}>${role}</option>`,
            )}
          </select>
          <input class="ss-input ss-input--sm" name="reason" type="text" autocomplete="off" placeholder="Reason (audited)" required />
          <label class="ss-check">
            <input type="checkbox" name="revoke" />
            <span class="ss-meta">revoke</span>
          </label>
          <button class="ss-btn ss-btn--sm" type="submit">Apply</button>
        </form>
      </td>
    </tr>
  `;
}

function shortId(id: string): string {
  return id.length > 18 ? id.slice(0, 18) : id;
}

function setStatus(status: HTMLElement, tone: 'warn' | 'danger' | 'good', message: string): void {
  status.textContent = message;
  status.className = `ss-form-status ss-form-status--${tone}`;
}

function failureState(kind: string, message: string): SafeMarkup {
  if (kind === 'forbidden') {
    return deniedState('NOT PERMITTED', message || 'Your role does not permit this view. The request was refused by the server.');
  }
  if (kind === 'no_membership') {
    return deniedState('NO SECURESCAN MEMBERSHIP', 'Your account has no SecureScan membership. An administrator has to grant one.');
  }
  if (kind === 'unauthenticated') {
    return deniedState('AUTHENTICATION REQUIRED', 'Sign in to your World Monitor account to reach the SecureScan console.');
  }
  if (kind === 'not_found') {
    return errorState('NOT FOUND', 'That record does not exist, or it was removed.');
  }
  if (kind === 'unavailable') {
    return errorState('BACKEND UNAVAILABLE', 'The SecureScan backend could not be reached. Nothing is being shown.');
  }
  return errorState('UNEXPECTED ERROR', 'The request could not be completed. The details were logged server-side.');
}