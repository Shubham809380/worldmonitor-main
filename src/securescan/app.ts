/**
 * WM SecureScan shell and routing.
 *
 * Routing is hash-based and hand-rolled in `routing.ts`. A framework is
 * unnecessary for ten surfaces, and a dependency that owns URL parsing is one
 * more place a `javascript:`-bearing path could be normalised into something
 * navigable.
 *
 * The route table lives in `routing.ts` and is data, not a registry of
 * components, so the shell can render the whole navigation — including the
 * sections a given role cannot reach — from one place. **Navigation is not
 * authorization.** Every section is listed for every role and the server
 * refuses the ones the caller may not use; a hidden link is a courtesy, and
 * the console behaves correctly when someone arrives at the URL directly.
 */

import { html, mount, type SafeMarkup } from './components/dom';
import { link } from './components/links';
import { deniedState, errorState, roleBadge, shortSubject } from './components/ui';
import { hrefFor, parseRoute, ROUTES, DEFAULT_ROUTE } from './routing';
import type { Route, RouteName } from './routing';
import { fail, getDashboard, getViewerIdentity } from './services/api';
import type { DashboardReadModel, Result, ResultFailure, ViewerIdentityReadModel } from './services/api';
import { renderAssessmentDetail } from './pages/assessment-detail';
import { renderAssessmentList } from './pages/assessments';
import { renderEvidence } from './pages/evidence';
import { renderFindingDetail } from './pages/finding-detail';
import { activateFindingsFilters, renderFindings } from './pages/findings';
import { renderReport } from './pages/report';

const ROOT_ID = 'ss-root';

export type { Role } from './services/api';

/**
 * A rendered SecureScan view.
 *
 * Static pages produce only `body`. Pages that act on a form (New Assessment,
 * Administration) also attach their listeners in `activate`, which the shell
 * calls once the view is in the document. Keeping the two apart means the
 * shell's paint loop stays a single function: assemble markup, mount, activate.
 */
export interface SecureScanView {
  body: SafeMarkup;
  activate?: (view: HTMLElement) => void;
}

const NAV_SECTIONS: { label: string; items: { name: RouteName; label: string }[] }[] = [
  {
    label: 'Assess',
    items: [
      { name: 'dashboard', label: 'Dashboard' },
      { name: 'assessments', label: 'Assessments' },
      { name: 'findings', label: 'Findings' },
      { name: 'evidence', label: 'Evidence' },
    ],
  },
  {
    label: 'Report',
    items: [{ name: 'report', label: 'Report' }],
  },
  {
    label: 'Assurance',
    items: [{ name: 'audit', label: 'Audit Center' }],
  },
  {
    label: 'Workspace',
    items: [{ name: 'admin', label: 'Administration' }],
  },
];

/** The sidebar. Rendered for every role; the server enforces what each may use. */
export function shell(
  current: Route,
  identity: { signedIn: boolean; userId: string | null; role: string | null },
  body: SafeMarkup,
): SafeMarkup {
  return html`
    <div class="ss-app">
      <div class="ss-shell">
        <aside class="ss-sidebar">
          <a class="ss-brand" href="#/dashboard">
            <span class="ss-brand__mark" aria-hidden="true">SS</span>
            <span>
              <span class="ss-brand__name">SecureScan</span>
              <span class="ss-brand__sub">World Monitor</span>
            </span>
          </a>

          <nav class="ss-nav" aria-label="SecureScan sections">
            ${NAV_SECTIONS.map(
              (section) => html`
                <span class="ss-nav__group">${section.label}</span>
                ${section.items.map(
                  (item) => html`
                    <a
                      class="ss-nav__link"
                      href="${hrefFor(item.name)}"
                      ${current.name === item.name ? html`aria-current="page"` : ''}
                    >
                      ${item.label}
                    </a>
                  `,
                )}
              `,
            )}
          </nav>

          <div class="ss-sidebar__foot">
            <strong>${identity.signedIn ? 'Signed in' : 'Not authenticated'}</strong>
            <span class="ss-meta">${identity.userId ? shortSubject(identity.userId) : 'No session'}</span>
            ${identity.signedIn && !identity.role
              ? html`<span class="ss-meta">No SecureScan role</span>`
              : ''}
            ${identity.role ? html`<div style="margin-top:6px">${roleBadge(identity.role)}</div>` : ''}
          </div>
        </aside>

        <main class="ss-main" id="ss-main">
          <div class="ss-topbar">
            <div>
              <h1 class="ss-page-title">${current.heading}</h1>
              <p class="ss-page-sub">${current.sub}</p>
            </div>
            <div class="ss-btn-row">
              <a class="ss-btn ss-btn--sm" href="${hrefFor('assessments-new')}">New assessment</a>
            </div>
          </div>
          <div id="ss-view">${body}</div>
        </main>
      </div>
    </div>
  `;
}

/** Maps a failed call to the state that explains it, without implying a result. */
function failureState(kind: string, _message: string): SafeMarkup {
  if (kind === 'unauthenticated') {
    return deniedState(
      'AUTHENTICATION REQUIRED',
      'Sign in to your World Monitor account to reach the SecureScan console. No assessment data is shown to an unauthenticated caller.',
    );
  }
  if (kind === 'no_membership') {
    return deniedState(
      'NO SECURESCAN MEMBERSHIP',
      'Your account is signed in but has no SecureScan membership. A workspace administrator has to grant one. Authentication alone does not grant access to assessment data.',
    );
  }
  if (kind === 'forbidden') {
    return deniedState('NOT PERMITTED', 'Your role does not permit this view. Nothing is hidden — the request was refused by the server.');
  }
  if (kind === 'not_found') {
    return errorState('NOT FOUND', 'That record does not exist, or it was removed.');
  }
  if (kind === 'unavailable') {
    return errorState(
      'BACKEND UNAVAILABLE',
      'The SecureScan backend could not be reached. No results are being shown, and nothing has been assessed. Retry once the deployment is reachable.',
    );
  }
  return errorState('UNEXPECTED ERROR', 'The request could not be completed. The details were logged server-side.');
}

/**
 * `dashboardResult` carries the dashboard's own failure so the dashboard route
 * can report *why* it has no data. Only read when `dashboard` is null, so it is
 * typed as the failure arm.
 */
async function renderRoute(
  route: Route,
  dashboard: DashboardReadModel | null,
  dashboardResult: ResultFailure = fail('unavailable', 'The dashboard could not be loaded.'),
): Promise<SecureScanView> {
  switch (route.name) {
    case 'dashboard': {
      if (!dashboard) return { body: failureState(dashboardResult.kind, dashboardResult.message) };
      const { renderDashboard } = await import('./pages/dashboard');
      return { body: renderDashboard(dashboard) };
    }
    case 'assessments': {
      const { listMyAssessments } = await import('./services/api');
      const result = await listMyAssessments();
      if (!result.ok) return { body: failureState(result.kind, result.message) };
      return { body: renderAssessmentList(result.value) };
    }
    case 'assessments-new': {
      const { renderNewAssessment } = await import('./pages/new-assessment');
      return renderNewAssessment();
    }
    case 'assessments-detail': {
      const assessmentId = route.params.assessmentId;
      if (!assessmentId) return { body: errorState('MISSING ASSESSMENT', 'No assessment id was supplied.') };
      const { getAssessmentDetail } = await import('./services/api');
      const result = await getAssessmentDetail(assessmentId);
      if (!result.ok) return { body: failureState(result.kind, result.message) };
      return { body: renderAssessmentDetail(result.value, assessmentId) };
    }
    case 'findings': {
      const { listFindings } = await import('./services/api');
      const { isState, isSev } = await import('./pages/findings');
      const args: { limit: number; state?: string; severity?: string; assessmentId?: string } = { limit: 200 };
      // Re-validated here because this is the hop that turns an attacker-reachable
      // URL into a backend query. `renderFindings` validates for rendering, but the
      // request is built before that, so an unknown value from the address bar
      // would otherwise reach Convex as an argument-validation error.
      if (isState(route.params.state)) args.state = route.params.state;
      if (isSev(route.params.severity)) args.severity = route.params.severity;
      if (route.params.assessmentId) args.assessmentId = route.params.assessmentId;
      const result = await listFindings(args);
      if (!result.ok) return { body: failureState(result.kind, result.message) };
      return { body: renderFindings(result.value, route.params), activate: activateFindingsFilters };
    }
    case 'findings-detail': {
      const findingId = route.params.findingId;
      if (!findingId) return { body: errorState('MISSING FINDING', 'No finding id was supplied.') };
      const { getFindingDetail } = await import('./services/api');
      const result = await getFindingDetail(findingId);
      if (!result.ok) return { body: failureState(result.kind, result.message) };
      return renderFindingDetail(result.value, route.params);
    }
    case 'evidence': {
      const evidenceId = route.params.evidenceId;
      if (!evidenceId) {
        return {
          body: errorState(
            'MISSING EVIDENCE',
            'No evidence id was supplied in the URL. Open a finding that cites this evidence or choose it from the findings detail page.',
            link('Go to findings', 'findings', {}, 'ss-btn ss-btn--primary'),
          ),
        };
      }
      const { getEvidence } = await import('./services/api');
      const result = await getEvidence(evidenceId);
      if (!result.ok) return { body: failureState(result.kind, result.message) };
      return { body: renderEvidence(result.value, route.params) };
    }
    case 'report': {
      const assessmentId = route.params.assessmentId;
      if (!assessmentId) {
        return {
          body: errorState(
            'CHOOSE AN ASSESSMENT',
            'A report belongs to one assessment. Open an assessment and choose Report, or pass ?assessmentId=. in the URL.',
            link('Go to assessments', 'assessments', {}, 'ss-btn ss-btn--primary'),
          ),
        };
      }
      const { getReport } = await import('./services/api');
      const result = await getReport(assessmentId);
      if (!result.ok) return { body: failureState(result.kind, result.message) };
      return { body: renderReport(result.value, route.params) };
    }
    case 'audit': {
      const { renderAudit } = await import('./pages/audit');
      return renderAudit(route.params);
    }
    case 'admin': {
      const { renderAdmin } = await import('./pages/admin');
      return renderAdmin();
    }
    default:
      // Reachable: `parseRoute` returns `unknown` for any unrecognised first
      // segment, so a stale or mistyped link lands here. Without an action the
      // reader is stranded on a route that cannot be left from this page.
      return {
        body: errorState(
          'PAGE NOT FOUND',
          'That SecureScan view does not exist. It may have been renamed, or the link may be mistyped.',
          html`<div class="ss-btn-row">
            ${link('Go to dashboard', DEFAULT_ROUTE, {}, 'ss-btn ss-btn--primary')}
            ${link('Browse assessments', 'assessments')}
            ${link('Browse findings', 'findings')}
          </div>`,
        ),
      };
  }
}

function rootElement(): HTMLElement {
  const el = document.getElementById(ROOT_ID);
  if (!el) throw new Error(`SecureScan: #${ROOT_ID} is missing from the page.`);
  return el;
}

/** Annotate the boot skeleton so a failure explains itself instead of spinning. */
export function reportBootFailure(): void {
  document.getElementById('ss-boot')?.classList.add('ss-boot--failed');
}

function clearBootSkeleton(): void {
  document.getElementById('ss-boot')?.remove();
}

let teardown: (() => void) | null = null;

export async function startSecureScan(): Promise<void> {
  const root = rootElement();
  // The boot skeleton is deliberately NOT cleared here. `getDashboard` waits on
  // the auth handshake, which can take seconds; removing the skeleton before the
  // first paint leaves an empty white page for exactly that long. It is removed
  // by the first successful mount instead.

  let inFlight = 0;

  async function paint(): Promise<void> {
    const route = parseRoute(window.location.hash);
    const tick = (inFlight += 1);

    // A malformed backend payload makes a page renderer throw. Without this
    // boundary the rejected promise is unhandled, the shell never mounts, and
    // the console is left blank -- indistinguishable from a hung page load.
    // The reader still gets the navigation and an explanation, and nothing is
    // claimed about the data that failed to render.
    let rendered: SecureScanView;
    let identity: { signedIn: boolean; userId: string | null; role: string | null };
    try {
      // The identity footer and the dashboard are the same authorization
      // decision, so they come from one call. On other routes the dashboard is
      // still the cheapest way to say who we are; the server refuses it if the
      // caller is not a SecureScan member, and that refusal becomes the route's
      // own refusal rather than being fetched twice.
      //
      // `viewer` is asked alongside it because the dashboard refuses non-members,
      // and a refusal must not erase the difference between "no session" and
      // "session without a grant". Without it the sidebar can only say one of
      // those two things and it says the wrong one for a signed-in non-member.
      const [viewerResult, identityResult]: [Result<ViewerIdentityReadModel>, Result<DashboardReadModel>] =
        await Promise.all([getViewerIdentity(), getDashboard()]);

      identity = viewerResult.ok
        ? { signedIn: viewerResult.value.signedIn, userId: viewerResult.value.userId, role: viewerResult.value.role }
        : // The viewer query discloses nothing sensitive, so if it cannot answer,
          // fall back to the dashboard's own verdict rather than inventing a
          // session: "unauthenticated" is the only failure that proves there is
          // no session, and anything else leaves the question open.
          identityResult.ok
          ? { signedIn: true, userId: identityResult.value.userId, role: identityResult.value.role }
          : { signedIn: identityResult.kind !== 'unauthenticated', userId: null, role: null };

      // The dashboard's failure kind travels into the route. Collapsing it to
      // "unavailable" would tell a signed-in caller with no membership that the
      // backend is down, which is a different and false claim.
      rendered = await renderRoute(
        route,
        identityResult.ok ? identityResult.value : null,
        identityResult.ok ? undefined : identityResult,
      );
    } catch (error) {
      console.error('[securescan] route render failed', error);
      identity ??= { signedIn: false, userId: null, role: null };
      rendered = {
        body: errorState(
          'THIS VIEW COULD NOT BE RENDERED',
          'The response could not be displayed. This is a rendering fault, not an assessment result: nothing about your security posture is implied, and no value below has been changed. Retry the page, and report the reference below if it recurs.',
        ),
      };
    }

    // A slower earlier navigation must not overwrite a newer one.
    if (tick !== inFlight) return;
    mount(root, shell(route, identity, rendered.body));
    document.title = `${route.title} · WM SecureScan`;
    if (rendered.activate) {
      const viewEl = root.querySelector('#ss-view');
      if (viewEl) rendered.activate(viewEl as HTMLElement);
    }
  }

  const onHashChange = (): void => {
    void paint();
  };

  const onRefresh = (): void => {
    void paint();
  };

  window.addEventListener('hashchange', onHashChange);
  // A view that has just written (e.g. a finding lifecycle action) asks the
  // shell to re-paint so the screen is re-read from the server rather than
  // composed from local memory of the previous response.
  window.addEventListener('securescan:refresh', onRefresh);
  window.addEventListener('pagehide', () => {
    window.removeEventListener('hashchange', onHashChange);
    window.removeEventListener('securescan:refresh', onRefresh);
    teardown?.();
  });

  if (!window.location.hash) {
    window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}#/dashboard`);
  }
  await paint();
  // First paint has mounted the shell, so the skeleton has done its job.
  clearBootSkeleton();
  teardown = () => root.replaceChildren();
}

export { failureState };
export type { Route };
// Re-exported for tooling and tests that exercise the route table without DOM.
export { ROUTES };