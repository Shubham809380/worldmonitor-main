/**
 * SecureScan routing.
 *
 * Hash-based and hand-rolled. A framework is unnecessary for eight surfaces,
 * and a dependency that owns URL parsing is one more place a `javascript:`-bearing
 * path could be normalised into something navigable.
 *
 * This lives apart from `app.ts` so a page can build a link without importing
 * the shell. A page importing the shell to reach `hrefFor` creates a cycle, and
 * the resulting initialisation order is the kind of thing that works in
 * development and produces an undefined route in production.
 *
 * The route table is data, not a registry of components, so the shell can render
 * the whole navigation — including the sections a given role cannot reach — from
 * one place. **Navigation is not authorization.** Every section is listed for
 * every role and the server refuses the ones the caller may not use; a hidden
 * link is a courtesy, and the console behaves correctly when someone arrives at
 * the URL directly.
 */

export type RouteName =
  | 'dashboard'
  | 'assessments'
  | 'assessments-new'
  | 'assessments-detail'
  | 'findings'
  | 'findings-detail'
  | 'evidence'
  | 'report'
  | 'audit'
  | 'admin'
  | 'unknown';

export interface Route {
  name: RouteName;
  params: Record<string, string>;
  title: string;
  /** The heading shown under the product name, kept short and factual. */
  heading: string;
  sub: string;
}

interface RouteSpec {
  name: RouteName;
  title: string;
  heading: string;
  sub: string;
  adminOnly?: boolean;
}

export const ROUTES: Record<string, RouteSpec> = {
  dashboard: {
    name: 'dashboard',
    title: 'Dashboard',
    heading: 'Security Assessment Overview',
    sub: 'Workspace totals, the latest run, and the work still waiting on an analyst. Every figure is a count of stored records.',
  },
  assessments: {
    name: 'assessments',
    title: 'Assessments',
    heading: 'Assessments',
    sub: 'Assessments you own. Each one is a controlled evaluation of a target somebody authorized.',
  },
  'assessments-new': {
    name: 'assessments-new',
    title: 'New Assessment',
    heading: 'New Assessment',
    sub: 'Register an authorized target and open an assessment. The authorization you record here is written into the audit chain permanently.',
  },
  'assessments-detail': {
    name: 'assessments-detail',
    title: 'Assessment',
    heading: 'Assessment',
    sub: 'Run history, check outcomes, and findings for this assessment.',
  },
  findings: {
    name: 'findings',
    title: 'Findings',
    heading: 'Findings',
    sub: 'Every finding across the workspace. A scanner failure is a candidate until an analyst validates it.',
  },
  'findings-detail': {
    name: 'findings-detail',
    title: 'Finding',
    heading: 'Finding',
    sub: 'Evidence, technical detail, validation history, and remediation state.',
  },
  evidence: {
    name: 'evidence',
    title: 'Evidence',
    heading: 'Evidence',
    sub: 'The records findings cite, and the findings that cite them.',
  },
  report: {
    name: 'report',
    title: 'Report',
    heading: 'Assessment Report',
    sub: 'A rendering of what was recorded: coverage, findings, gaps, and audit integrity. There is no overall security score, because a scan cannot produce one.',
  },
  audit: {
    name: 'audit',
    title: 'Audit Center',
    heading: 'Audit Center',
    sub: 'The append-only record of who did what to which assessment, and the integrity check on the chain that holds it. Admin only.',
    adminOnly: true,
  },
  admin: {
    name: 'admin',
    title: 'Administration',
    heading: 'Administration',
    sub: 'Workspace membership, roles, and the audit trail. Admin only.',
    adminOnly: true,
  },
};

export const DEFAULT_ROUTE: RouteName = 'dashboard';

/** Path segment reserved for the create-assessment route. */
const NEW_SEGMENT = 'new';

/**
 * Parses `#/findings/FND-1?state=CANDIDATE` into a route plus params.
 *
 * A malformed percent-escape falls back to the raw segment rather than throwing.
 * Throwing here would take down the whole shell for one bad link, and a broken
 * deep link should render a "not found" view, not a blank page.
 */
export function parseRoute(hash: string): Route {
  const raw = hash.replace(/^#\/?/, '');
  const [pathPart = '', query = ''] = raw.split('?');
  const segments = pathPart
    .split('/')
    .filter(Boolean)
    .map((segment) => {
      try {
        return decodeURIComponent(segment);
      } catch {
        return segment;
      }
    });

  const [first, second] = segments;

  let name: RouteName = DEFAULT_ROUTE;
  if (first !== undefined) {
    // The query carries the id for the one assessment whose id is the reserved
    // word, so that it is reachable at all rather than shadowed by the create
    // route. A bare `#/assessments` with no id is the assessment list.
    const queryId = new URLSearchParams(query).get('assessmentId');
    if (first === 'assessments' && (second === NEW_SEGMENT || (second === undefined && queryId))) {
      name = second === NEW_SEGMENT ? 'assessments-new' : 'assessments-detail';
    } else if (first === 'assessments' && second) name = 'assessments-detail';
    else if (first === 'findings' && second) name = 'findings-detail';
    else if (first in ROUTES) name = first as RouteName;
    else name = 'unknown';
  }

  const params: Record<string, string> = {};

  // The query is read first and the path is read second, so a path segment wins.
  // `#/assessments/ASM-1?assessmentId=ASM-2` used to leave `assessmentId` as
  // "ASM-2": the heading said one assessment while the request fetched another.
  // The server authorizes whatever is requested, so this is not a way to read
  // another tenant's data, but it is an id-confusion bug that makes the rendered
  // URL disagree with the record on screen.
  for (const [key, value] of new URLSearchParams(query)) params[key] = value;
  if (second && first === 'assessments') params.assessmentId = second;
  if (second && first === 'findings') params.findingId = second;

  const spec = ROUTES[name] ?? ROUTES[DEFAULT_ROUTE] ?? {
    name: DEFAULT_ROUTE,
    title: 'Dashboard',
    heading: 'SecureScan Dashboard',
    sub: '',
  };
  return { name, params, title: spec.title, heading: spec.heading, sub: spec.sub };
}

/**
 * Builds an in-app href.
 *
 * The id is percent-encoded because a finding or assessment id is server-issued
 * and a `javascript:` value would otherwise be a navigable link in an admin's
 * session. `safeHref` in `components/dom` is the second line of defence for
 * target URLs, which come from stored data rather than from here.
 */
export function hrefFor(name: RouteName, params: Record<string, string> = {}): string {
  // Canonical spelling for the create route. Without this the create page had
  // two valid URLs -- the shell linked the path form while `hrefFor` emitted the
  // flat form -- so a reviewer could not tell which one was real.
  if (name === 'assessments-new') return '#/assessments/new';
  // The literal segment "new" is reserved for the create route. An assessment
  // id equal to "new" cannot be addressed by path (its id is server-issued, so
  // this never happens in practice), and quietly falling through would render
  // the create form for what the caller asked to see.
  if (name === 'assessments-detail' && params.assessmentId) {
    if (params.assessmentId === NEW_SEGMENT) return `#/assessments?assessmentId=${encodeURIComponent(params.assessmentId)}`;
    return `#/assessments/${encodeURIComponent(params.assessmentId)}`;
  }
  if (name === 'findings-detail' && params.findingId) {
    return `#/findings/${encodeURIComponent(params.findingId)}`;
  }
  if (name === 'evidence' && params.evidenceId) {
    return `#/evidence?evidenceId=${encodeURIComponent(params.evidenceId)}`;
  }
  if (name === 'report' && params.assessmentId) {
    return `#/report?assessmentId=${encodeURIComponent(params.assessmentId)}`;
  }
  if (name === 'audit' && params.assessmentId) {
    return `#/audit?assessmentId=${encodeURIComponent(params.assessmentId)}`;
  }
  if (name === 'findings' && (params.state || params.severity || params.assessmentId)) {
    const search = new URLSearchParams();
    if (params.state) search.set('state', params.state);
    if (params.severity) search.set('severity', params.severity);
    if (params.assessmentId) search.set('assessmentId', params.assessmentId);
    return `#/findings?${search.toString()}`;
  }
  return `#/${name}`;
}

/** Href for an evidence record, from any view that cites it. */
export function evidenceHref(evidenceId: string): string {
  return hrefFor('evidence', { evidenceId });
}
