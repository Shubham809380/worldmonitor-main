/**
 * WM SecureScan — deterministic identifiers and finding fingerprints.
 *
 * The fingerprint is the platform's load-bearing idea, so it is worth stating
 * what it has to satisfy:
 *
 *  - **Stable across runs.** The same defect observed in two assessments must
 *    produce the same fingerprint, otherwise the baseline comparison in
 *    `baseline.ts` cannot tell a regression from a new finding.
 *  - **Narrow enough to keep distinct defects apart.** A fingerprint of just
 *    the category would collapse "missing authz on /api/a" and "missing authz
 *    on /api/b" into one, hiding a fix that only covered half the surface.
 *  - **Independent of evidence ids.** Evidence ids are content-addressed and
 *    change whenever a line number moves, which would make fingerprints
 *    unstable for reasons that have nothing to do with the security posture.
 *
 * Endpoint paths are therefore normalised to a *shape* (`/api/x/:id`) so a
 * family of endpoints that share a root cause groups into one finding, while
 * the un-normalised list is preserved separately on the finding.
 */

import { sha256Hex } from './repo';

export type FingerprintDimension =
  | 'category'
  | 'rootCause'
  | 'component'
  | 'endpointShape'
  | 'control'
  | 'boundary';

export interface FingerprintInput {
  readonly category: string;
  readonly rootCause: string;
  readonly component: string;
  readonly endpoints: readonly string[];
  readonly control: string;
  readonly boundary: string | null;
}

const UUID_SEGMENT = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi;
const NUMERIC_SEGMENT = /\d+/g;
const HEX_SEGMENT = /\b[0-9a-f]{16,}\b/gi;
const LONG_OPAQUE = /\b[A-Za-z0-9_-]{32,}\b/g;

/**
 * Reduce a path to its shape.
 *
 * Numeric and hex segments collapse to `:id` because they are the same class
 * of identifier to an attacker: a value the attacker chooses. RSS query
 * strings and fragment identifiers are dropped entirely — they carry request
 * variation, not distinct resources, and keeping them would give every URL
 * parameter its own fingerprint.
 */
export function normalizeEndpoint(path: string): string {
  if (path === '') return '/';
  const withoutQuery = path.split('?')[0] ?? path;
  const withoutFragment = withoutQuery.split('#')[0] ?? withoutQuery;
  return withoutFragment
    .replace(UUID_SEGMENT, ':id')
    .replace(HEX_SEGMENT, ':id')
    .replace(NUMERIC_SEGMENT, ':id')
    .replace(LONG_OPAQUE, ':id')
    .replace(/\/+$/, '')
    .toLowerCase();
}

/**
 * Collapse a list of endpoints to the set of distinct shapes, sorted.
 *
 * Two findings that differ only in *which* member of an endpoint family they
 * hit therefore share a fingerprint, while their `affectedEndpoints` lists
 * differ — which is what lets the console show "4 endpoints, one root cause"
 * instead of four near-identical rows.
 */
export function endpointShapeSet(endpoints: readonly string[]): string[] {
  return [...new Set(endpoints.map(normalizeEndpoint))].sort();
}

export function rootCauseIdFor(input: Pick<FingerprintInput, 'category' | 'rootCause' | 'component'>): Promise<string> {
  return sha256Hex(
    ['rootcause', input.category.trim().toLowerCase(), input.rootCause.trim().toLowerCase(), input.component.trim().toLowerCase()].join(
      '\u0000',
    ),
  ).then((digest) => `RC-${digest.slice(0, 10).toUpperCase()}`);
}

export async function fingerprintFor(input: FingerprintInput): Promise<string> {
  const canonical = [
    `category:${input.category.trim().toLowerCase()}`,
    `rootcause:${input.rootCause.trim().toLowerCase()}`,
    `component:${input.component.trim().toLowerCase()}`,
    `endpoints:${endpointShapeSet(input.endpoints).join(',')}`,
    `control:${input.control.trim().toLowerCase()}`,
    `boundary:${(input.boundary ?? 'none').toLowerCase()}`,
  ].join('\u0000');
  return (await sha256Hex(canonical)).slice(0, 16);
}

/**
 * A display id that stays stable for humans reading a report.
 *
 * Derived from the fingerprint rather than a counter, so re-running an
 * assessment does not renumber findings underneath a reader who has already
 * seen the previous report.
 */
export async function findingIdFor(fingerprint: string, ordinal: number): Promise<string> {
  const digest = await sha256Hex(`finding-id:${fingerprint}`);
  // 24 bits of the digest keep collisions negligible for a single engagement
  // while staying short enough to read aloud in a review.
  const value = Number.parseInt(digest.slice(0, 6), 16) % 0xffffff;
  return `F-${String((ordinal << 24) | value).slice(-6).padStart(6, '0')}`;
}

/** Stable id for a control, independent of any single assessment. */
export function controlIdFor(node: string, control: string): string {
  const slug = (value: string): string =>
    value
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '');
  return `CTRL-${slug(node)}-${slug(control)}`.toUpperCase();
}

/** Stable id for a regression test derived from a control. */
export function regressionTestIdFor(controlId: string, node: string): string {
  const slug = (value: string): string =>
    value
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .toUpperCase();
  return `${slug(controlId)}-${slug(node)}`;
}

/**
 * Stable id for a test, derived from module + slug so reruns match.
 *
 * Deliberately free of any ordinal or counter: a test id has to be identical
 * across assessments so a retest can point at "the same test" and so the
 * regression suite can recognise its own probes. A run-order-dependent id would
 * make both of those silently unreliable. Uniqueness within a module is the
 * module's responsibility to uphold, and the recorder enforces it.
 */
export function testIdFor(module: string, slug: string): string {
  const normalize = (value: string): string =>
    value
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .toUpperCase();
  return `${normalize(module)}-${normalize(slug)}`;
}
