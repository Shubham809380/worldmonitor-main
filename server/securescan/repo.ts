/**
 * WM SecureScan — engine ports.
 *
 * The engine never touches the filesystem, the network, the clock or `process`.
 * Everything it needs arrives through these interfaces. Two consequences the
 * tests depend on:
 *
 *  1. A `RepoSnapshot` is a plain value. The same snapshot + the same scope
 *     yields byte-identical results, which is what makes a retest evidence.
 *  2. No module can accidentally reach the network. A module that needs to
 *     probe must be handed a `ProbeClient` that only routes through
 *     `scope.ts`, so fail-closed enforcement is structural rather than a rule
 *     someone has to remember.
 */

import type {
  AssessmentId,
  Confidence,
  Evidence,
  EvidenceId,
  EvidencePayload,
  EvidenceType,
  Finding,
  FindingId,
  ProbeCapability,
  SecurityTestResult,
  TestId,
  TestRunId,
  TrustBoundaryId,
} from './types';

// ---------------------------------------------------------------------------
// Repository snapshot
// ---------------------------------------------------------------------------

/**
 * An in-memory view of a World Monitor checkout.
 *
 * Only text files the engine actually reasons about are held. `path` is
 * POSIX-style and relative to the repository root so snapshots are comparable
 * across operating systems.
 */
export interface RepoSnapshot {
  readonly rootLabel: string;
  readonly revision: string | null;
  readonly files: ReadonlyMap<string, string>;
  /** Files the engine could not read, with the reason. Reported, not hidden. */
  readonly unreadable: readonly { readonly path: string; readonly reason: string }[];
}

export interface RepoSnapshotOptions {
  /** Case-sensitive path lookup. World Monitor paths are case-sensitive. */
  readonly caseSensitive?: boolean;
}

/** Normalised lookup wrapper. Every read goes through this, never `.files.get`. */
export class RepoView {
  private readonly index: Map<string, string>;

  constructor(
    private readonly snapshot: RepoSnapshot,
    options: RepoSnapshotOptions = {},
  ) {
    this.index = new Map();
    for (const [path, content] of snapshot.files) {
      this.index.set(options.caseSensitive === false ? path.toLowerCase() : path, content);
    }
  }

  get rootLabel(): string {
    return this.snapshot.rootLabel;
  }

  get revision(): string | null {
    return this.snapshot.revision;
  }

  get unreadable(): readonly { readonly path: string; readonly reason: string }[] {
    return this.snapshot.unreadable;
  }

  /** @returns file content, or `null` when absent. */
  read(path: string): string | null {
    const direct = this.index.get(path);
    if (direct !== undefined) return direct;
    const lower = this.index.get(path.toLowerCase());
    return lower ?? null;
  }

  exists(path: string): boolean {
    return this.index.has(path) || this.index.has(path.toLowerCase());
  }

  /** Every stored path, sorted, so iteration order never depends on Map order. */
  paths(): string[] {
    return [...this.index.keys()].sort();
  }

  /**
   * Paths matching a predicate over the full POSIX path. Sorted.
   * Used for discovery (all `api/**`, all `server/worldmonitor/**`).
   */
  select(predicate: (path: string) => boolean): string[] {
    return this.paths().filter(predicate);
  }

  /** All files under a directory prefix, sorted. */
  under(prefix: string): string[] {
    const normalized = prefix.endsWith('/') ? prefix : `${prefix}/`;
    return this.select((path) => path.startsWith(normalized));
  }
}

// ---------------------------------------------------------------------------
// Source inspection helpers (pure, shared by every static module)
// ---------------------------------------------------------------------------

export interface SourceLocation {
  readonly path: string;
  readonly startLine: number;
  readonly endLine: number;
  readonly text: string;
}

/**
 * A line-oriented reader. The engine is a static analyser, so a tiny line
 * reader with located matches is all the machinery it needs — and unlike a
 * real parser it cannot be confused by syntax it does not model.
 */
export class SourceReader {
  private readonly lines: readonly string[];

  constructor(readonly path: string, content: string) {
    this.lines = content.split(/\r?\n/);
  }

  get lineCount(): number {
    return this.lines.length;
  }

  line(number: number): string {
    return this.lines[number - 1] ?? '';
  }

  slice(start: number, end: number): string {
    return this.lines.slice(Math.max(0, start - 1), Math.max(0, end)).join('\n');
  }

  /**
   * Locate every line matching a pattern. Returns 1-based inclusive ranges.
   * Blank lines between matches are folded in so a multi-line construct reads
   * as one evidence block.
   */
  findAll(pattern: RegExp, options: { foldBlankRuns?: number } = {}): SourceLocation[] {
    const found: { start: number; end: number }[] = [];
    for (let i = 0; i < this.lines.length; i += 1) {
      const line = this.lines[i] ?? '';
      pattern.lastIndex = 0;
      if (!pattern.test(line)) continue;
      const previous = found[found.length - 1];
      if (previous && i + 1 - previous.end <= (options.foldBlankRuns ?? 2)) {
        previous.end = i + 1;
      } else {
        found.push({ start: i + 1, end: i + 1 });
      }
    }
    return found.map((range) => ({
      path: this.path,
      startLine: range.start,
      endLine: range.end,
      text: this.slice(range.start, range.end),
    }));
  }

  find(pattern: RegExp, options: { foldBlankRuns?: number } = {}): SourceLocation | null {
    return this.findAll(pattern, options)[0] ?? null;
  }

  /** Does the file contain the pattern anywhere? Cheap pre-filter. */
  has(pattern: RegExp): boolean {
    pattern.lastIndex = 0;
    return this.lines.some((line) => {
      pattern.lastIndex = 0;
      return pattern.test(line);
    });
  }
}

export function readSource(repo: RepoView, path: string): SourceReader | null {
  const content = repo.read(path);
  return content === null ? null : new SourceReader(path, content);
}

/** Parse a JSON file, returning `null` rather than throwing on malformed input. */
export function readJson<T = unknown>(repo: RepoView, path: string): T | null {
  const content = repo.read(path);
  if (content === null) return null;
  try {
    return JSON.parse(content) as T;
  } catch {
    return null;
  }
}

/**
 * Locate a node inside a nested object using a slash/bracket pointer, and
 * return every value along the way. `proxies.vite.server.headers` style.
 */
export function pointerGet(root: unknown, pointer: string): unknown {
  if (pointer === '') return root;
  let cursor: unknown = root;
  for (const rawSegment of pointer.split('.')) {
    const segment = rawSegment.replace(/\[\d+\]$/, '');
    if (cursor === null || typeof cursor !== 'object') return undefined;
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  return cursor;
}

// ---------------------------------------------------------------------------
// Architecture inputs
// ---------------------------------------------------------------------------

/**
 * Which architecture components a snapshot actually contains. The runner
 * derives this from the snapshot itself (probe the known marker paths) rather
 * than accepting it on faith, so a target that is not World Monitor is
 * reported as such instead of scoring a wall of vacuous passes.
 *
 * Declared in `architecture.ts` alongside the detection logic; re-exported here
 * so a module can depend on the engine ports alone.
 */
export type { DetectedArchitecture } from './architecture';

// ---------------------------------------------------------------------------
// Probe port
// ---------------------------------------------------------------------------

export interface ProbeRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: string;
}

export interface ProbeResponse {
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  /** Wall-clock cost in ms, supplied by the client so the engine stays pure. */
  readonly durationMs: number;
}

export type ProbeOutcome =
  | { readonly kind: 'response'; readonly response: ProbeResponse }
  | { readonly kind: 'refused'; readonly reason: string }
  | { readonly kind: 'error'; readonly message: string };

/**
 * The only way a module can touch the network.
 *
 * Implementations MUST consult `ScopeEnforcer` before dispatching, and MUST
 * NOT retry a refused request. `ProbeRefusal` carries the reason so the engine
 * can record `SKIPPED_OUT_OF_SCOPE` rather than a fake `FAIL`.
 */
export interface ProbeClient {
  send(request: ProbeRequest): Promise<ProbeOutcome>;
}

// ---------------------------------------------------------------------------
// Module contract
// ---------------------------------------------------------------------------

export interface ModuleContext {
  readonly assessmentId: AssessmentId;
  readonly runId: TestRunId;
  readonly repo: RepoView;
  readonly probe: ProbeClient | null;
  /** Injected so evidence timestamps are caller-controlled, not `Date.now()`. */
  readonly now: () => string;
  readonly moduleCapability: ProbeCapability;
  /**
   * Detected once by the orchestrator and shared read-only. Passing it here
   * rather than letting each module re-detect keeps the architecture graph
   * identical across modules, so two findings cannot disagree about which
   * components exist.
   */
  readonly architecture: import('./architecture').DetectedArchitecture;
  readonly surface: import('./attack-surface').SurfaceDiscovery;
  /** Authorization context for the running assessment, for scope-aware notes. */
  readonly environment: import('./types').EnvironmentKind;
}

export interface ModuleOutput {
  readonly tests: readonly SecurityTestResult[];
  readonly evidence: readonly Evidence[];
  readonly findings: readonly Finding[];
  readonly controls: readonly import('./types').SecurityControl[];
  readonly coverageNotes: readonly { readonly controlId: string; readonly note: string }[];
}

export function emptyModuleOutput(): ModuleOutput {
  return { tests: [], evidence: [], findings: [], controls: [], coverageNotes: [] };
}

export interface SecurityModule {
  readonly name: string;
  readonly label: string;
  readonly category: string;
  /** Trust boundary this module primarily exercises, for the coverage view. */
  readonly boundary: TrustBoundaryId | null;
  /** Maximum capability the module may use. The orchestrator grants the min. */
  readonly requires: ProbeCapability;
  run(context: ModuleContext): Promise<ModuleOutput> | ModuleOutput;
}

// ---------------------------------------------------------------------------
// Evidence construction
// ---------------------------------------------------------------------------

/**
 * Deterministic evidence id. Content-addressed rather than sequential so the
 * same observation collected in two assessments deduplicates instead of
 * producing two evidence records that later disagree.
 *
 * The assessment id is deliberately *not* mixed in: cross-assessment
 * deduplication is the point. The per-assessment binding lives on the
 * `Evidence` record itself.
 */
export function evidenceIdFor(digest: string): EvidenceId {
  return `EV-${digest.slice(0, 12).toUpperCase()}`;
}

export interface EvidenceDraft {
  readonly type: EvidenceType;
  readonly description: string;
  readonly payload: EvidencePayload;
  readonly producedBy: string;
  readonly testId?: TestId;
  readonly findingId?: FindingId;
  readonly sourceLocation?: string;
}

/**
 * SHA-256 over a canonical serialisation. The engine runs on Vercel Edge, the
 * Node runner, and the browser console; only Web Crypto is available in all
 * three, so this is async by necessity.
 */
export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Stable JSON: keys sorted recursively so digests do not depend on key order. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

export async function buildEvidence(
  assessmentId: AssessmentId,
  now: string,
  environment: import('./types').EnvironmentKind,
  draft: EvidenceDraft,
): Promise<Evidence> {
  // The digest covers the observation only — not the assessment, not the
  // timestamp. That is what lets a retest prove it saw exactly the same thing,
  // and what lets the same evidence deduplicate across assessments instead of
  // arriving as two records that later disagree.
  const digestInput = canonicalJson({
    type: draft.type,
    description: draft.description,
    payload: draft.payload,
    sourceLocation: draft.sourceLocation ?? null,
  });
  const sha256 = await sha256Hex(digestInput);
  return {
    evidenceId: evidenceIdFor(sha256),
    findingId: draft.findingId ?? null,
    testId: draft.testId ?? null,
    assessmentId,
    collectedAt: now,
    type: draft.type,
    description: draft.description,
    payload: draft.payload,
    sha256,
    producedBy: draft.producedBy,
    targetEnvironment: environment,
    sourceLocation: draft.sourceLocation ?? null,
  };
}

/** Confidence a static, file-based observation deserves. */
export function staticObservationConfidence(independentCorroborations: number): Confidence {
  if (independentCorroborations >= 3) return 'HIGH';
  if (independentCorroborations >= 2) return 'MEDIUM';
  return 'LOW';
}
