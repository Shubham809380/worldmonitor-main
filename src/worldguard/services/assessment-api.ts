/**
 * WorldGuard assessment API.
 *
 * The landing page shows an engine-status card and a posture score. Those are
 * the two surfaces most likely to be mistaken for live measurements, so the
 * result type makes the distinction explicit: `unavailable` means no assessment
 * service answered, and the caller must render the DEMO ASSESSMENT labelling
 * rather than the values it was going to show.
 */

const DEFAULT_BASE = '/api/worldguard/v1';
const REQUEST_TIMEOUT_MS = 8_000;

export interface CollectorState {
  readonly name: string;
  readonly online: boolean;
  readonly latencyMs: number | null;
  readonly lastSuccessAt: string | null;
}

export interface EngineStatus {
  readonly collectors: readonly CollectorState[];
  readonly queueDepth: number | null;
  readonly medianLatencyMs: number | null;
  readonly capturedAt: string;
}

export interface ScoreFactor {
  readonly key: string;
  readonly label: string;
  readonly value: number;
  readonly confidence: number;
  /** Human-readable note from the service, when it supplies one. */
  readonly detail: string | null;
}

export interface RiskScore {
  readonly score: number;
  readonly band: string;
  readonly confidence: number;
  readonly factors: readonly ScoreFactor[];
  readonly subject: string;
  readonly capturedAt: string;
}

export type AssessmentResult<T> =
  | { readonly state: 'available'; readonly data: T }
  | { readonly state: 'unavailable'; readonly reason: 'not_configured' | 'network' | 'malformed' };

function baseUrl(): string {
  try {
    const configured = import.meta.env.VITE_WORLDGUARD_API_BASE;
    if (typeof configured === 'string' && configured.trim() !== '') {
      return configured.trim().replace(/\/+$/, '');
    }
  } catch {
    // No Vite env in this context — use the default.
  }
  return DEFAULT_BASE;
}

function isJson(response: Response): boolean {
  const contentType = response.headers.get('content-type');
  return Boolean(contentType && /\bjson\b/i.test(contentType));
}

async function getJson(path: string, signal?: AbortSignal): Promise<AssessmentResult<unknown>> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const onExternalAbort = (): void => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener('abort', onExternalAbort, { once: true });
  }
  try {
    const response = await fetch(`${baseUrl()}${path}`, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      signal: controller.signal,
      credentials: 'omit',
    });
    if (response.status === 404 || response.status === 405 || response.status === 501) {
      return { state: 'unavailable', reason: 'not_configured' };
    }
    if (!response.ok) return { state: 'unavailable', reason: 'network' };
    if (!isJson(response)) return { state: 'unavailable', reason: 'malformed' };
    return { state: 'available', data: await response.json() };
  } catch {
    return { state: 'unavailable', reason: 'network' };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onExternalAbort);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function parseEngineStatus(payload: unknown): EngineStatus | null {
  if (!isRecord(payload) || !Array.isArray(payload.collectors)) return null;
  const collectors: CollectorState[] = [];
  for (const entry of payload.collectors) {
    if (!isRecord(entry) || typeof entry.name !== 'string') continue;
    collectors.push({
      name: entry.name,
      online: entry.online === true,
      latencyMs: numberOrNull(entry.latencyMs),
      lastSuccessAt: typeof entry.lastSuccessAt === 'string' ? entry.lastSuccessAt : null,
    });
  }
  if (collectors.length === 0) return null;
  return {
    collectors,
    queueDepth: numberOrNull(payload.queueDepth),
    medianLatencyMs: numberOrNull(payload.medianLatencyMs),
    capturedAt: typeof payload.capturedAt === 'string' ? payload.capturedAt : new Date(0).toISOString(),
  };
}

function parseRiskScore(payload: unknown): RiskScore | null {
  if (!isRecord(payload)) return null;
  const score = numberOrNull(payload.score);
  if (score === null) return null;
  const factors: ScoreFactor[] = [];
  if (Array.isArray(payload.factors)) {
    for (const entry of payload.factors) {
      if (!isRecord(entry) || typeof entry.label !== 'string') continue;
      const value = numberOrNull(entry.value);
      if (value === null) continue;
      factors.push({
        key: typeof entry.key === 'string' ? entry.key : entry.label,
        label: entry.label,
        value,
        confidence: numberOrNull(entry.confidence) ?? 0,
        detail: typeof entry.detail === 'string' ? entry.detail : null,
      });
    }
  }
  return {
    score,
    band: typeof payload.band === 'string' ? payload.band : 'Unclassified',
    confidence: numberOrNull(payload.confidence) ?? 0,
    factors,
    subject: typeof payload.subject === 'string' ? payload.subject : 'global',
    capturedAt: typeof payload.capturedAt === 'string' ? payload.capturedAt : new Date(0).toISOString(),
  };
}

export async function fetchEngineStatus(signal?: AbortSignal): Promise<AssessmentResult<EngineStatus>> {
  const result = await getJson('/assessment/status', signal);
  if (result.state === 'unavailable') return result;
  const parsed = parseEngineStatus(result.data);
  return parsed
    ? { state: 'available', data: parsed }
    : { state: 'unavailable', reason: 'malformed' };
}

export async function fetchRiskScore(
  subject = 'global',
  signal?: AbortSignal,
): Promise<AssessmentResult<RiskScore>> {
  const result = await getJson(`/assessment/score?subject=${encodeURIComponent(subject)}`, signal);
  if (result.state === 'unavailable') return result;
  const parsed = parseRiskScore(result.data);
  return parsed
    ? { state: 'available', data: parsed }
    : { state: 'unavailable', reason: 'malformed' };
}
