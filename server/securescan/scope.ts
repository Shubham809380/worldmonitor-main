/**
 * WM SecureScan — authorization and scope enforcement.
 *
 * This is the file that makes the platform safe to run. Every rule here is
 * deny-by-default: a request that cannot be positively matched against the
 * declared scope is refused. The platform has no "unscoped" mode, no
 * "just this once" bypass, and no environment variable that widens scope
 * implicitly — widening scope is an explicit edit to the assessment, which
 * leaves a reviewable diff.
 *
 * The three refusals worth knowing:
 *
 *  - `UNAUTHORIZED_TARGET` — the host is not in `allowedDomains`. This is the
 *    refusal that prevents WM SecureScan from ever being a general-purpose
 *    scanner pointed at the public internet.
 *  - `INTENSITY_EXCEEDED` — the assessment is PASSIVE/LOW and a module asked
 *    for more. Modules are granted the *minimum* of what they require and what
 *    the scope permits, so this is a downgrade, not a failure.
 *  - `BUDGET_EXHAUSTED` — the request ceiling is reached. Deliberately
 *    counted, not estimated: a burst limiter that guesses is a burst limiter
 *    that undercounts.
 */

import type { AssessmentScope, ProbeCapability, TestIntensity } from './types';
import type { ProbeRequest } from './repo';

export type ScopeRefusalCode =
  | 'AUTHORIZATION_UNCONFIRMED'
  | 'UNAUTHORIZED_TARGET'
  | 'PATH_OUT_OF_SCOPE'
  | 'INTENSITY_EXCEEDED'
  | 'BUDGET_EXHAUSTED'
  | 'PROBE_UNAVAILABLE'
  | 'SCHEME_NOT_ALLOWED'
  | 'DOMAIN_ENTRIES_MISSING';

export class ProbeRefusal extends Error {
  constructor(
    readonly code: ScopeRefusalCode,
    message: string,
  ) {
    super(message);
    this.name = 'ProbeRefusal';
  }
}

/** Why an assessment may not run at all, independent of any individual request. */
export interface AuthorizationDecision {
  readonly allowed: boolean;
  readonly code: ScopeRefusalCode | null;
  readonly reason: string;
}

const INTENSITY_CAPABILITY: Record<TestIntensity, ProbeCapability> = {
  PASSIVE: 'NONE',
  LOW: 'SINGLE_REQUEST',
  MEDIUM: 'BOUNDED_SEQUENCE',
  HIGH: 'BOUNDED_SEQUENCE',
};

const CAPABILITY_RANK: Record<ProbeCapability, number> = {
  NONE: 0,
  SINGLE_REQUEST: 1,
  BOUNDED_SEQUENCE: 2,
};

/** Scheme allowlist. The engine never speaks plaintext to a remote target. */
const ALLOWED_REMOTE_SCHEMES = new Set(['https:']);

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, '');
}

/**
 * A domain entry is either an exact host or a `*.suffix` wildcard. Nothing
 * broader — `*` or a bare `.` would match every host and defeat the check.
 */
function domainEntryMatches(entry: string, host: string): boolean {
  const normalized = normalizeHost(entry);
  if (normalized === '') return false;
  if (normalized.startsWith('*.')) {
    const suffix = normalized.slice(2);
    return host === suffix || host.endsWith(`.${suffix}`);
  }
  return host === normalized;
}

/**
 * Path prefix match, with a segment boundary. `/api/mcp` must not match
 * `/api/mcp-evil`; a plain `startsWith` would let a sibling path in.
 */
function pathPrefixMatches(prefix: string, pathname: string): boolean {
  const normalized = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  if (normalized === '' || normalized === '/') return true;
  if (!pathname.startsWith(normalized)) return false;
  const next = pathname.charAt(normalized.length);
  return next === '' || next === '/' || next === '?';
}

/**
 * Mutable per-run request accounting. Kept separate from `AssessmentScope`
 * (an immutable declaration) so the declaration stays a value that can be
 * hashed into a report and the counters stay per-run state.
 */
export class ScopeEnforcer {
  private requestsIssued = 0;
  private readonly grantedCapability: ProbeCapability;

  constructor(
    private readonly scope: AssessmentScope,
    private readonly now: () => string,
  ) {
    this.grantedCapability = INTENSITY_CAPABILITY[scope.intensity] ?? 'NONE';
  }

  get capability(): ProbeCapability {
    return this.grantedCapability;
  }

  get issued(): number {
    return this.requestsIssued;
  }

  get remaining(): number {
    return Math.max(0, this.scope.maxRequests - this.requestsIssued);
  }

  /**
   * May an assessment with this scope start at all?
   *
   * This is the gate the console calls before enabling "Start Assessment", and
   * the gate the orchestrator calls again before dispatching the first module.
   * Both call sites exist on purpose: a UI check is a convenience, the
   * orchestrator check is the control.
   */
  authorize(): AuthorizationDecision {
    if (this.scope.authorization === 'UNCONFIRMED') {
      return {
        allowed: false,
        code: 'AUTHORIZATION_UNCONFIRMED',
        reason: 'The assessment has not been confirmed as authorized. WM SecureScan refuses to test an unconfirmed target.',
      };
    }
    if (this.scope.environment === 'PRODUCTION' && this.scope.authorization !== 'CONFIRMED') {
      return {
        allowed: false,
        code: 'AUTHORIZATION_UNCONFIRMED',
        reason: 'A production target requires CONFIRMED authorization. Self-hosted and local declarations do not carry production targets.',
      };
    }
    if (this.scope.allowedDomains.length === 0 && this.grantedCapability !== 'NONE') {
      return {
        allowed: false,
        code: 'DOMAIN_ENTRIES_MISSING',
        reason: 'Active testing requires at least one allowed domain. An empty allowlist cannot be treated as "no restriction".',
      };
    }
    if (this.scope.maxRequests < 0) {
      return {
        allowed: false,
        code: 'BUDGET_EXHAUSTED',
        reason: 'Negative request budget is not a valid configuration.',
      };
    }
    return { allowed: true, code: null, reason: 'Authorized for the declared scope.' };
  }

  /**
   * Downgrade a module's requirement to what the scope permits.
   * Never escalates: a module that needs `BOUNDED_SEQUENCE` under a LOW scope
   * receives `SINGLE_REQUEST`, and the module reports INCONCLUSIVE for the
   * checks it could not complete.
   */
  resolveCapability(required: ProbeCapability): ProbeCapability {
    if (CAPABILITY_RANK[required] > CAPABILITY_RANK[this.grantedCapability]) {
      return this.grantedCapability;
    }
    return required;
  }

  /** Would this module run at all under the granted capability? */
  admits(required: ProbeCapability): boolean {
    return CAPABILITY_RANK[this.grantedCapability] >= CAPABILITY_RANK[required];
  }

  /**
   * Authorize one outbound request. Throws `ProbeRefusal` rather than
   * returning a boolean so a caller cannot forget to check the negative case.
   *
   * Order matters: authorization first, then scheme, then host, then path, then
   * budget. A refused request must not consume budget, or a misconfigured
   * assessment would exhaust its own ceiling probing targets it was never
   * allowed to reach and report a misleading `BUDGET_EXHAUSTED`.
   */
  authorizeRequest(request: ProbeRequest): URL {
    const decision = this.authorize();
    if (!decision.allowed) {
      throw new ProbeRefusal(decision.code ?? 'AUTHORIZATION_UNCONFIRMED', decision.reason);
    }
    if (this.grantedCapability === 'NONE') {
      throw new ProbeRefusal(
        'INTENSITY_EXCEEDED',
        `Assessment intensity ${this.scope.intensity} permits no outbound requests. Run the assessment as PASSIVE, or raise the intensity.`,
      );
    }

    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      throw new ProbeRefusal('UNAUTHORIZED_TARGET', 'Request URL could not be parsed.');
    }

    if (!ALLOWED_REMOTE_SCHEMES.has(url.protocol) && !isLoopback(url.hostname)) {
      throw new ProbeRefusal(
        'SCHEME_NOT_ALLOWED',
        `Scheme ${url.protocol} is not permitted for a remote target. HTTPS only; loopback is exempt for local self-tests.`,
      );
    }

    const host = normalizeHost(url.hostname);
    const inScope = this.scope.allowedDomains.some((entry) => domainEntryMatches(entry, host));
    if (!inScope) {
      throw new ProbeRefusal(
        'UNAUTHORIZED_TARGET',
        `Host ${host} is not listed in the assessment's allowed domains. Refusing to send the request.`,
      );
    }

    const pathScoped =
      this.scope.allowedPaths.length === 0 && this.scope.allowedApiPaths.length === 0
        ? true
        : [...this.scope.allowedPaths, ...this.scope.allowedApiPaths].some((prefix) =>
            pathPrefixMatches(prefix, url.pathname),
          );
    if (!pathScoped) {
      throw new ProbeRefusal(
        'PATH_OUT_OF_SCOPE',
        `Path ${url.pathname} does not match any allowed path prefix for this assessment.`,
      );
    }

    if (this.requestsIssued >= this.scope.maxRequests) {
      throw new ProbeRefusal(
        'BUDGET_EXHAUSTED',
        `Assessment request budget of ${this.scope.maxRequests} is exhausted. No further requests will be sent.`,
      );
    }

    this.requestsIssued += 1;
    return url;
  }

  /**
   * Release a budget slot after a connection-level failure so a refused DNS
   * lookup does not permanently consume the assessment's allowance. Called by
   * the probe client only on `error` outcomes, never on a refusal.
   */
  refundRequest(): void {
    this.requestsIssued = Math.max(0, this.requestsIssued - 1);
  }

  describe(): {
    intensity: TestIntensity;
    capability: ProbeCapability;
    issued: number;
    max: number;
    timeoutMs: number;
  } {
    return {
      intensity: this.scope.intensity,
      capability: this.grantedCapability,
      issued: this.requestsIssued,
      max: this.scope.maxRequests,
      timeoutMs: this.scope.requestTimeoutMs,
    };
  }

  snapshotTimestamp(): string {
    return this.now();
  }
}

export function isLoopback(hostname: string): boolean {
  const host = normalizeHost(hostname);
  return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
}

/**
 * Wrap a real HTTP client so *no* module can bypass the enforcer.
 *
 * The important property is structural: `ProbeClient` implementations only
 * ever reach the network through `send`, and `send` refuses before the
 * underlying client is touched. A module that wants to probe out of scope
 * cannot, because it has no other door.
 */
export function createScopedProbeClient(
  enforcer: ScopeEnforcer,
  transport: (request: ProbeRequest, timeoutMs: number) => Promise<import('./repo').ProbeOutcome>,
): import('./repo').ProbeClient {
  return {
    async send(request) {
      try {
        enforcer.authorizeRequest(request);
      } catch (error) {
        if (error instanceof ProbeRefusal) {
          return { kind: 'refused', reason: `${error.code}: ${error.message}` };
        }
        return { kind: 'refused', reason: 'Scope enforcement failed closed.' };
      }
      // The per-request timeout is the scope's declared ceiling, not the request
      // budget: passing the budget here would hand the transport a timeout in
      // the thousands or a single digit depending on the assessment.
      const outcome = await transport(request, enforcer.describe().timeoutMs);
      if (outcome.kind === 'error') enforcer.refundRequest();
      return outcome;
    },
  };
}
