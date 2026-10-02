/**
 * WM SecureScan — security headers module (TB-1, Browser to Edge).
 *
 * World Monitor does not have one header policy; it has seven, because the
 * surfaces genuinely differ:
 *
 *   /((?!docs|embed|...).*)          app-wide SPA: nonce + strict-dynamic + hashes
 *   /embed, /embed.html               deliberately framable widget, no Sentry origins
 *   /api/slack/oauth/callback         inline-script HTML returned from an API route
 *   /api/discord/oauth/callback       ditto
 *   /api/brief/(.*)                   inline script, self-only frame-ancestors
 *   /wm-widget-sandbox.html           sandbox allow-scripts, no allow-same-origin
 *
 * So this module does not ask "is CSP present". It parses every declared policy,
 * classifies the surface it serves, and evaluates the directives that surface is
 * actually entitled to. `frame-ancestors *` on the embed route is a product
 * decision, not a defect; the same directive missing on an OAuth callback page
 * is a gap. Reporting both as "frame-ancestors" would be worse than useless.
 *
 * Two restraints, repeated because they are the whole point:
 *
 *  - A missing header is a control status, never a severity. Whether an absent
 *    `X-Frame-Options` is exploitable depends on whether anything frames the
 *    response, and the engine does not establish that.
 *  - `Report-Only` is reported as not-enforcing. A `Report-Only` policy observes
 *    violations; it blocks nothing.
 */

import { Recorder, asvs, configEvidence, srcEvidence } from './_helpers';
import { readJson, readSource, type ModuleContext, type SecurityModule } from '../repo';

interface HeaderRule {
  readonly source: string;
  readonly headers: readonly { readonly key: string; readonly value: string }[];
}

interface CspPolicy {
  readonly source: string;
  readonly raw: string;
  /** Directive name (lowercase, without trailing `*`) to its value tokens. */
  readonly directives: ReadonlyMap<string, readonly string[]>;
}

type SurfaceKind = 'APP' | 'FRAMABLE_WIDGET' | 'SANDBOXED_WIDGET' | 'OAUTH_CALLBACK' | 'HTML_DOCUMENT';

interface HeaderVerdict {
  readonly key: string;
  readonly enforcing: boolean;
  readonly source: string;
  readonly value: string;
}

const HTML_SURFACE_NODES = {
  APP: 'browser-spa',
  FRAMABLE_WIDGET: 'browser-spa',
  SANDBOXED_WIDGET: 'browser-spa',
  OAUTH_CALLBACK: 'oauth-server',
  HTML_DOCUMENT: 'browser-spa',
} as const satisfies Record<SurfaceKind, 'browser-spa' | 'oauth-server'>;

/**
 * Fetch directives that inherit from `default-src` when absent. Their absence
 * is only a weakness when there is no `default-src` to inherit from, so the
 * engine must not report them missing from a policy that already declares a
 * restrictive `default-src`.
 */
const FALLBACK_DIRECTIVES: readonly string[] = ['script-src', 'object-src', 'style-src', 'connect-src', 'img-src', 'frame-src'];

/**
 * Directives that have no fallback. Per the specification these default to
 * unrestricted when omitted, so absence is a genuine gap: `base-uri` leaves
 * `<base>` rewriting open, and `form-action` leaves form submission targets
 * open.
 */
const NO_FALLBACK_DIRECTIVES: readonly string[] = ['base-uri', 'form-action', 'frame-ancestors'];


function readRules(config: unknown): readonly HeaderRule[] {
  if (config === null || typeof config !== 'object') return [];
  const headers = (config as { headers?: unknown }).headers;
  if (!Array.isArray(headers)) return [];
  const rules: HeaderRule[] = [];
  for (const raw of headers) {
    if (raw === null || typeof raw !== 'object') continue;
    const record = raw as { source?: unknown; headers?: unknown };
    if (typeof record.source !== 'string' || !Array.isArray(record.headers)) continue;
    const parsed: { key: string; value: string }[] = [];
    for (const item of record.headers) {
      if (item === null || typeof item !== 'object') continue;
      const header = item as { key?: unknown; value?: unknown };
      if (typeof header.key !== 'string' || typeof header.value !== 'string') continue;
      parsed.push({ key: header.key, value: header.value });
    }
    rules.push({ source: record.source, headers: parsed });
  }
  return rules;
}

/**
 * CSP directive names may carry a `*` suffix (`script-src-elem`, `frame-src *`).
 * Normalise to the base name so required-directive checks do not miss a
 * directive that was spelled with a suffix.
 */
function baseDirective(name: string): string {
  return name.endsWith('*') ? name.slice(0, -1) : name;
}

export function parseCsp(source: string, raw: string): CspPolicy {
  const directives = new Map<string, string[]>();
  for (const segment of raw.split(';')) {
    const tokens = segment.trim().split(/\s+/).filter((token) => token !== '');
    const name = tokens[0];
    if (name === undefined) continue;
    const values = tokens.slice(1);
    const key = baseDirective(name.toLowerCase());
    const existing = directives.get(key);
    directives.set(key, existing ? [...existing, ...values] : values);
  }
  return { source, raw, directives };
}

function classify(policy: CspPolicy): SurfaceKind {
  if (/\/oauth\/callback|oauth\/callback|callback/i.test(policy.source)) return 'OAUTH_CALLBACK';
  if (policy.directives.has('sandbox')) return 'SANDBOXED_WIDGET';
  const frameAncestors = policy.directives.get('frame-ancestors') ?? [];
  if (frameAncestors.includes('*')) return 'FRAMABLE_WIDGET';
  if (policy.source.includes('(?!') || frameAncestors.length > 0) return 'APP';
  return 'HTML_DOCUMENT';
}

/** Non-CSP headers evaluated once each, first declaration in file order winning. */
const SIMPLE_HEADERS: readonly { key: string; why: string; required: boolean }[] = [
  { key: 'Strict-Transport-Security', why: 'HSTS blocks protocol downgrade on repeat visits.', required: true },
  { key: 'X-Content-Type-Options', why: 'nosniff stops the browser re-interpreting a response as script.', required: true },
  { key: 'Referrer-Policy', why: 'Limits referrer leakage to third-party origins.', required: false },
  { key: 'X-Frame-Options', why: 'Legacy clickjacking defence; superseded by CSP frame-ancestors where supported.', required: false },
  { key: 'Permissions-Policy', why: 'Restricts device features the dashboard does not use.', required: false },
  { key: 'Cross-Origin-Opener-Policy', why: 'Isolates the browsing context group.', required: false },
  { key: 'Cross-Origin-Embedder-Policy', why: 'Controls which cross-origin resources may embed.', required: false },
];

function isEnforcing(key: string, value: string): boolean {
  return !/report-only/i.test(key) && !/report-only/i.test(value);
}

function findHeader(rules: readonly HeaderRule[], key: string): HeaderVerdict | null {
  const target = key.toLowerCase();

  // The report-only form is a distinct header *name* (`<name>-Report-Only`),
  // not a variant payload. A lookup that matches the enforcing name only will
  // never see a report-only deployment, so "declared but not enforced" would be
  // reported as "absent" — two very different statements to make in a report.
  // An enforcing declaration wins over a report-only one, so it is looked for
  // first.
  const seek = (wanted: string): HeaderVerdict | null => {
    for (const rule of rules) {
      for (const header of rule.headers) {
        if (header.key.toLowerCase() !== wanted) continue;
        return { key: header.key, value: header.value, source: rule.source, enforcing: isEnforcing(header.key, header.value) };
      }
    }
    return null;
  };

  return seek(target) ?? seek(`${target}-report-only`);
}

function truncate(value: string, limit = 300): string {
  return value.length > limit ? `${value.slice(0, limit)}… [+${value.length - limit} chars]` : value;
}

/**
 * Control name for a per-surface CSP policy.
 *
 * The readable source goes in the control's `label`, not in the name, because
 * `controlIdFor` slugs the name into an identifier — and two Vercel sources
 * that differ only in punctuation (e.g. `/embed` vs `/embed.html`) would slug to
 * the same id and silently merge into one control. A short hash of the exact
 * source keeps them distinct. The test for this control passes the same name, so
 * the two join in the coverage view.
 */
function cspControlName(source: string): string {
  return `csp-surface:${fnv1a(source, 0x811c9dc5).toString(16).padStart(8, '0')}`;
}

function fnv1a(input: string, seed: number): number {
  let hash = seed >>> 0;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

export const securityHeadersModule: SecurityModule = {
  name: 'security-headers',
  label: 'Security Headers',
  category: 'SECURITY_HEADERS',
  boundary: 'TB-1-BROWSER-EDGE',
  requires: 'NONE',
  async run(context: ModuleContext) {
    const recorder = new Recorder(context, 'security-headers', 'SECURITY_HEADERS', 'TB-1-BROWSER-EDGE');
    const config = readJson<Record<string, unknown>>(context.repo, 'vercel.json');

    if (config === null) {
      await recorder.test({
        slug: 'header-policy-readable',
        component: 'Vercel Edge',
        control: 'declared-header-policy',
        node: 'vercel-edge',
        target: 'vercel.json',
        expected: 'vercel.json is present and parseable so the header policy can be evaluated',
        observed: 'vercel.json is absent or is not valid JSON in the assessed snapshot',
        status: 'INCONCLUSIVE',
        confidence: 'LOW',
        notes: [
          'The header policy could not be read. An unreadable policy file is not evidence that headers are absent, and no control status is inferred from it.',
        ],
      });
      return { ...recorder.output(), findings: [], coverageNotes: [] };
    }

    const rules = readRules(config);
    const policies: CspPolicy[] = rules
      .filter((rule) => rule.headers.some((header) => header.key.toLowerCase() === 'content-security-policy'))
      .map((rule) => {
        const csp = rule.headers.find((header) => header.key.toLowerCase() === 'content-security-policy');
        return parseCsp(rule.source, csp?.value ?? '');
      });

    // -------------------------------------------------------------------------
    // CSP, evaluated per surface
    // -------------------------------------------------------------------------
    if (policies.length === 0) {
      // Absence is only a legitimate FAIL if it is auditable, so the evidence is
      // the policy file itself: the reader has to be able to confirm the config
      // was read and that it contains no CSP. Without this the recorder rejects
      // the FAIL and the whole module is lost.
      await recorder.test({
        slug: 'csp-declared',
        component: 'Vercel Edge',
        control: 'Content-Security-Policy',
        node: 'vercel-edge',
        target: 'vercel.json',
        expected: 'At least one Content-Security-Policy is declared',
        observed: `vercel.json declares no Content-Security-Policy header (${rules.length} header rule(s) present, none carrying a CSP)`,
        status: 'FAIL',
        confidence: 'HIGH',
        notes: ['The snapshot serves HTML, so a CSP is the primary XSS containment control and its absence is a direct observation.'],
        evidence: [
          configEvidence(
            'vercel.json',
            'headers',
            rules.map((rule) => `${rule.source}: ${rule.headers.map((header) => header.key).join(', ') || 'no headers'}`).join('\n') || 'no header rules',
            'The header rules present in vercel.json, none of which declare a Content-Security-Policy.',
          ),
        ],
      });
    }

    for (const policy of policies) {
      const kind = classify(policy);
      const node = HTML_SURFACE_NODES[kind];
      const scriptSrc = policy.directives.get('script-src') ?? [];
      const hasStrictDynamic = scriptSrc.includes("'strict-dynamic'");
      const hasNonce = scriptSrc.some((token) => token.startsWith("'nonce-"));
      const inlineAllowed = scriptSrc.includes("'unsafe-inline'") && !hasStrictDynamic;
      const evalAllowed = scriptSrc.includes("'unsafe-eval'");
      const sandbox = policy.directives.get('sandbox') ?? [];
      const defaultSrc = policy.directives.get('default-src') ?? [];
      const frameAncestors = policy.directives.get('frame-ancestors') ?? [];
      const framableByDesign = kind === 'FRAMABLE_WIDGET';
      const opaqueOrigin = sandbox.length > 0 && !sandbox.includes('allow-same-origin');

      // CSP fallback semantics, per the specification. `script-src` and
      // `object-src` fall back to `default-src`, so their absence is only a
      // weakness when there is no `default-src` to inherit — and the engine
      // must not report `object-src` missing from a policy that declares
      // `default-src 'none'`, because that policy blocks objects already.
      // `base-uri`, `form-action` and `frame-ancestors` have no fallback, so
      // their absence is a real gap.
      const rootDeclared = defaultSrc.length > 0;
      const defaultIsNone = defaultSrc.includes("'none'");
      const weaknesses: string[] = [];
      const observations: string[] = [];
      let inlineContainedBySandbox = false;

      if (!rootDeclared) {
        weaknesses.push('no default-src, so every fetch directive is unrestricted');
      }
      for (const directive of FALLBACK_DIRECTIVES) {
        if (policy.directives.has(directive)) continue;
        if (!rootDeclared) {
          weaknesses.push(`absent ${directive} with no default-src to inherit`);
        } else if (!defaultIsNone && directive === 'script-src') {
          observations.push(`script-src absent, inheriting default-src ${defaultSrc.join(' ')}`);
        }
      }
      for (const directive of NO_FALLBACK_DIRECTIVES) {
        if (policy.directives.has(directive)) continue;
        // `frame-ancestors` is the point of a framable widget, and a sandboxed
        // widget is already confined to an opaque origin, so neither is a gap.
        if (directive === 'frame-ancestors' && (framableByDesign || kind === 'SANDBOXED_WIDGET')) continue;
        if (directive === 'form-action' && kind === 'SANDBOXED_WIDGET') continue;
        weaknesses.push(`absent ${directive}, which has no fallback and so defaults to unrestricted`);
      }

      // An opaque-origin sandbox is what makes an inline-script allowance
      // defensible: the document cannot reach the embedder's origin at all.
      // Reporting that as a weakness while the notes explain why it is fine
      // would be a report that contradicts itself.
      if (inlineAllowed) {
        if (opaqueOrigin) {
          inlineContainedBySandbox = true;
        } else {
          weaknesses.push("script-src permits 'unsafe-inline' without 'strict-dynamic' to neutralise it");
        }
      }
      if (evalAllowed) {
        weaknesses.push("script-src permits 'unsafe-eval'");
      }

      const expected = buildExpectation(kind, { hasNonce, hasStrictDynamic, opaqueOrigin });
      const observed = buildObservation(kind, {
        inlineAllowed,
        inlineContainedBySandbox,
        evalAllowed,
        weaknesses,
        observations,
        frameAncestors,
        sandbox,
        opaqueOrigin,
      });
      const controlName = cspControlName(policy.source);

      await recorder.test({
        slug: `csp-surface-${slugify(policy.source)}`,
        component: `Edge policy ${policy.source}`,
        control: controlName,
        node,
        target: policy.source,
        expected,
        observed,
        status: weaknesses.length === 0 ? 'PASS' : 'FAIL',
        confidence: 'HIGH',
        notes: buildNotes(policy, kind, {
          weaknesses,
          observations,
          inlineAllowed,
          inlineContainedBySandbox,
          hasNonce,
          hasStrictDynamic,
          opaqueOrigin,
          framableByDesign,
          frameAncestors,
        }),
        evidence: [configEvidence('vercel.json', `headers.${policy.source}.Content-Security-Policy`, truncate(policy.raw), `CSP for ${policy.source}.`)],
      });

      await recorder.control({
        control: controlName,
        node,
        label: `CSP for ${policy.source}`,
        status: weaknesses.length === 0 ? 'PRESENT' : 'WEAK',
        rationale:
          weaknesses.length === 0
            ? `The ${describeKind(kind)} policy declares default-src and base-uri with no unneutralised script escape.`
            : `${describeKind(kind)} policy: ${weaknesses.join('; ')}.`,
        evidence: [configEvidence('vercel.json', `headers.${policy.source}.Content-Security-Policy`, truncate(policy.raw), `CSP for ${policy.source}.`)],
        mappings: [asvs('V14.4.1'), asvs('V14.4.7')],
      });
    }

    // -------------------------------------------------------------------------
    // The rest of the header set, evaluated once
    // -------------------------------------------------------------------------
    for (const header of SIMPLE_HEADERS) {
      const found = findHeader(rules, header.key);
      const evidence = found
        ? [configEvidence('vercel.json', `headers.${found.source}.${found.key}`, truncate(found.value), `${header.key} as configured.`)]
        : [];
      if (found === null) {
        await recorder.test({
          slug: slugify(header.key),
          component: 'Vercel Edge',
          control: header.key,
          node: 'vercel-edge',
          target: `vercel.json (no ${header.key})`,
          expected: `${header.key} declared`,
          observed: `No ${header.key} header is declared by any rule in vercel.json`,
          status: 'INCONCLUSIVE',
          confidence: 'LOW',
          notes: [
            `Absence is reported, not scored. ${header.why} Whether the absence is exploitable depends on the response being framed, sniffed or cached, which this static check did not establish.`,
          ],
        });
        await recorder.control({
          control: header.key,
          node: 'vercel-edge',
          label: header.key,
          status: 'ABSENT',
          rationale: `Not declared in vercel.json. ${header.why}`,
        });
        continue;
      }

      await recorder.test({
        slug: slugify(header.key),
        component: 'Vercel Edge',
        control: header.key,
        node: 'vercel-edge',
        target: `${found.source} -> ${found.key}`,
        expected: `${header.key} set with an enforcing value`,
        observed: found.enforcing
          ? `set with an enforcing value by ${found.source}`
          : `declared in report-only mode by ${found.source} (${found.value})`,
        status: found.enforcing ? 'PASS' : 'FAIL',
        confidence: 'HIGH',
        notes: found.enforcing
          ? [header.why]
          : [
              `A Report-Only header reports violations and blocks none. ${header.why} Treating it as enforced would overstate the deployed posture.`,
            ],
        evidence,
      });
      await recorder.control({
        control: header.key,
        node: 'vercel-edge',
        label: header.key,
        status: found.enforcing ? 'PRESENT' : 'WEAK',
        rationale: found.enforcing
          ? `Declared with an enforcing value by ${found.source}.`
          : `Declared in report-only mode by ${found.source}, so it does not block. ${header.why}`,
        evidence,
        mappings: [asvs('V14.4.1')],
      });
    }

    // Whether the declared policy is authoritative depends on middleware not
    // rewriting headers downstream. Checked rather than assumed.
    const middleware = readSource(context.repo, 'middleware.ts');
    if (middleware) {
      const mutates = /NextResponse\.(json|redirect|rewrite|next)|headers\.(set|append|delete)\(/.test(middleware.slice(1, middleware.lineCount));
      await recorder.test({
        slug: 'header-policy-is-authoritative',
        component: 'Vercel Edge',
        control: 'header-policy-authority',
        node: 'vercel-edge',
        target: 'middleware.ts',
        expected: 'Middleware constructs responses in a way that preserves the vercel.json header policy, or replaces it deliberately',
        observed: mutates
          ? 'middleware.ts constructs responses directly; whether the vercel.json header policy still applies to those responses was not established by this check'
          : 'middleware.ts does not appear to construct responses itself, so the vercel.json policy is not superseded there',
        status: 'INCONCLUSIVE',
        confidence: 'LOW',
        notes: [
          'Response-construction shape in middleware cannot be resolved statically to a yes/no. The recorded status is INCONCLUSIVE rather than a guess in either direction.',
        ],
        evidence: [srcEvidence('middleware.ts', 1, Math.min(middleware.lineCount, 80), middleware.slice(1, Math.min(middleware.lineCount, 80)), 'middleware.ts response construction.')],
      });
    }

    return { ...recorder.output(), findings: [], coverageNotes: [] };
  },
};

function describeKind(kind: SurfaceKind): string {
  switch (kind) {
    case 'APP':
      return 'application-wide';
    case 'FRAMABLE_WIDGET':
      return 'framable widget';
    case 'SANDBOXED_WIDGET':
      return 'sandboxed widget';
    case 'OAUTH_CALLBACK':
      return 'OAuth callback';
    default:
      return 'HTML document';
  }
}

function buildExpectation(
  kind: SurfaceKind,
  flags: { hasNonce: boolean; hasStrictDynamic: boolean; opaqueOrigin: boolean },
): string {
  const base = 'declares default-src and base-uri';
  switch (kind) {
    case 'SANDBOXED_WIDGET':
      return `${base}; runs under sandbox without allow-same-origin (opaque origin) so inline script is contained (observed sandbox=${flags.opaqueOrigin ? 'opaque' : 'same-origin permitted'})`;
    case 'FRAMABLE_WIDGET':
      return `${base}; script-src carries no inline or eval escape, and form-action/object-src stay closed so being framed by arbitrary sites does not grant script execution or form submission`;
    case 'OAUTH_CALLBACK':
      return `${base}; and declares frame-ancestors and form-action, because this surface returns markup from an API route rather than serving a static document`;
    case 'APP':
      return `${base}; script-src is nonce- and hash-based so inline script requires a per-response nonce (observed nonce=${flags.hasNonce}, strict-dynamic=${flags.hasStrictDynamic})`;
    default:
      return base;
  }
}

function buildObservation(
  kind: SurfaceKind,
  flags: {
    inlineAllowed: boolean;
    inlineContainedBySandbox: boolean;
    evalAllowed: boolean;
    weaknesses: readonly string[];
    observations: readonly string[];
    frameAncestors: readonly string[];
    sandbox: readonly string[];
    opaqueOrigin: boolean;
  },
): string {
  const parts: string[] = [];
  parts.push(flags.weaknesses.length === 0 ? 'policy met its expectations' : `weakness: ${flags.weaknesses.join('; ')}`);
  // The script-escape verdict is stated once. When the sandbox already contains
  // the inline allowance it is not also listed as a weakness, so repeating the
  // phrase here would make the same fact appear to contradict itself.
  if (flags.inlineContainedBySandbox) {
    parts.push("script-src 'unsafe-inline' is live, contained by the opaque-origin sandbox");
  } else if (!flags.inlineAllowed) {
    parts.push(
      flags.evalAllowed
        ? "script-src 'unsafe-eval' is permitted"
        : 'script-src has no unneutralised inline/eval escape',
    );
  }
  if (flags.frameAncestors.length > 0) {
    parts.push(`frame-ancestors ${flags.frameAncestors.join(' ')}`);
  } else if (kind !== 'SANDBOXED_WIDGET') {
    parts.push('no frame-ancestors declared');
  }
  if (flags.sandbox.length > 0) {
    parts.push(`sandbox ${flags.sandbox.join(' ')}`);
  }
  for (const observation of flags.observations) {
    parts.push(observation);
  }
  return parts.join('; ');
}

function buildNotes(
  policy: CspPolicy,
  kind: SurfaceKind,
  flags: {
    weaknesses: readonly string[];
    observations: readonly string[];
    inlineAllowed: boolean;
    inlineContainedBySandbox: boolean;
    hasNonce: boolean;
    hasStrictDynamic: boolean;
    opaqueOrigin: boolean;
    framableByDesign: boolean;
    frameAncestors: readonly string[];
  },
): readonly string[] {
  const notes: string[] = [];
  if (flags.framableByDesign) {
    notes.push(
      `frame-ancestors * on ${policy.source} is a deliberate product decision: this surface exists to be embedded by third-party sites. It is not treated as a defect. The compensating controls that do matter are object-src, form-action and a script-src without inline/eval, and those are what this test evaluates.`,
    );
  }
  if (kind === 'SANDBOXED_WIDGET' && flags.opaqueOrigin && flags.inlineContainedBySandbox) {
    notes.push(
      'sandbox without allow-same-origin puts the document in an opaque origin, which is what makes the inline-script allowance acceptable here: the script cannot reach the embedding origin\'s storage or cookies. The inline allowance is therefore recorded as a fact, not as a weakness.',
    );
  }
  if (kind === 'OAUTH_CALLBACK' && flags.inlineAllowed) {
    notes.push(
      "This surface returns HTML from an API route and runs script-src 'unsafe-inline' with no nonce. That is only safe while the response body is entirely server-generated. The engine did not establish that the callback parameters cannot be reflected into the document, so this is recorded as a weak control, not as a confirmed injection.",
    );
  }
  if (flags.hasStrictDynamic) {
    notes.push(
      "'strict-dynamic' lets the engine trust nonce- and hash-bearing script elements over host allowlists, so 'self' in script-src is not the load-bearing part of this policy.",
    );
  }
  if (flags.hasNonce && !flags.hasStrictDynamic) {
    notes.push('A nonce is present without strict-dynamic, so script-src host allowlists still apply.');
  }
  for (const observation of flags.observations) {
    notes.push(`Recorded without penalty: ${observation}.`);
  }
  for (const weakness of flags.weaknesses) {
    notes.push(`Weakness recorded: ${weakness}.`);
  }
  if (notes.length === 0) {
    notes.push(`The ${describeKind(kind)} policy matched the expectations for this surface type.`);
  }
  return notes;
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64);
}
