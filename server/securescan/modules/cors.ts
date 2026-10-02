/**
 * WM SecureScan — CORS module (TB-1, Browser to Edge).
 *
 * World Monitor runs two deliberately different CORS postures and this module
 * exists mainly to tell them apart:
 *
 *  - `api/_cors.js` has `getPublicCorsHeaders()` — `Access-Control-Allow-Origin: *`,
 *    no credentials, no `Vary`. The legacy handlers need it because a
 *    shared-cacheable response with origin-keyed ACAO fragments the cache and,
 *    worse, a wildcard with no `Vary` collapses every origin into one entry
 *    which can bypass origin checks on cache hits.
 *  - `server/cors.ts` reflects the caller's origin with `Vary: Origin` and
 *    credentials. The Sebuf gateway needs the reflecting form, and compensates
 *    by only issuing `CDN-Cache-Control` for allowlisted origins.
 *
 * The high-value check here is not "is there a wildcard" but "does a
 * shared-cacheable response use a posture that cannot leak between origins".
 */

import { Recorder, apiTop10, asvs, srcEvidence } from './_helpers';
import { readSource, type ModuleContext, type SecurityModule } from '../repo';

interface CorsApi {
  readonly exports: readonly string[];
  readonly hasPublicHelper: boolean;
  readonly hasCredentialedHelper: boolean;
  readonly reflectsOrigin: boolean;
  readonly allowedOriginPatterns: readonly string[];
  readonly devPatternsEnabled: boolean;
  readonly location: string;
}

function readOriginPatterns(content: string): readonly string[] {
  const patterns: string[] = [];
  const inBlock = /const\s+(?:ALLOWED_ORIGIN_PATTERNS|PRODUCTION_PATTERNS)\s*[:=]/.test(content);
  if (!inBlock) return patterns;
  for (const line of content.split(/\r?\n/)) {
    const match = /^\s*(\/\^.*\/[a-z]*),?\s*$/.exec(line);
    if (match?.[1]) {
      patterns.push(match[1]);
      continue;
    }
    // `APP_ORIGIN_PATTERN` is a named const pulled into the array.
    const named = /^\s*([A-Z_]+),\s*$/.exec(line);
    if (named?.[1]) patterns.push(named[1]);
  }
  return patterns;
}

function inspectCorsModule(path: string, content: string): CorsApi {
  return {
    exports: [...content.matchAll(/export\s+(?:async\s+)?(?:function|const)\s+(\w+)/g)]
      .map((match) => match[1] ?? '')
      .filter((name) => name !== ''),
    hasPublicHelper: /export function getPublicCorsHeaders/.test(content),
    hasCredentialedHelper: /Access-Control-Allow-Credentials/.test(content),
    reflectsOrigin: /'Access-Control-Allow-Origin':\s*allowOrigin/.test(content),
    allowedOriginPatterns: readOriginPatterns(content),
    devPatternsEnabled: /localhost|127\.0\.0\.1/.test(content) && /NODE_ENV\s*===\s*['"]production['"]/.test(content),
    location: path,
  };
}

export const corsModule: SecurityModule = {
  name: 'cors',
  label: 'CORS',
  category: 'CORS',
  boundary: 'TB-1-BROWSER-EDGE',
  requires: 'NONE',
  run(context: ModuleContext) {
    return (async () => {
      const recorder = new Recorder(context, 'cors', 'CORS', 'TB-1-BROWSER-EDGE');
      const jsReader = readSource(context.repo, 'api/_cors.js');
      const tsReader = readSource(context.repo, 'server/cors.ts');

      if (!jsReader && !tsReader) {
        await recorder.test({
          slug: 'cors-implementation-present',
          component: 'Vercel Edge',
          control: 'cors-allowlist',
          node: 'vercel-edge',
          target: 'api/_cors.js, server/cors.ts',
          expected: 'A CORS allowlist implementation exists',
          observed: 'Neither api/_cors.js nor server/cors.ts is present in the assessed snapshot',
          status: 'INCONCLUSIVE',
          confidence: 'LOW',
          notes: ['CORS could not be evaluated. This is not evidence that CORS is permissive.'],
        });
        return { ...recorder.output(), findings: [], coverageNotes: [] };
      }

      for (const reader of [jsReader, tsReader]) {
        if (!reader) continue;
        const api = inspectCorsModule(reader.path, reader.slice(1, reader.lineCount));

        await recorder.test({
          slug: `origin-allowlist-${reader.path.includes('_cors') ? 'legacy' : 'gateway'}`,
          component: reader.path === 'api/_cors.js' ? 'Legacy api/*.js Handlers' : 'Sebuf RPC Gateway',
          control: 'cors-origin-allowlist',
          node: reader.path === 'api/_cors.js' ? 'legacy-api-js' : 'edge-gateway',
          target: reader.path,
          expected: 'Origins are matched against an explicit pattern allowlist rather than reflected unconditionally',
          observed:
            api.allowedOriginPatterns.length > 0
              ? `${api.allowedOriginPatterns.length} allowlist pattern(s) declared; ACAO reflects only a matched origin (${api.reflectsOrigin ? 'reflection confirmed' : 'reflection not found'})`
              : 'No allowlist pattern block found in this module',
          status: api.allowedOriginPatterns.length > 0 && api.reflectsOrigin ? 'PASS' : 'FAIL',
          confidence: 'HIGH',
          notes: [
            `Exports: ${api.exports.join(', ') || 'none detected'}.`,
            api.allowedOriginPatterns.length > 0
              ? `Patterns: ${api.allowedOriginPatterns.join(' | ')}`
              : 'Pattern extraction found nothing; verify the module has not been refactored away from its documented shape.',
          ],
          evidence: [
            srcEvidence(
              reader.path,
              1,
              Math.min(reader.lineCount, 60),
              reader.slice(1, Math.min(reader.lineCount, 60)),
              'CORS allowlist and header construction as implemented.',
            ),
          ],
        });

        // A production allowlist that also matches localhost/127.0.0.1 without a
        // NODE_ENV guard would let any local page read authenticated responses.
        const loopbackUnguarded =
          /localhost|127\\?\.0\\?\.0\\?\.1/.test(reader.slice(1, reader.lineCount)) &&
          !/NODE_ENV/.test(reader.slice(1, reader.lineCount));
        await recorder.test({
          slug: `loopback-not-in-production-allowlist-${reader.path.includes('_cors') ? 'legacy' : 'gateway'}`,
          component: reader.path === 'api/_cors.js' ? 'Legacy api/*.js Handlers' : 'Sebuf RPC Gateway',
          control: 'cors-dev-origin-isolation',
          node: reader.path === 'api/_cors.js' ? 'legacy-api-js' : 'edge-gateway',
          target: reader.path,
          expected: 'Loopback and 127.0.0.1 origins are permitted only when NODE_ENV is not production',
          observed: api.devPatternsEnabled
            ? 'The allowlist is assembled conditionally on NODE_ENV, so loopback origins are excluded in production'
            : loopbackUnguarded
              ? 'Loopback origin patterns appear without a NODE_ENV guard in this module'
              : 'No loopback origin pattern found in this module',
          status: api.devPatternsEnabled || !loopbackUnguarded ? 'PASS' : 'FAIL',
          confidence: 'MEDIUM',
          notes: [
            'A local origin in a production allowlist lets any page served from localhost read credentialed API responses.',
          ],
          evidence: [
            srcEvidence(
              reader.path,
              1,
              Math.min(reader.lineCount, 45),
              reader.slice(1, Math.min(reader.lineCount, 45)),
              'Origin allowlist construction including any NODE_ENV conditional.',
            ),
          ],
        });

        if (api.hasCredentialedHelper) {
          await recorder.test({
            slug: `credentialed-response-vary-${reader.path.includes('_cors') ? 'legacy' : 'gateway'}`,
            component: reader.path === 'api/_cors.js' ? 'Legacy api/*.js Handlers' : 'Sebuf RPC Gateway',
            control: 'cors-credentialed-vary',
            node: reader.path === 'api/_cors.js' ? 'legacy-api-js' : 'edge-gateway',
            target: reader.path,
            expected: 'A credentialed (Access-Control-Allow-Credentials) response also emits Vary: Origin so a shared cache keys per origin',
            observed: /Vary['"]?\s*[:=]\s*['"]?Origin/.test(reader.slice(1, reader.lineCount))
              ? 'Vary: Origin is emitted alongside the credentialed header'
              : 'No Vary: Origin found next to the credentialed header',
            status: /Vary['"]?\s*[:=]\s*['"]?Origin/.test(reader.slice(1, reader.lineCount)) ? 'PASS' : 'FAIL',
            confidence: 'HIGH',
            notes: [
              'Without Vary: Origin a shared cache may store one origin\'s credentialed response and replay it to another, which is a cross-origin data leak rather than a CORS misconfiguration.',
            ],
            evidence: [
              srcEvidence(
                reader.path,
                1,
                Math.min(reader.lineCount, 200),
                reader.slice(1, Math.min(reader.lineCount, 200)),
                'CORS header construction for the reflecting/credentialed path.',
              ),
            ],
          });
        }
      }

      // The parity requirement between the two implementations is a real
      // control: divergence means one tier loses header access silently.
      if (jsReader && tsReader) {
        const jsHeaders = extractHeaderNames(jsReader.slice(1, jsReader.lineCount));
        const tsHeaders = extractHeaderNames(tsReader.slice(1, tsReader.lineCount));
        const jsOnly = [...jsHeaders].filter((name) => !tsHeaders.has(name));
        const tsOnly = [...tsHeaders].filter((name) => !jsHeaders.has(name));
        const divergent = jsOnly.length > 0 || tsOnly.length > 0;
        await recorder.test({
          slug: 'cors-header-parity-between-tiers',
          component: 'Vercel Edge',
          control: 'cors-header-parity',
          node: 'vercel-edge',
          target: 'api/_cors.js vs server/cors.ts',
          expected: 'Both CORS implementations declare the same Access-Control-* header names, so a cross-origin client does not lose header visibility in one tier',
          observed: divergent
            ? `Divergence: api/_cors.js only=${jsOnly.join(', ') || 'none'}; server/cors.ts only=${tsOnly.join(', ') || 'none'}`
            : `Both tiers declare the same ${jsHeaders.size} Access-Control-* header names`,
          status: divergent ? 'FAIL' : 'PASS',
          confidence: 'HIGH',
          notes: divergent
            ? ['Header-name divergence between the legacy and gateway CORS modules is a cross-origin client compatibility defect.']
            : ['Parity confirmed across both CORS implementations.'],
          evidence: [
            srcEvidence('api/_cors.js', 1, Math.min(jsReader.lineCount, 200), jsReader.slice(1, Math.min(jsReader.lineCount, 200)), 'Legacy CORS module.'),
            srcEvidence('server/cors.ts', 1, Math.min(tsReader.lineCount, 200), tsReader.slice(1, Math.min(tsReader.lineCount, 200)), 'Gateway CORS module.'),
          ],
        });

        await recorder.control({
          control: 'cors-header-parity',
          node: 'vercel-edge',
          label: 'CORS header parity across API tiers',
          status: divergent ? 'WEAK' : 'PRESENT',
          rationale: divergent ? 'Access-Control-* header names differ between api/_cors.js and server/cors.ts.' : 'Both CORS tiers declare identical Access-Control-* header names.',
          evidence: [srcEvidence('server/cors.ts', 1, 60, tsReader.slice(1, 60), 'Gateway CORS header declaration.')],
          mappings: [apiTop10('API8:2023 Security Misconfiguration')],
        });
      }

      // Shared-cache posture: a wildcard ACAO on a credentialed response is the
      // single highest-value CORS defect, so check for the combination directly.
      const wildcardWithCredentials = await findWildcardCredentialedCombination(context);
      await recorder.test({
        slug: 'no-wildcard-with-credentials',
        component: 'Vercel Edge',
        control: 'cors-wildcard-credentials',
        node: 'vercel-edge',
        target: 'every CORS response path in api/, server/ and src/',
        expected: 'No single response sets Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true',
        observed: wildcardWithCredentials.length === 0
          ? 'No single response path combines a wildcard ACAO with credentials; public and credentialed postures are separated'
          : wildcardWithCredentials
              .map((hit) => `${hit.path}:${hit.line} (${hit.where})`)
              .join(', '),
        status: wildcardWithCredentials.length === 0 ? 'PASS' : 'FAIL',
        confidence: wildcardWithCredentials.length === 0 ? 'MEDIUM' : 'HIGH',
        notes: wildcardWithCredentials.length === 0
          ? [
              'The public (wildcard) and credentialed (reflecting) postures are kept in separate response helpers, which is the correct shape: a wildcard ACAO with credentials is rejected by browsers, and keeping them together invites a bypass.',
              'Scored per response path, not per file, so a module holding both a public and a credentialed helper is not reported as a defect.',
              'Known gap: a response that spreads a shared constant holding the wildcard and adds credentials inline would not be detected, so this is a MEDIUM-confidence pass rather than a proof.',
            ]
          : ['A single response emits a wildcard ACAO together with credentials. Any bypass of that pairing is a cross-origin data leak.'],
        evidence: wildcardWithCredentials.length > 0
          ? wildcardWithCredentials.map((hit) =>
              srcEvidence(hit.path, hit.line, 1, hit.snippet, `Wildcard ACAO combined with credentials in ${hit.where} (${hit.path}:${hit.line}).`),
            )
          : [],
      });

      // Recorded per tier rather than once on `vercel-edge`, because the CORS
      // allowlist is implemented by each tier independently and a control
      // whose id does not match the tests that exercise it can never appear as
      // covered — the coverage view would report NOT_TESTED for a control that
      // was in fact tested twice.
      const tiers: readonly { node: 'legacy-api-js' | 'edge-gateway'; path: string }[] = [
        { node: 'legacy-api-js', path: 'api/_cors.js' },
        { node: 'edge-gateway', path: 'server/cors.ts' },
      ];
      for (const tier of tiers) {
        const reader = tier.path === 'api/_cors.js' ? jsReader : tsReader;
        await recorder.control({
          control: 'cors-origin-allowlist',
          node: tier.node,
          label: `CORS origin allowlist (${tier.path})`,
          status: reader ? 'PRESENT' : 'ABSENT',
          rationale: reader
            ? `An explicit origin allowlist is implemented in ${tier.path}; access is granted by pattern match and refusal echoes the raw Origin so the client can read the 403.`
            : `${tier.path} is not present in the assessed snapshot, so this tier's CORS posture could not be evaluated.`,
          evidence: reader ? [srcEvidence(tier.path, 1, 45, reader.slice(1, 45), 'CORS allowlist patterns.')] : [],
          mappings: [asvs('V14.4.1'), apiTop10('API8:2023')],
        });
      }

      await recorder.control({
        control: 'cors-wildcard-credentials',
        node: 'vercel-edge',
        label: 'No wildcard ACAO on credentialed responses',
        status: wildcardWithCredentials.length === 0 ? 'PRESENT' : 'WEAK',
        rationale:
          wildcardWithCredentials.length === 0
            ? 'No single response path combines a wildcard Access-Control-Allow-Origin with Access-Control-Allow-Credentials; the public and credentialed postures are separate helpers.'
            : `${wildcardWithCredentials.length} response path(s) combine a wildcard ACAO with credentials: ${wildcardWithCredentials.map((hit) => `${hit.path}:${hit.line} (${hit.where})`).join(', ')}.`,
        evidence: wildcardWithCredentials.length > 0
          ? wildcardWithCredentials.map((hit) =>
              srcEvidence(hit.path, hit.line, 1, hit.snippet, `Wildcard ACAO combined with credentials in ${hit.where} (${hit.path}:${hit.line}).`),
            )
          : [],
        mappings: [apiTop10('API5:2023 Broken Function Level Authorization')],
      });

      return { ...recorder.output(), findings: [], coverageNotes: [] };
    })();
  },
};

function extractHeaderNames(content: string): Set<string> {
  const names = new Set<string>();
  for (const match of content.matchAll(/['"]Access-Control-([A-Za-z-]+)['"]\s*:/g)) {
    const name = match[1];
    if (name) names.add(`Access-Control-${name}`);
  }
  return names;
}

/**
 * Split a source file into brace-balanced top-level blocks, skipping strings,
 * template literals and comments so a brace inside them cannot desynchronise
 * the scan.
 */
function topLevelBlocks(content: string): { start: number; text: string }[] {
  const blocks: { start: number; text: string }[] = [];
  let depth = 0;
  let start = -1;
  let i = 0;
  let state: 'code' | 'single' | 'double' | 'template' | 'line' | 'block' = 'code';

  while (i < content.length) {
    const char = content[i] as string;
    const next = content[i + 1];

    if (state === 'code') {
      if (char === '/' && next === '/') { state = 'line'; i += 2; continue; }
      if (char === '/' && next === '*') { state = 'block'; i += 2; continue; }
      if (char === "'") { state = 'single'; i += 1; continue; }
      if (char === '"') { state = 'double'; i += 1; continue; }
      if (char === '`') { state = 'template'; i += 1; continue; }
      if (char === '{') {
        if (depth === 0) start = i;
        depth += 1;
        i += 1;
        continue;
      }
      if (char === '}') {
        depth -= 1;
        if (depth === 0 && start >= 0) {
          blocks.push({ start, text: content.slice(start, i + 1) });
          start = -1;
        }
        i += 1;
        continue;
      }
      i += 1;
      continue;
    }

    if (state === 'line') {
      if (char === '\n') state = 'code';
      i += 1;
      continue;
    }
    if (state === 'block') {
      if (char === '*' && next === '/') { state = 'code'; i += 2; continue; }
      i += 1;
      continue;
    }
    if (char === '\\') { i += 2; continue; }
    if ((state === 'single' && char === "'") || (state === 'double' && char === '"') || (state === 'template' && char === '`')) {
      state = 'code';
    }
    i += 1;
  }

  return blocks;
}

function enclosingFunctionName(content: string, offset: number): string {
  const before = content.slice(0, offset);
  const matches = [...before.matchAll(/(?:function|const|let)\s+(\w+)\s*[({=]/g)];
  const last = matches.length > 0 ? matches[matches.length - 1] : undefined;
  return last?.[1] ?? 'module scope';
}

/**
 * Find response paths that emit a wildcard ACAO and credentials in the *same*
 * header object.
 *
 * The unit has to be a single response path, not a file. A module that keeps a
 * public wildcard helper beside a credentialed reflecting helper is the
 * recommended shape, and scoring it as a defect would report a non-existent
 * cross-origin data leak — the most damaging kind of false positive this tool
 * could produce. So each brace-balanced block is scored on its own.
 *
 * Known conservative gap: a response that spreads a shared header constant
 * holding the wildcard and then adds credentials inline would not be detected
 * here. That yields a clean result, so a later refactor could introduce this
 * without a failing test. Mitigated by recording the posture rather than only
 * the verdict.
 */
function findWildcardCredentialedPaths(content: string): { line: number; where: string; snippet: string }[] {
  const wildcard = /Access-Control-Allow-Origin['"]?\s*:\s*['"`]\*/i;
  const credentials = /Access-Control-Allow-Credentials['"]?\s*:\s*['"`]true/i;
  const hits: { line: number; where: string; snippet: string }[] = [];
  for (const block of topLevelBlocks(content)) {
    if (!wildcard.test(block.text) || !credentials.test(block.text)) continue;
    hits.push({
      line: content.slice(0, block.start).split('\n').length,
      where: enclosingFunctionName(content, block.start),
      snippet: block.text.replace(/\s+/g, ' ').slice(0, 300),
    });
  }
  return hits;
}

async function findWildcardCredentialedCombination(context: ModuleContext): Promise<{ path: string; line: number; where: string; snippet: string }[]> {
  const found: { path: string; line: number; where: string; snippet: string }[] = [];
  const files = [
    ...context.repo.under('api'),
    ...context.repo.under('server'),
    ...context.repo.under('src'),
  ];
  for (const path of files) {
    if (/\.(test|spec)\./.test(path)) continue;
    const content = context.repo.read(path);
    if (content === null) continue;
    for (const hit of findWildcardCredentialedPaths(content)) {
      found.push({ path, ...hit });
    }
  }
  return found.sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line);
}

