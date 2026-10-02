/**
 * WM SecureScan — architecture detection.
 *
 * The engine refuses to assume the target is a World Monitor deployment. Every
 * node is *probed* in the snapshot against marker paths that would have to
 * exist for the component to be real, and the result is recorded either way.
 *
 * This matters more than it looks. A scanner pointed at something that is not
 * World Monitor would otherwise report "CORS allowlist present, rate-limit
 * registry present, SSRF guard present" for a codebase that happens to contain
 * similarly-named files, or worse, report PASS on controls it never found. By
 * deriving presence from content, an absent component becomes `present: false`
 * and the coverage view can say NOT TESTED rather than PASS.
 */

import type { SourceReader } from './repo';
import type { RepoView } from './repo';
import type {
  ArchitectureEdge,
  ArchitectureNode,
  ArchitectureNodeId,
  TrustBoundary,
  TrustBoundaryId,
} from './types';

interface NodeDefinition {
  readonly id: ArchitectureNodeId;
  readonly kind: import('./types').ArchitectureNodeKind;
  readonly label: string;
  /**
   * `path` exists, or `content` contains the pattern. Both are required unless
   * a definition only lists `paths`.
   */
  readonly markers: readonly { readonly path: string; readonly contains?: string }[];
  /** Human-readable reason a component is missing, when it is. */
  readonly absenceNote: string;
}

const NODES: readonly NodeDefinition[] = [
  {
    id: 'browser-spa',
    kind: 'CLIENT',
    label: 'Browser SPA',
    markers: [
      { path: 'index.html', contains: '/src/main.ts' },
      { path: 'src/main.ts', contains: '@/services' },
    ],
    absenceNote: 'No Vite HTML entry bootstrapping src/main.ts. Not a World Monitor browser build.',
  },
  {
    id: 'vercel-edge',
    kind: 'EDGE',
    label: 'Vercel Edge Functions',
    markers: [{ path: 'middleware.ts' }, { path: 'vercel.json' }],
    absenceNote: 'No middleware.ts or vercel.json. Edge request pipeline is not present.',
  },
  {
    id: 'edge-gateway',
    kind: 'EDGE',
    label: 'Sebuf RPC Gateway',
    markers: [{ path: 'server/gateway.ts', contains: 'createDomainGateway' }],
    absenceNote: 'No server/gateway.ts. Sebuf RPC dispatch and its auth/entitlement chain are not present.',
  },
  {
    id: 'sebuf-handlers',
    kind: 'SERVERLESS',
    label: 'Sebuf Handlers',
    markers: [
      { path: 'server/worldmonitor/market/v1/handler.ts' },
      { path: 'proto/worldmonitor/market/v1/list_market_quotes.proto' },
    ],
    absenceNote: 'No server/worldmonitor/** handlers or proto/worldmonitor/** contracts.',
  },
  {
    id: 'legacy-api-js',
    kind: 'SERVERLESS',
    label: 'Legacy api/*.js Handlers',
    markers: [{ path: 'api/_cors.js' }, { path: 'api/rss-proxy.js' }],
    absenceNote: 'No api/_cors.js. The self-contained JavaScript edge handler tier is not present.',
  },
  {
    id: 'upstash-redis',
    kind: 'CACHE',
    label: 'Upstash Redis Cache',
    markers: [{ path: 'server/_shared/redis.ts' }, { path: 'api/_redis-key-ownership.js' }],
    absenceNote: 'No shared Redis helpers. Cache-isolation controls cannot be assessed.',
  },
  {
    id: 'convex',
    kind: 'DATABASE',
    label: 'Convex',
    markers: [{ path: 'convex/schema.ts' }, { path: 'convex/auth.config.ts' }],
    absenceNote: 'No convex/schema.ts. No Convex-backed data store to assess.',
  },
  {
    id: 'railway-relay',
    kind: 'RELAY',
    label: 'Railway Relay',
    markers: [{ path: 'api/_relay.js', contains: 'getRelayBaseUrl' }, { path: 'scripts/ais-relay.cjs' }],
    absenceNote: 'No relay helper. Direct-fetch paths only.',
  },
  {
    id: 'external-providers',
    kind: 'EXTERNAL',
    label: 'External Data Providers',
    markers: [{ path: 'api/_rss-allowed-domains.js' }, { path: 'server/_shared/fetch-json.ts' }],
    absenceNote: 'No outbound-fetch helper or feed allowlist.',
  },
  {
    id: 'rss-content',
    kind: 'EXTERNAL',
    label: 'External RSS / News Content',
    markers: [{ path: 'api/rss-proxy.js' }, { path: 'src/components/NewsPanel.ts' }],
    absenceNote: 'No RSS ingestion or news rendering path.',
  },
  {
    id: 'mcp-interface',
    kind: 'EXTERNAL',
    label: 'MCP Interface',
    markers: [{ path: 'api/mcp/handler.ts' }, { path: 'mcp.json' }],
    absenceNote: 'No MCP handler or manifest.',
  },
  {
    id: 'oauth-server',
    kind: 'EDGE',
    label: 'OAuth 2.1 Authorization Server',
    markers: [{ path: 'api/oauth/authorize.js' }, { path: 'api/oauth/token.ts' }],
    absenceNote: 'No OAuth authorization server.',
  },
  {
    id: 'tauri-shell',
    kind: 'DESKTOP',
    label: 'Tauri Desktop Shell',
    markers: [{ path: 'src-tauri/tauri.conf.json' }, { path: 'src-tauri/src/main.rs' }],
    absenceNote: 'No Tauri desktop runtime.',
  },
  {
    id: 'sidecar',
    kind: 'DESKTOP',
    label: 'Node.js Local Sidecar',
    markers: [{ path: 'src-tauri/sidecar/local-api-server.mjs' }],
    absenceNote: 'No local sidecar.',
  },
  {
    id: 'build-toolchain',
    kind: 'BUILD',
    label: 'Build Toolchain',
    markers: [{ path: 'package.json' }, { path: 'package-lock.json' }],
    absenceNote: 'No npm manifest or lockfile. Dependency assessment is not possible.',
  },
];

const EDGES: readonly ArchitectureEdge[] = [
  { from: 'browser-spa', to: 'vercel-edge', kind: 'FETCHES', label: 'Browser issues same-origin /api/* requests' },
  { from: 'vercel-edge', to: 'edge-gateway', kind: 'PROXIES', label: 'middleware.ts gates and rewrites /api/*' },
  { from: 'edge-gateway', to: 'sebuf-handlers', kind: 'CALLS', label: 'createDomainGateway dispatches Sebuf RPCs' },
  { from: 'edge-gateway', to: 'upstash-redis', kind: 'CACHES', label: 'Cached data and seed metadata' },
  { from: 'sebuf-handlers', to: 'upstash-redis', kind: 'STORES', label: 'Handler-level cache reads and writes' },
  { from: 'sebuf-handlers', to: 'external-providers', kind: 'FETCHES', label: 'Upstream provider calls (Finnhub, Yahoo, EIA, …)' },
  { from: 'sebuf-handlers', to: 'railway-relay', kind: 'PROXIES', label: 'Relay fallback for blocked upstream hosts' },
  { from: 'legacy-api-js', to: 'upstash-redis', kind: 'CACHES', label: 'Legacy registry and bootstrap reads' },
  { from: 'legacy-api-js', to: 'external-providers', kind: 'FETCHES', label: 'RSS proxy allowlisted feed fetches' },
  { from: 'rss-content', to: 'browser-spa', kind: 'RENDERS', label: 'Untrusted feed text rendered in the news panel' },
  { from: 'browser-spa', to: 'convex', kind: 'AUTHENTICATES', label: 'Clerk JWT-backed Convex client' },
  { from: 'convex', to: 'upstash-redis', kind: 'STORES', label: 'Convex internal data store' },
  { from: 'mcp-interface', to: 'edge-gateway', kind: 'CALLS', label: 'MCP tool dispatch reaches Sebuf RPCs' },
  { from: 'mcp-interface', to: 'upstash-redis', kind: 'CACHES', label: 'MCP quota and daily-usage counters' },
  { from: 'oauth-server', to: 'edge-gateway', kind: 'AUTHORIZES', label: 'Issued access tokens validated at the gateway' },
  { from: 'oauth-server', to: 'mcp-interface', kind: 'AUTHENTICATES', label: 'Pro token grants the MCP Pro surface' },
  { from: 'tauri-shell', to: 'browser-spa', kind: 'RENDERS', label: 'Desktop webview loads the dashboard bundle' },
  { from: 'tauri-shell', to: 'sidecar', kind: 'PROXIES', label: 'IPC proxy injects LOCAL_API_TOKEN per request' },
  { from: 'sidecar', to: 'upstash-redis', kind: 'STORES', label: 'Desktop cache layer' },
  { from: 'sidecar', to: 'external-providers', kind: 'FETCHES', label: 'Sidecar provider calls with private-range blocking' },
  { from: 'browser-spa', to: 'build-toolchain', kind: 'TRUSTS', label: 'Bundle integrity depends on the dependency tree' },
];

/**
 * The eight trust boundaries WM SecureScan reasons about.
 *
 * `expectedControl` names the *World Monitor* control that is supposed to make
 * the crossing safe, taken from the documented architecture rather than from
 * a generic checklist. A boundary whose expected control is not present in the
 * snapshot is reported by the trust-boundary modules as WEAK or ABSENT.
 */
const BOUNDARIES: readonly TrustBoundary[] = [
  {
    id: 'TB-1-BROWSER-EDGE',
    from: 'browser-spa',
    to: 'vercel-edge',
    label: 'Browser to Vercel Edge',
    untrustedInput: 'Origin header, cookies, query parameters, request body, User-Agent',
    expectedControl: 'ALLOWED_ORIGIN_PATTERNS CORS reflection with Vary: Origin, plus session cookie attributes',
  },
  {
    id: 'TB-2-EDGE-UPSTREAM',
    from: 'edge-gateway',
    to: 'external-providers',
    label: 'Edge to Upstream APIs',
    untrustedInput: 'Feed URLs, webhook registration URLs, MCP serverUrl, provider-supplied redirect targets',
    expectedControl: 'Domain allowlist plus private/reserved address rejection re-checked on every redirect hop',
  },
  {
    id: 'TB-3-DESKTOP-TAURI',
    from: 'browser-spa',
    to: 'tauri-shell',
    label: 'Desktop Renderer to Tauri IPC',
    untrustedInput: 'Window label, command name, sidecar request path, cache key',
    expectedControl: 'require_trusted_window / require_secret_management_window plus the local-API proxy path allowlist',
  },
  {
    id: 'TB-4-TAURI-SIDECAR',
    from: 'tauri-shell',
    to: 'sidecar',
    label: 'Tauri Shell to Node Sidecar',
    untrustedInput: 'Any local process able to reach 127.0.0.1:46123',
    expectedControl: 'Per-launch CSPRNG LOCAL_API_TOKEN with default-deny gate and stripped transport header',
  },
  {
    id: 'TB-5-APP-REDIS',
    from: 'edge-gateway',
    to: 'upstash-redis',
    label: 'Application to Redis',
    untrustedInput: 'Cache key components derived from request parameters, seeded payload contents',
    expectedControl: 'Request-varying cache keys, per-deployment key prefixing, and a shared-cache no-store floor',
  },
  {
    id: 'TB-6-APP-CONVEX',
    from: 'browser-spa',
    to: 'convex',
    label: 'Application to Convex',
    untrustedInput: 'Query/mutation arguments, including anything user-scoped',
    expectedControl: 'ctx.auth.getUserIdentity() derived ownership; client-supplied identity never trusted',
  },
  {
    id: 'TB-7-APP-EXTERNAL-CONTENT',
    from: 'rss-content',
    to: 'browser-spa',
    label: 'External Content to Application',
    untrustedInput: 'Feed titles, snippets, links, enclosure URLs, HTML fragments',
    expectedControl: 'Text-only handling with escapeHtml/sanitizeUrl, plus DOMPurify for rendered markup',
  },
  {
    id: 'TB-8-MCP-EXTERNAL-CLIENT',
    from: 'mcp-interface',
    to: 'mcp-interface',
    label: 'MCP to External Clients',
    untrustedInput: 'JSON-RPC method, tool name, tool arguments, OAuth client registration, bearer token',
    expectedControl: 'Bearer/API-key validation, per-plan burst and daily quota, PKCE S256, exact redirect-URI match',
  },
];

export interface DetectedArchitecture {
  readonly nodes: readonly ArchitectureNode[];
  readonly edges: readonly ArchitectureEdge[];
  readonly boundaries: readonly TrustBoundary[];
  readonly presentNodeIds: ReadonlySet<ArchitectureNodeId>;
}

function markerSatisfied(repo: RepoView, marker: { path: string; contains?: string }): boolean {
  if (marker.contains === undefined) return repo.exists(marker.path);
  const content = repo.read(marker.path);
  if (content === null) return false;
  return content.includes(marker.contains);
}

export function detectArchitecture(repo: RepoView): DetectedArchitecture {
  const nodes: ArchitectureNode[] = [];
  const presentNodeIds = new Set<ArchitectureNodeId>();

  for (const definition of NODES) {
    const satisfied = definition.markers.filter((marker) => markerSatisfied(repo, marker));
    const present = satisfied.length > 0;
    if (present) presentNodeIds.add(definition.id);
    nodes.push({
      id: definition.id,
      kind: definition.kind,
      label: definition.label,
      evidence: satisfied.map((marker) => marker.path),
      present,
    });
  }

  // Edges and boundaries are only surfaced when both endpoints exist. An edge
  // to a component that is not deployed describes nothing, and listing it would
  // imply a crossing the assessment never examined.
  const edges = EDGES.filter((edge) => presentNodeIds.has(edge.from) && presentNodeIds.has(edge.to));
  const boundaries = BOUNDARIES.filter(
    (boundary) => presentNodeIds.has(boundary.from) && presentNodeIds.has(boundary.to),
  );

  return { nodes, edges, boundaries, presentNodeIds };
}

export function boundaryById(
  architecture: DetectedArchitecture,
  id: TrustBoundaryId,
): TrustBoundary | null {
  return architecture.boundaries.find((boundary) => boundary.id === id) ?? null;
}

export function nodeLabel(architecture: DetectedArchitecture, id: ArchitectureNodeId): string {
  return architecture.nodes.find((node) => node.id === id)?.label ?? id;
}

/** Reasons components are absent, for the assessment's "Not Tested" section. */
export function absentNodes(architecture: DetectedArchitecture): readonly { readonly id: string; readonly reason: string }[] {
  return NODES.filter((definition) => !architecture.presentNodeIds.has(definition.id)).map((definition) => ({
    id: definition.id,
    reason: definition.absenceNote,
  }));
}

export type { SourceReader };
