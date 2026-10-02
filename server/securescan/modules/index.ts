/**
 * WM SecureScan — module registry.
 *
 * Registration is explicit and ordered rather than discovered by directory
 * scanning, for two reasons:
 *
 *  - The order modules run in is part of the report's meaning. Static modules
 *    that establish the architecture and attack surface run first so later
 *    modules can attribute findings to real components instead of guessing.
 *  - A registry is greppable. "Which modules assert anything about CSP?" should
 *    be answerable by reading one file, not by inferring it from the filesystem.
 *
 * Every module is `NONE`-capability by default; anything that needs to send a
 * request must say so in its own declaration so the orchestrator can refuse to
 * grant more than the assessment's scope allows.
 */

import type { SecurityModule } from '../repo';
import { corsModule } from './cors';
import { securityHeadersModule } from './security-headers';

export interface RegisteredModule {
  readonly module: SecurityModule;
  /** Lower runs first. Ties broken by registration order. */
  readonly order: number;
}

/**
 * The shipped module set. Kept small and honest: a module exists because there
 * is a control worth checking, not because the category list has a gap in it.
 */
export const BUILT_IN_MODULES: readonly SecurityModule[] = [
  securityHeadersModule,
  corsModule,
];

export const MODULE_RUN_ORDER: readonly string[] = [
  // Reserved for the discovery modules that run before any control module:
  // 'architecture', 'attack-surface'. They are engine phases, not modules, but
  // they are listed here so a report reader can see the full phase sequence.
  'security-headers',
  'cors',
];

export function moduleByName(name: string, modules: readonly SecurityModule[] = BUILT_IN_MODULES): SecurityModule | null {
  return modules.find((candidate) => candidate.name === name) ?? null;
}

/** Resolve the run list, preserving the declared order and rejecting unknown names. */
export function resolveModules(
  requested: readonly string[],
  available: readonly SecurityModule[] = BUILT_IN_MODULES,
): { readonly resolved: readonly SecurityModule[]; readonly unknown: readonly string[] } {
  const unknown: string[] = [];
  const resolved: SecurityModule[] = [];
  for (const name of requested) {
    const found = available.find((candidate) => candidate.name === name);
    if (found) resolved.push(found);
    else unknown.push(name);
  }
  return { resolved, unknown };
}
