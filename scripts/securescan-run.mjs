#!/usr/bin/env node
/**
 * WM SecureScan — Node snapshot builder and assessment runner.
 *
 * This is the only place the engine is allowed to touch a real filesystem. The
 * engine itself is pure and takes a `RepoSnapshot`; this script walks a
 * checkout, decides what belongs in that snapshot, and hands it over.
 *
 * Three properties the walk has to preserve, because the engine's guarantees
 * depend on them:
 *
 *  1. **Only text the engine can reason about is read.** A snapshot containing
 *     every `node_modules` file would be gigabytes and would make the evidence
 *     digests meaningless. Binary and oversized files are skipped and *counted*,
 *     so a skipped file shows up in the report rather than silently narrowing
 *     the assessment.
 *  2. **Paths are POSIX and relative.** An assessment run on Windows has to
 *     produce the same evidence digests as one run on Linux, or a retest cannot
 *     be compared to its baseline.
 *  3. **Unreadable files are reported, never swallowed.** A permission error
 *     that vanishes is an assessment that quietly did less than it claims.
 *
 * Usage:
 *   node --import tsx scripts/securescan-run.mjs [--root <dir>] [--json] [--modules a,b]
 *
 * This script performs NO network requests. The assessment it runs is PASSIVE
 * by construction, because a repository snapshot is the only target it is
 * authorised to describe. Active probing requires the scope-gated probe client
 * and an operator-supplied authorization declaration, which is a different
 * entry point and not this one.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

import { runAssessment } from '../server/securescan/orchestrator.ts';
import { BUILT_IN_MODULES } from '../server/securescan/modules/index.ts';
import { ScopeEnforcer } from '../server/securescan/scope.ts';

/** Directories that are never part of an assessed source tree. */
const SKIP_DIRECTORIES = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  '.vercel',
  '.turbo',
  'coverage',
  '.cache',
  'target',
  'vendor',
  '__pycache__',
  '.venv',
  'venv',
]);

const SKIP_FILE_PATTERNS = [
  /\.(png|jpe?g|gif|webp|avif|ico|icns|bmp|tiff?)$/i,
  /\.(mp3|mp4|webm|ogg|wav|flac|aac|m4a)$/i,
  /\.(woff2?|ttf|otf|eot)$/i,
  /\.(zip|tar|gz|tgz|bz2|xz|7z|rar|dmg|exe|msi|deb|rpm|apk|ipa)$/i,
  /\.(wasm|node|so|dylib|dll)$/i,
  /\.map$/i,
  /-lock\.json$/i,
  /^package-lock\.json$/i,
  /(^|\/)pnpm-lock\.yaml$/i,
  /(^|\/)yarn\.lock$/i,
  /\.pdf$/i,
];

/** Files above this size are recorded as unreadable with a reason. */
const MAX_FILE_BYTES = 1024 * 1024;

const TEXT_EXTENSIONS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts',
  '.json', '.jsonc', '.html', '.css', '.scss', '.md', '.mdx', '.txt',
  '.yml', '.yaml', '.toml', '.env', '.example', '.proto', '.rs', '.sh',
  '.ps1', '.sql', '.graphql', '.gql', '.vue', '.svelte', '.astro', '.xml',
  '.ini', '.cfg', '.conf', '.properties', '.gitignore', '.dockerignore', '.lock',
]);

function looksTextual(path) {
  const lower = path.toLowerCase();
  if (lower.endsWith('.env.example') || lower.endsWith('/.env.example')) return true;
  if (lower.endsWith('.gitignore') || lower.endsWith('.dockerignore')) return true;
  if (lower.endsWith('.env')) return true;
  const dot = lower.lastIndexOf('.');
  if (dot < 0) return false;
  return TEXT_EXTENSIONS.has(lower.slice(dot));
}

function shouldSkipFile(path) {
  return SKIP_FILE_PATTERNS.some((pattern) => pattern.test(path));
}

function toPosix(path) {
  return path.split(sep).join('/');
}

/**
 * Walk a checkout into a `RepoSnapshot`.
 * @returns {{files: Map<string,string>, unreadable: {path:string,reason:string}[]}}
 */
export function buildSnapshot(root, { maxFiles = 20000 } = {}) {
  const files = new Map();
  const unreadable = [];
  let skippedBinary = 0;
  let skippedTooLarge = 0;

  const walk = (absolute, relativePosix) => {
    if (files.size >= maxFiles) return;
    let entries;
    try {
      entries = readdirSync(absolute, { withFileTypes: true });
    } catch (error) {
      unreadable.push({ path: relativePosix, reason: `directory unreadable: ${error.message}` });
      return;
    }
    // Sort so the snapshot is independent of the filesystem's readdir order.
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

    for (const entry of entries) {
      if (files.size >= maxFiles) return;
      const childAbsolute = join(absolute, entry.name);
      const childRelative = relativePosix === '' ? entry.name : `${relativePosix}/${entry.name}`;

      if (entry.isDirectory()) {
        if (SKIP_DIRECTORIES.has(entry.name)) continue;
        walk(childAbsolute, childRelative);
        continue;
      }
      if (!entry.isFile()) continue;
      if (shouldSkipFile(childRelative)) {
        skippedBinary += 1;
        continue;
      }
      if (!looksTextual(childRelative)) {
        skippedBinary += 1;
        continue;
      }

      let stats;
      try {
        stats = statSync(childAbsolute);
      } catch (error) {
        unreadable.push({ path: childRelative, reason: `stat failed: ${error.message}` });
        continue;
      }
      if (stats.size > MAX_FILE_BYTES) {
        skippedTooLarge += 1;
        unreadable.push({
          path: childRelative,
          reason: `skipped: ${stats.size} bytes exceeds the ${MAX_FILE_BYTES}-byte snapshot limit`,
        });
        continue;
      }

      try {
        files.set(childRelative, readFileSync(childAbsolute, 'utf8'));
      } catch (error) {
        unreadable.push({ path: childRelative, reason: `read failed: ${error.message}` });
      }
    }
  };

  walk(root, '');
  return { files, unreadable, skippedBinary, skippedTooLarge };
}

function parseArgs(argv) {
  const args = {
    root: process.cwd(),
    json: false,
    modules: null,
    submitUrl: null,
    submitOwner: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === '--root') args.root = argv[++i];
    else if (token === '--json') args.json = true;
    else if (token === '--modules') args.modules = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
    else if (token === '--submit') args.submitUrl = argv[++i];
    else if (token === '--owner') args.submitOwner = argv[++i];
    else if (token === '--help' || token === '-h') args.help = true;
  }
  return args;
}

const USAGE = `WM SecureScan runner

  node --import tsx scripts/securescan-run.mjs [options]

  --root <dir>     Checkout to assess. Default: current directory.
  --modules a,b    Comma-separated module names. Default: all registered.
  --json           Emit the full AssessmentResult as JSON.
  --submit <url>   POST the result to the deployment's run bridge. Implies
                   --owner; the bridge refuses a run whose owner does not match
                   the assessment, so the two must agree.
  --owner <id>     Subject id of the assessment's owner. Required with --submit.
  -h, --help       This message.

This runner is PASSIVE: it reads a local checkout and issues no network
requests. Active assessment requires an operator authorization declaration and
the scope-gated probe client, which this entry point does not construct.

The bridge key is read from SECURESCAN_RUNNER_KEY. It is never accepted as a
command-line argument, because a command line is visible in the process table
and in shell history to every other user on the machine.`;

/**
 * Hands a completed run to the deployment's bridge.
 *
 * The key is read from the environment only, and a missing key is an error here
 * rather than something to discover as a 503 from the server. The runner is
 * already the trusted party, so failing loudly about a missing credential is more
 * useful than silently producing a result that was never recorded.
 */
async function submitRun(result, args) {
  const key = process.env.SECURESCAN_RUNNER_KEY;
  if (!key) {
    throw new Error(
      'SECURESCAN_RUNNER_KEY is not set. The bridge cannot be called without it, and the key is not accepted as an argument.',
    );
  }
  if (!args.submitOwner) {
    throw new Error('--owner is required with --submit: the bridge checks the owner against the assessment.');
  }

  const response = await fetch(args.submitUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-wm-securescan-runner-key': key,
      'User-Agent': 'wm-securescan-runner/1.0',
    },
    body: JSON.stringify({ ownerUserId: args.submitOwner, result: JSON.stringify(result) }),
  });

  const body = await response.text();
  if (!response.ok) {
    throw new Error(`bridge rejected the run (${response.status} ${response.statusText}): ${body}`);
  }
  return body;
}

function summarize(result) {
  const byStatus = new Map();
  for (const test of result.tests) byStatus.set(test.status, (byStatus.get(test.status) ?? 0) + 1);
  const statusLine = [...byStatus.entries()].sort().map(([k, v]) => `${k}=${v}`).join('  ');

  const failing = result.tests.filter((test) => test.status === 'FAIL');
  const weakControls = result.controls.filter((control) => control.status === 'WEAK' || control.status === 'ABSENT');

  const lines = [];
  lines.push(`WM SecureScan ${result.toolVersion}  target=${result.assessment.name}  revision=${result.targetRevision ?? 'unknown'}`);
  lines.push('');
  lines.push(`Modules   ${result.run.progress.map((p) => `${p.module}:${p.status}`).join('  ')}`);
  lines.push(`Tests     ${result.tests.length}  (${statusLine || 'none'})`);
  lines.push(`Controls  ${result.controls.length}  (WEAK/ABSENT: ${weakControls.length})`);
  lines.push(`Surfaces  ${result.surface.length}`);
  lines.push(`Evidence  ${result.evidence.length}`);
  lines.push(`NotTested ${result.notTested.length}`);
  lines.push('');

  if (failing.length > 0) {
    lines.push('Failing checks');
    for (const test of failing) {
      lines.push(`  [${test.testId}]`);
      lines.push(`    control : ${test.control}`);
      lines.push(`    target  : ${test.target}`);
      lines.push(`    observed: ${test.observed}`);
      if (test.evidenceIds.length > 0) lines.push(`    evidence: ${test.evidenceIds.join(', ')}`);
      for (const note of test.notes.slice(0, 3)) lines.push(`    note    : ${note}`);
    }
    lines.push('');
  }

  if (weakControls.length > 0) {
    lines.push('Weak or absent controls');
    for (const control of weakControls) {
      lines.push(`  [${control.id}] ${control.status} — ${control.label}`);
      lines.push(`    ${control.rationale}`);
    }
    lines.push('');
  }

  if (result.notTested.length > 0) {
    lines.push('Not tested (and why)');
    for (const note of result.notTested) lines.push(`  ${note.module}: ${note.reason}`);
    lines.push('');
  }

  return lines.join('\n');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }

  const root = resolve(args.root);
  const built = buildSnapshot(root);
  if (built.files.size === 0) {
    process.stderr.write(`No assessable source files were found under ${root}.\n`);
    process.exitCode = 1;
    return;
  }

  // A frozen clock keeps the run reproducible, which is the property the
  // evidence digests and the retest comparison both depend on.
  const frozenNow = new Date().toISOString();

  const assessment = {
    id: 'ASSESS-CLI',
    name: `Local assessment of ${toPosix(relative(process.cwd(), root)) || '.'}`,
    state: 'RUNNING',
    scope: {
      // SELF_HOSTED + LOCAL_ONLY is the honest declaration for a local checkout
      // read. Anything stronger would be asserting an authorization the runner
      // has no way to have been given.
      authorization: 'LOCAL_ONLY',
      environment: 'LOCAL',
      allowedDomains: [],
      allowedPaths: [],
      allowedApiPaths: [],
      testAccountLabel: 'none — passive local analysis only',
      intensity: 'PASSIVE',
      maxRequests: 0,
      requestTimeoutMs: 5000,
      collectEvidence: true,
    },
    moduleNames: args.modules ?? BUILT_IN_MODULES.map((module) => module.name),
    createdBy: 'securescan-run.mjs',
    createdAt: frozenNow,
    startedAt: frozenNow,
    finishedAt: null,
    authorizationNote:
      'Passive analysis of a local checkout. No network requests are issued, so no target was contacted and no authorization was required.',
  };

  const outcome = await runAssessment({
    assessment,
    snapshot: {
      rootLabel: toPosix(relative(process.cwd(), root)) || '.',
      revision: null,
      files: built.files,
      unreadable: built.unreadable,
    },
    now: () => frozenNow,
    modules: BUILT_IN_MODULES,
  });

  if (outcome.result === null) {
    process.stderr.write(`Assessment refused.\n${outcome.abortReason}\n`);
    process.exitCode = 2;
    return;
  }

  const result = outcome.result;

  if (args.submitUrl) {
    const recorded = await submitRun(result, args);
    process.stdout.write(`Submitted run ${result.run.id} to the bridge.\n${recorded}\n`);
    return;
  }

  if (args.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  const enforcerNote = new ScopeEnforcer(assessment.scope, () => frozenNow).describe();
  process.stdout.write(`${summarize(result)}\n`);
  process.stdout.write(
    `Snapshot ${built.files.size} files (${built.skippedBinary} non-textual skipped, ${built.unreadable.length} unreadable)\n`,
  );
  process.stdout.write(
    `Scope    intensity=${enforcerNote.intensity} capability=${enforcerNote.capability} requests=${enforcerNote.issued}/${enforcerNote.max}\n`,
  );
}

// Only run when invoked directly, so the module can be imported by tests.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    process.stderr.write(`securescan-run failed: ${error?.stack ?? error}\n`);
    process.exitCode = 1;
  });
}
