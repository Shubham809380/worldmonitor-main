/**
 * SecureScan badge tones resolve to real CSS.
 *
 * The badge helpers interpolate a tone straight into a class name, so a tone with
 * no matching rule does not fail loudly - it silently falls back to `.ss-badge`'s
 * default fill. That is how the two axes this file is about collapsed into one:
 * a validation state ended up painted with the *severity* ramp's "none" fill,
 * which is the exact opposite of what `tokens.css` documents.
 *
 * So this is a contract test over the stylesheet: every tone a badge can emit must
 * have a rule, and every variable a state rule reads must be defined. Adding a
 * tone without styling it, or renaming a token, now fails here instead of
 * rendering as an unstyled pill.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

import { severityBadge, stateBadge, testStatusBadge, outcomeBadge, roleBadge } from '@/securescan/components/ui';
import type { SafeMarkup } from '@/securescan/components/dom';

const baseCss = readFileSync(resolve(process.cwd(), 'src/securescan/styles/base.css'), 'utf8');
const tokensCss = readFileSync(resolve(process.cwd(), 'src/securescan/styles/tokens.css'), 'utf8');

/** The rendered markup for a badge. `SafeMarkup` is already a verified string. */
function textOf(markup: SafeMarkup): string {
  return markup.value;
}

/** Every class name present in the stylesheet. */
function declaredClasses(): Set<string> {
  const found = new Set<string>();
  for (const match of baseCss.matchAll(/\.((?:ss|wg)-[A-Za-z0-9_-]+)/g)) found.add(match[1]!);
  return found;
}

/** Every custom property the stylesheet defines. */
function definedVariables(): Set<string> {
  const found = new Set<string>();
  for (const match of tokensCss.matchAll(/^\s*(--ss-[A-Za-z0-9-]+)\s*:/gm)) found.add(match[1]!);
  return found;
}

/**
 * The tone classes a rendered badge actually carries.
 *
 * Takes `SafeMarkup` rather than a string on purpose: a `SafeMarkup` instance
 * stringifies to `[object Object]`, so a signature that said `string` would let
 * the regex quietly match nothing and report every badge as unstyled.
 */
function toneClasses(markup: SafeMarkup | string): string[] {
  const source = typeof markup === 'string' ? markup : markup.value;
  const match = /class="([^"]*)"/.exec(source);
  if (!match) return [];
  return match[1]!.split(/\s+/).filter((c) => c.startsWith('ss-badge--'));
}

/** A validator must actually appear in an assessment result before a retest. */
const FINDING_STATES = [
  'CANDIDATE',
  'VALIDATING',
  'VALIDATED',
  'REMEDIATION',
  'RETEST_REQUIRED',
  'RETESTING',
  'VERIFIED',
  'FIXED',
  'REGRESSION',
  'INCONCLUSIVE',
  'CLOSED',
] as const;

/**
 * WCAG relative luminance and contrast, computed from the token values.
 *
 * The badge fills are translucent (`rgba(..., 0.13)`), so the readable backdrop is
 * the token fill composited over `--ss-bg`, not the fill on its own. Comparing a
 * light label against a saturated translucent colour as though it were opaque
 * reports a failure no reader would ever experience, and comparing against the page
 * background while ignoring the fill overstates it. Compositing is the only
 * reading that matches the pixels.
 */
function parseColour(value: string): { r: number; g: number; b: number; a: number } | null {
  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(value.trim());
  if (hex) {
    const h = hex[1]!.length === 3 ? hex[1]!.replace(/./g, (c) => c + c) : hex[1]!;
    return {
      r: parseInt(h.slice(0, 2), 16),
      g: parseInt(h.slice(2, 4), 16),
      b: parseInt(h.slice(4, 6), 16),
      a: 1,
    };
  }
  const rgb = /^rgba?\(([^)]+)\)$/i.exec(value.trim());
  if (!rgb) return null;
  const parts = rgb[1]!.split(/[\s,/]+/).filter(Boolean).map(Number);
  if (parts.length < 3 || parts.some((n) => Number.isNaN(n))) return null;
  return { r: parts[0]!, g: parts[1]!, b: parts[2]!, a: parts.length > 3 ? parts[3]! : 1 };
}

function tokenValue(name: string): string | null {
  const match = new RegExp(`^\\s*${name}\\s*:\\s*([^;]+);`, 'm').exec(tokensCss);
  return match ? match[1]!.trim() : null;
}

function relativeLuminance({ r, g, b }: { r: number; g: number; b: number }): number {
  const channel = (raw: number): number => {
    const s = raw / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrastRatio(foreground: string, background: string): number | null {
  const fg = parseColour(foreground);
  const bg = parseColour(background);
  if (!fg || !bg) return null;
  const page = parseColour(tokenValue('--ss-bg') ?? '') ?? { r: 255, g: 255, b: 255, a: 1 };
  // The label is opaque; the fill is composited over the page it sits on.
  const composited = {
    r: bg.r * bg.a + page.r * (1 - bg.a),
    g: bg.g * bg.a + page.g * (1 - bg.a),
    b: bg.b * bg.a + page.b * (1 - bg.a),
  };
  const a = relativeLuminance(fg);
  const b = relativeLuminance(composited);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

/** The `color` and `background` a tone rule resolves to, as token values. */
function resolvedTone(tone: string): { colour: string; background: string } | null {
  const rule = new RegExp(`\\.${tone}\\s*\\{([^}]*)\\}`).exec(baseCss);
  if (!rule) return null;
  const body = rule[1]!;
  const pick = (property: string): string | null => {
    // Anchored to a declaration boundary on purpose. A bare `color\s*:` also
    // matches the tail of `border-color:`, which would silently measure the border
    // token as the label colour and report a contrast failure that no reader has.
    const use = new RegExp(`(?:^|[;{])\\s*${property}\\s*:\\s*var\\((--ss-[A-Za-z0-9-]+)\\)`).exec(body);
    if (!use) return null;
    return tokenValue(use[1]!);
  };
  const colour = pick('color');
  const background = pick('background');
  return colour && background ? { colour, background } : null;
}

describe('SecureScan badge tones are styled', () => {
  const classes = declaredClasses();

  it('styles every validation-state tone a finding can reach', () => {
    const unstyled: string[] = [];
    for (const state of FINDING_STATES) {
      const tones = toneClasses(stateBadge(state));
      // A state badge may carry no tone at all only if that is deliberate; every
      // state here is expected to resolve to exactly one.
      expect(tones.length, `${state} should carry a tone`).toBeGreaterThan(0);
      for (const tone of tones) {
        if (!classes.has(tone)) unstyled.push(`${state} -> ${tone}`);
      }
    }
    expect(unstyled, `unstyled state tones: ${unstyled.join(', ')}`).toEqual([]);
  });

  it('keeps the validation axis separate from the severity axis', () => {
    // `tokens.css` states the two axes must never be collapsed. A state badge that
    // reads a `--ss-sev-*` fill is the collapse, whatever its colour.
    //
    // The tone list is derived from what `stateBadge` actually emits rather than
    // written out here. A hardcoded list would only check the tones someone
    // remembered to add, which is how `validated` and `verified` went unchecked
    // while they were borrowing another axis's class.
    const stateTones = new Set<string>();
    for (const state of FINDING_STATES) {
      for (const tone of toneClasses(stateBadge(state))) stateTones.add(tone);
    }
    expect(stateTones.size, 'expected several distinct state tones').toBeGreaterThan(3);

    const escaped: string[] = [];
    for (const tone of stateTones) {
      const rule = new RegExp(`\\.${tone}\\s*\\{([^}]*)\\}`);
      const body = rule.exec(baseCss)?.[1] ?? '';
      if (body === '') {
        escaped.push(`${tone} has no rule`);
        continue;
      }
      if (/var\(--ss-sev-/.test(body)) escaped.push(`${tone} reads a severity token`);
    }
    expect(escaped, `collapsed onto the severity axis: ${escaped.join(', ')}`).toEqual([]);
  });

  it('never paints a lifecycle state with the test-status green', () => {
    // `testStatusBadge` owns `.ss-badge--good` for PASS. VALIDATED and VERIFIED
    // used to resolve to that same class, so "an analyst judged this real" and
    // "a test passed" rendered identically. Same collapse as the severity axis,
    // one step along, so it gets its own guard.
    const borrowed = FINDING_STATES.filter((state) =>
      toneClasses(stateBadge(state)).includes('ss-badge--good'),
    );
    expect(borrowed, `states borrowing the test-status tone: ${borrowed.join(', ')}`).toEqual([]);

    // And the converse: a PASS test result must still spend the green accent, or
    // the separation above would have been achieved by removing green.
    expect(toneClasses(testStatusBadge('PASS'))).toContain('ss-badge--good');
  });

  it('keeps every badge label readable against the fill it is painted on', () => {
    // 4.5:1 is the WCAG AA threshold for text this size, and a lifecycle badge is
    // 11px semibold, so it is small text by the letter of the standard. A state
    // tone that resolves to a real hue but an unreadable pairing still renders as
    // a pill, so nothing else in this file would notice.
    const unreadable: string[] = [];
    const unresolved: string[] = [];
    const tones = new Set<string>();
    for (const state of FINDING_STATES) {
      for (const tone of toneClasses(stateBadge(state))) tones.add(tone);
    }
    for (const severity of ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const) {
      for (const tone of toneClasses(severityBadge(severity))) tones.add(tone);
    }
    for (const tone of tones) {
      const resolved = resolvedTone(tone);
      if (!resolved) {
        unresolved.push(tone);
        continue;
      }
      const ratio = contrastRatio(resolved.colour, resolved.background);
      if (ratio === null) {
        unresolved.push(tone);
      } else if (ratio < 4.5) {
        unreadable.push(`${tone} at ${ratio.toFixed(2)}:1 (${resolved.colour} on ${resolved.background})`);
      }
    }
    expect(unresolved, `tones with no resolvable colour pair: ${unresolved.join(', ')}`).toEqual([]);
    expect(unreadable, `tones below 4.5:1: ${unreadable.join('; ')}`).toEqual([]);
  });

  it('separates judged from confirmed', () => {
    // VALIDATED is an analyst's judgement; VERIFIED is an outcome the engine
    // reached by running a retest. Sharing one hue would make the two read as
    // the same kind of fact.
    const validated = toneClasses(stateBadge('VALIDATED'));
    const verified = toneClasses(stateBadge('VERIFIED'));
    expect(validated[0]).not.toBe(verified[0]);
    for (const tone of [...validated, ...verified]) {
      expect(classes.has(tone), `${tone} must have its own rule`).toBe(true);
    }
  });

  it('defines every variable a badge rule reads', () => {
    const defined = definedVariables();
    const badgeBlocks = [...baseCss.matchAll(/\.ss-badge[^{]*\{([^}]*)\}/g)];
    const missing: string[] = [];
    for (const match of badgeBlocks) {
      const body = match[1] ?? '';
      for (const use of body.matchAll(/var\((--ss-[A-Za-z0-9-]+)\)/g)) {
        if (!defined.has(use[1]!)) missing.push(use[1]!);
      }
    }
    expect([...new Set(missing)], 'badge rules referencing undefined tokens').toEqual([]);
  });

  it('styles every severity and status badge it can be asked for', () => {
    const unstyled: string[] = [];
    const renderers: Array<[string, () => string]> = [
      ['severity NONE', () => textOf(severityBadge('NONE'))],
      ['severity LOW', () => textOf(severityBadge('LOW'))],
      ['severity MEDIUM', () => textOf(severityBadge('MEDIUM'))],
      ['severity HIGH', () => textOf(severityBadge('HIGH'))],
      ['severity CRITICAL', () => textOf(severityBadge('CRITICAL'))],
      ['status PASS', () => textOf(testStatusBadge('PASS'))],
      ['status FAIL', () => textOf(testStatusBadge('FAIL'))],
      ['status INCONCLUSIVE', () => textOf(testStatusBadge('INCONCLUSIVE'))],
      ['status NOT_TESTED', () => textOf(testStatusBadge('NOT_TESTED'))],
      ['status SKIPPED_OUT_OF_SCOPE', () => textOf(testStatusBadge('SKIPPED_OUT_OF_SCOPE'))],
      ['outcome ALLOWED', () => textOf(outcomeBadge('ALLOWED'))],
      ['outcome DENIED', () => textOf(outcomeBadge('DENIED'))],
      ['role ADMIN', () => textOf(roleBadge('ADMIN'))],
      ['role SECURITY_ANALYST', () => textOf(roleBadge('SECURITY_ANALYST'))],
      ['role VIEWER', () => textOf(roleBadge('VIEWER'))],
      ['role SYSTEM', () => textOf(roleBadge('SYSTEM'))],
    ];
    for (const [label, render] of renderers) {
      for (const tone of toneClasses(render())) {
        if (!classes.has(tone)) unstyled.push(`${label} -> ${tone}`);
      }
    }
    expect(unstyled, `unstyled tones: ${unstyled.join(', ')}`).toEqual([]);
  });

  it('keeps the text label on every badge, so tone is never the only signal', () => {
    // The dot is a redundant cue; the label is the real one. Dropping it would make
    // a state unreadable in greyscale and would violate the module's own contract.
    const unlabelled: string[] = [];
    for (const state of FINDING_STATES) {
      const label = textOf(stateBadge(state)).replace(/<[^>]*>/g, '').trim();
      if (label === '') unlabelled.push(state);
    }
    expect(unlabelled, `states rendering no text label: ${unlabelled.join(', ')}`).toEqual([]);
  });
});
