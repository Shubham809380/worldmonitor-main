/**
 * Focused follow-up: measure the Audit Center focus ring after *real* keyboard
 * interaction.
 *
 * The first drive called `element.focus()` programmatically and read
 * `outline-style: none`. That was a measurement artifact, not a defect:
 * Chromium only matches `:focus-visible` once the user has actually interacted
 * by keyboard, so a scripted `.focus()` right after `page.goto` correctly
 * yields no ring. The rule at `src/securescan/styles/base.css:116` declares
 * `outline: 2px solid var(--ss-border-focus)`.
 *
 * This step re-measures after a real Tab press, so the value reflects the
 * keyboard affordance a user would actually get, and additionally checks that
 * the ring is not invisible against its own backdrop.
 */
export default async function ({ page, base, shot, log }) {
  const SELECTOR = '.ss-nav__link[href="#/audit"]';

  const readFocus = () =>
    page.locator(SELECTOR).evaluate((el) => {
      const s = getComputedStyle(el);
      const rgb = (v) => {
        const m = /rgba?\(([^)]+)\)/.exec(v);
        return m ? m[1].split(',').slice(0, 3).map((n) => Number(n.trim())) : null;
      };
      const lum = (c) => {
        const [r, g, b] = c.map((n) => {
          const x = n / 255;
          return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4;
        });
        return 0.2126 * r + 0.7152 * g + 0.0722 * b;
      };
      const ratio = (a, b) => {
        const [l1, l2] = [lum(a), lum(b)].sort((x, y) => y - x);
        return Number(((l1 + 0.05) / (l2 + 0.05)).toFixed(2));
      };
      const ring = rgb(s.outlineColor);
      // Walk up for the first non-transparent painted background.
      let node = el;
      let bg = null;
      while (node && !bg) {
        const c = rgb(getComputedStyle(node).backgroundColor);
        if (c && (c[0] || c[1] || c[2])) bg = c;
        node = node.parentElement;
      }
      return {
        focusVisible: el.matches(':focus-visible'),
        outlineStyle: s.outlineStyle,
        outlineWidth: s.outlineWidth,
        outlineColor: s.outlineColor,
        outlineOffset: s.outlineOffset,
        ringVsBackdropContrast: ring && bg ? ratio(ring, bg) : null,
      };
    });

  await page.goto(`${base}/securescan#/dashboard`, { waitUntil: 'domcontentloaded' });
  await page.locator('#ss-view').waitFor({ state: 'visible' });

  // Programmatic focus: expected NOT to raise a ring (no keyboard interaction).
  await page.locator(SELECTOR).focus();
  const programmatic = await readFocus();
  log('after programmatic .focus():', JSON.stringify(programmatic));
  if (programmatic.focusVisible) {
    log('note: this build applies :focus-visible even to scripted focus');
  }

  // Real keyboard focus: this is the affordance that must be visible.
  await page.goto(`${base}/securescan#/dashboard`, { waitUntil: 'domcontentloaded' });
  await page.locator('#ss-view').waitFor({ state: 'visible' });

  let hops = 0;
  let landed = false;
  while (hops < 25) {
    await page.keyboard.press('Tab');
    hops += 1;
    landed = await page.evaluate((sel) => document.activeElement?.getAttribute('href') === '#/audit', SELECTOR);
    if (landed) break;
  }
  if (!landed) throw new Error(`Audit Center link not reachable in ${hops} tab stops`);

  const keyboard = await readFocus();
  log(`after real Tab (${hops} hops):`, JSON.stringify(keyboard));

  if (!keyboard.focusVisible) {
    throw new Error('reached the link by keyboard but :focus-visible never matched — no keyboard affordance');
  }
  if (keyboard.outlineStyle === 'none') {
    throw new Error('no focus ring is painted despite :focus-visible matching');
  }
  const width = parseFloat(keyboard.outlineWidth);
  if (!(width >= 2)) {
    throw new Error(`focus ring is only ${keyboard.outlineWidth} — below the 2px minimum`);
  }
  if (keyboard.ringVsBackdropContrast !== null && keyboard.ringVsBackdropContrast < 3) {
    throw new Error(
      `focus ring contrast ${keyboard.ringVsBackdropContrast}:1 against its backdrop — the ring is there but effectively invisible`,
    );
  }
  log('focus ring is visible, >=2px, and legible against its backdrop');

  // The ring must survive activation too.
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => window.location.hash === '#/audit');
  log('activated; still on #/audit');

  await shot('01-audit-center-focus-ring-visible');

  log('PASS: keyboard focus affordance on Audit Center is genuinely visible');
}
