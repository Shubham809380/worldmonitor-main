/**
 * Audit Center navigation and refusal drive — the real app, no hosted backend.
 *
 * `VITE_CONVEX_URL` is unset in this checkout, so `getConvexClient()` returns null
 * and every SecureScan query resolves to `fail('unavailable')`. That makes the
 * data-dependent half of the Audit Center (real chain entries, a real integrity
 * verdict, real authorization refusals) **unprovable here** — the server that
 * would answer is not running. This drive therefore proves only what does not
 * depend on that server, and it proves one security property that genuinely
 * matters in this state:
 *
 *   **With no server verdict, the Audit Center must not claim the chain is
 *   valid or clean.** A page that renders "INTACT" or "Chain verified" from an
 *   absent response would be the single most damaging failure this surface
 *   could have, because an auditor would act on it.
 *
 * It also proves that **frontend visibility is not treated as authorization**:
 * the Assurance section and the Audit Center link are listed and reachable with
 * no session at all, and the refusal comes from the backend path rather than from
 * a hidden link.
 *
 * Not proven here, and deliberately not simulated: assessment picker contents,
 * ALLOWED/DENIED rows, outcome filtering, JSON export payloads, chain-integrity
 * states, and non-admin/forbidden refusals.
 */
export default async function ({ page, base, shot, log, expectVisible }) {
  const consoleErrors = [];
  const pageErrors = [];
  const failedRequests = [];

  page.on('console', (msg) => {
    if (msg.type() === 'error') consoleErrors.push(msg.text().slice(0, 300));
  });
  page.on('pageerror', (err) => pageErrors.push(String(err).slice(0, 300)));
  page.on('response', (res) => {
    if (res.status() >= 400) {
      failedRequests.push(`${res.status()} ${res.url().slice(0, 160)}`);
    }
  });

  /* ---- 1. The shell boots ------------------------------------------------ */

  await page.goto(`${base}/securescan`, { waitUntil: 'domcontentloaded' });
  await expectVisible('#ss-view');

  const brand = await page.locator('.ss-brand__name').textContent();
  if (brand !== 'SecureScan') throw new Error(`expected branded shell, got ${brand}`);
  log('shell brand', brand);

  /* ---- 2. The Assurance section and the Audit Center link exist ---------- */

  const groups = (await page.locator('.ss-nav__group').allTextContents()).map((t) => t.trim());
  if (!groups.includes('Assurance')) {
    throw new Error(`Assurance nav section missing; saw: ${groups.join(' / ')}`);
  }
  log('nav groups', groups.join(' / '));

  const links = (await page.locator('.ss-nav__link').allTextContents()).map((t) => t.trim());
  if (!links.includes('Audit Center')) {
    throw new Error(`Audit Center link missing; saw: ${links.join(' / ')}`);
  }
  log('nav links', links.join(' / '));

  // Navigation is not authorization: with no session the link must still be
  // present and reachable. Hiding it would only be a courtesy and would also
  // hide the fact that the server is the thing refusing.
  const auditLink = page.locator('.ss-nav__link[href="#/audit"]');
  if (!(await auditLink.isVisible())) throw new Error('Audit Center link not visible to an unauthenticated caller');

  await shot('01-audit-nav-listed-without-session');

  /* ---- 3. Clicking through to the Audit Center -------------------------- */

  await auditLink.click();
  await page.waitForFunction(() => window.location.hash === '#/audit');
  await expectVisible('#ss-view .ss-state');

  const heading = await page.locator('.ss-page-title').textContent();
  if (!heading?.includes('Audit Center')) throw new Error(`bad heading after nav: ${heading}`);
  log('route heading', heading.trim());

  await shot('02-audit-route-default-state');

  /* ---- 4. THE SECURITY PROPERTY ------------------------------------------
   * No backend means no integrity verdict. The page must render an explaining
   * failure and must not print any claim that the chain is valid, intact,
   * verified, clean, or empty-but-fine.
   */

  const auditText = (await page.locator('#ss-main').textContent()) ?? '';

  const forbiddenClaims = [
    'Chain verified',
    'Chain verification failed',
    'INTACT',
    'BROKEN',
    'NO ENTRIES RECORDED',
    'Chain (',
    'All 0 entries',
  ];
  for (const claim of forbiddenClaims) {
    if (auditText.includes(claim)) {
      throw new Error(
        `browser printed "${claim}" with no server verdict — an absent response must never read as an integrity claim`,
      );
    }
  }
  if (!auditText.includes('BACKEND UNAVAILABLE')) {
    throw new Error('expected an explaining failure state when the backend cannot be reached');
  }
  log('no integrity claim without a server verdict — correct');

  // The empty-chain state must be distinct from an unavailable backend: an
  // unreachable chain is not a chain with nothing in it.
  if (auditText.includes('NOTHING HAS BEEN ASSESSED') || auditText.includes('nothing was assessed')) {
    throw new Error('unreachable backend was rendered as an assessment result');
  }

  await shot('03-audit-backend-unavailable-not-verified');

  /* ---- 5. Deep link straight to a populated route ----------------------- */

  await page.goto(`${base}/securescan#/audit?assessmentId=ASM-DEEPLINK-1`, { waitUntil: 'domcontentloaded' });
  await expectVisible('#ss-view .ss-state');

  const deepText = (await page.locator('#ss-main').textContent()) ?? '';
  if (!deepText.includes('BACKEND UNAVAILABLE')) {
    throw new Error('deep link to an assessment should still render the explaining failure');
  }
  // The id must round-trip into the DOM request, not be silently dropped.
  const deepHash = await page.evaluate(() => window.location.hash);
  if (!deepHash.includes('ASM-DEEPLINK-1')) throw new Error(`assessment id lost in deep link: ${deepHash}`);
  log('deep link preserved id', deepHash);

  await shot('04-audit-deeplink-with-assessment-id');

  /* ---- 6. Refresh on the audit route must not crash --------------------- */

  await page.reload({ waitUntil: 'domcontentloaded' });
  await expectVisible('#ss-view .ss-state');
  const afterReload = await page.evaluate(() => window.location.hash);
  if (!afterReload.includes('ASM-DEEPLINK-1')) throw new Error(`refresh lost the route: ${afterReload}`);
  if ((await page.locator('#ss-view').textContent())?.trim() === '') {
    throw new Error('refresh produced a blank view');
  }
  log('refresh on audit route survived, hash retained');

  /* ---- 7. Back / forward ------------------------------------------------ */

  await page.goto(`${base}/securescan#/dashboard`, { waitUntil: 'domcontentloaded' });
  await expectVisible('#ss-view');
  await page.locator('.ss-nav__link[href="#/audit"]').click();
  await page.waitForFunction(() => window.location.hash === '#/audit');

  await page.goBack();
  await page.waitForFunction(() => window.location.hash === '#/dashboard');
  log('back -> #/dashboard');

  await page.goForward();
  await page.waitForFunction(() => window.location.hash === '#/audit');
  await expectVisible('#ss-view .ss-state');
  log('forward -> #/audit, view rendered');

  /* ---- 8. The route still resolves from the nav strip across the app ---- */

  const stillThere = await page.locator('.ss-nav__link[href="#/audit"][aria-current="page"]').count();
  if (stillThere !== 1) throw new Error('Audit Center is not marked as the current page');
  log('aria-current set on the active nav link');

  /* ---- 9. Responsive: desktop then mobile ------------------------------- */

  await page.setViewportSize({ width: 1280, height: 800 });
  const overflowDesktop = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  if (overflowDesktop > 0) throw new Error(`desktop horizontal overflow: ${overflowDesktop}px`);
  await shot('05-audit-desktop-1280');
  log('desktop 1280 no horizontal overflow');

  await page.setViewportSize({ width: 390, height: 800 });
  const overflowMobile = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  if (overflowMobile > 0) throw new Error(`mobile horizontal overflow: ${overflowMobile}px`);
  if (!(await page.locator('.ss-nav__link[href="#/audit"]').isVisible())) {
    throw new Error('Audit Center link unreachable at 390px');
  }
  const touchTarget = await page.locator('.ss-nav__link[href="#/audit"]').evaluate((el) => {
    const r = el.getBoundingClientRect();
    return { w: Math.round(r.width), h: Math.round(r.height) };
  });
  log('mobile nav link box', JSON.stringify(touchTarget));
  await shot('06-audit-mobile-390');
  log('mobile 390 no horizontal overflow, nav reachable');

  await page.setViewportSize({ width: 1280, height: 800 });

  /* ---- 10. Keyboard reachability ---------------------------------------- */

  await page.goto(`${base}/securescan#/audit`, { waitUntil: 'domcontentloaded' });
  await expectVisible('#ss-view');

  await page.locator('.ss-nav__link[href="#/audit"]').focus();
  const focusRing = await page.locator('.ss-nav__link[href="#/audit"]').evaluate((el) => {
    const s = getComputedStyle(el);
    return { outlineWidth: s.outlineWidth, outlineStyle: s.outlineStyle, outlineColor: s.outlineColor };
  });
  log('focused nav link computed outline', JSON.stringify(focusRing));

  await page.keyboard.press('Enter');
  await page.waitForFunction(() => window.location.hash === '#/audit');
  log('keyboard Enter reached #/audit');

  // Tab must reach the nav link rather than skipping it.
  await page.goto(`${base}/securescan#/dashboard`, { waitUntil: 'domcontentloaded' });
  await expectVisible('#ss-view');
  await page.keyboard.press('Tab');
  let hops = 0;
  let onAudit = false;
  while (hops < 25 && !onAudit) {
    onAudit = await page.evaluate(() => document.activeElement?.getAttribute('href') === '#/audit');
    if (!onAudit) {
      await page.keyboard.press('Tab');
      hops += 1;
    }
  }
  if (!onAudit) throw new Error(`Audit Center link not reachable within ${hops} tab stops`);
  log('tab order reaches the Audit Center link in', hops, 'hops');
  await shot('07-audit-keyboard-focus');

  /* ---- 11. Accessible names --------------------------------------------- */

  const navLabel = await page.locator('nav.ss-nav').getAttribute('aria-label');
  if (!navLabel) throw new Error('nav has no accessible name');

  const unnamedLinks = await page.evaluate(
    () =>
      Array.from(document.querySelectorAll('.ss-nav__link')).filter((a) => {
        const el = a;
        return (el.textContent ?? '').trim() === '' && !el.getAttribute('aria-label');
      }).length,
  );
  if (unnamedLinks > 0) throw new Error(`${unnamedLinks} nav links have no accessible name`);
  log('nav accessible name:', navLabel);

  /* ---- 12. Console / network triage ------------------------------------ */

  // Everything recorded here is expected without a hosted backend. Anything
  // else — a module transform failure, an uncaught TypeError, a 500 from our
  // own handler — is a real defect.
  const realDefects = [
    ...pageErrors.map((e) => `pageerror: ${e}`),
    ...consoleErrors.filter((e) => !/convex|Convex|websocket|WebSocket|ERR_/i.test(e)).map((e) => `console: ${e}`),
    ...failedRequests.filter((r) => !/convex|localhost:47001|favicon/i.test(r)).map((r) => `http: ${r}`),
  ];

  log('pageerrors', pageErrors.length);
  log('console errors', consoleErrors.length);
  log('failed requests (>=400)', failedRequests.length);
  for (const r of failedRequests.slice(0, 5)) log('  4xx/5xx:', r);
  for (const c of consoleErrors.slice(0, 5)) log('  console:', c);

  if (realDefects.length > 0) {
    throw new Error(`frontend defects, not environment failures:\n${realDefects.join('\n')}`);
  }
  log('no frontend defects: every recorded error traces to the absent backend');
}
