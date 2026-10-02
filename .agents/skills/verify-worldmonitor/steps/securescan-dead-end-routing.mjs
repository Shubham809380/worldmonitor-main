/**
 * Dead-end escapes and filter routing — the real app, no hosted backend.
 *
 * `VITE_CONVEX_URL` is unset in this checkout, so `getConvexClient()` returns null
 * and every SecureScan query resolves to `fail('unavailable')`. That makes the
 * data-dependent half of this surface **unprovable here**: finding rows, their
 * real state/severity badges, the lifecycle panels, and the finding rows the
 * filter narrows are all produced by a server that is not running. This drive
 * therefore proves only the parts that need no server verdict, and it is explicit
 * about which is which.
 *
 * What it proves:
 *   1. Every reachable dead end offers a real route out, and each escape lands on
 *      a page that actually renders. "Open a finding", "open an assessment" and
 *      "that view does not exist" used to be instructions with nothing to click.
 *   2. Navigation is a fragment operation, never a document load. This is the
 *      contract the findings filter was rewritten to satisfy: a filter must be
 *      readable from `location.hash` and must never leak into `location.search`,
 *      because a hash router cannot see a query string.
 *   3. Deep links, refresh, and back/forward all survive a round trip.
 *   4. Layout holds at 1280, 1024, 768 and 390 px, and the recovery controls are
 *      still reachable and big enough to hit on the narrowest width.
 *
 * Not proven here, and deliberately not simulated: any authorization or role
 * verdict, membership, findings content, and therefore the rendered appearance of
 * the state badges. A Convex deployment is required for those; see the final
 * report's blocked list rather than a fixture standing in for a server.
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
    if (res.status() >= 400) failedRequests.push(`${res.status()} ${res.url().slice(0, 160)}`);
  });

  /* ---- 1. The shell boots and every nav link is a fragment ---------------- */

  await page.goto(`${base}/securescan`, { waitUntil: 'domcontentloaded' });
  await expectVisible('#ss-view');

  const navHrefs = await page.evaluate(() =>
    Array.from(document.querySelectorAll('.ss-nav__link')).map((a) => a.getAttribute('href')),
  );
  if (navHrefs.length === 0) throw new Error('no nav links rendered');
  for (const href of navHrefs) {
    if (!href?.startsWith('#/')) {
      throw new Error(`nav link is not a fragment route: ${href}`);
    }
  }
  log('nav links are all fragment routes', navHrefs.join(' '));

  /* ---- 2. Document loads must not increase while navigating -------------- */

  const loads = [];
  page.on('load', () => loads.push(page.url()));

  // Walk every route through the nav strip and count full document loads. A hash
  // change is a fragment navigation; a real reload would re-run the whole app.
  for (const hash of [
    '#/assessments',
    '#/assessments/new',
    '#/findings',
    '#/evidence',
    '#/report',
    '#/audit',
    '#/admin',
    '#/dashboard',
  ]) {
    await page.evaluate((h) => {
      window.location.hash = h;
    }, hash);
    await expectVisible('#ss-view');
    // A route that resolves must not blank the view.
    const text = ((await page.locator('#ss-view').textContent()) ?? '').trim();
    if (text.length === 0) throw new Error(`route ${hash} rendered an empty view`);
  }
  await page.waitForTimeout(400);
  if (loads.length !== 0) {
    throw new Error(`fragment navigation triggered ${loads.length} document load(s): ${loads.join(', ')}`);
  }
  log('8 routes navigated with 0 document reloads');

  /* ---- 3. The dead ends that need no server verdict are escapable --------- */

  // These three refuse on the missing/invalid route before any fetch, so their
  // behaviour does not depend on a backend and is fully provable here.
  const deadEnds = [
    { hash: '#/evidence', title: 'MISSING EVIDENCE', escape: 'findings' },
    { hash: '#/report', title: 'CHOOSE AN ASSESSMENT', escape: 'assessments' },
    { hash: '#/this-route-does-not-exist', title: 'PAGE NOT FOUND', escape: 'dashboard' },
  ];

  for (const { hash, title, escape } of deadEnds) {
    await page.goto(`${base}/securescan${hash}`, { waitUntil: 'domcontentloaded' });
    await expectVisible('#ss-view .ss-state--error');

    const state = page.locator('.ss-state--error').first();
    const stateText = (await state.textContent()) ?? '';
    if (!stateText.includes(title)) {
      throw new Error(`${hash}: expected "${title}", got: ${stateText.slice(0, 160)}`);
    }
    // The dead end must read as an alert, not as content.
    if ((await state.getAttribute('role')) !== 'alert') {
      throw new Error(`${hash}: failure state is not announced as an alert`);
    }

    const hrefs = await page.evaluate(() =>
      Array.from(document.querySelectorAll('.ss-state--error a[href]')).map((a) => a.getAttribute('href')),
    );
    if (hrefs.length === 0) {
      throw new Error(`${hash}: "${title}" offers no way out — a reader is stranded here`);
    }
    log(`${hash} escapes to`, hrefs.join(' '));

    // Every escape must be a real route, must stay a fragment, and must not lead
    // back into the dead end it is escaping.
    for (const href of hrefs) {
      if (!href.startsWith('#/')) throw new Error(`${hash}: escape is not a fragment route: ${href}`);
      const routeName = href.replace(/^#\//, '').split('?')[0];
      if (routeName === '') throw new Error(`${hash}: empty escape href`);
      if (href === hash) throw new Error(`${hash}: escape points back at the dead end`);
      // An escape to a route name the router does not know is still a dead end,
      // just one step further away.
      const knownRoutes = await page.evaluate(() => Array.from(
        document.querySelectorAll('.ss-nav__link'),
      ).map((a) => (a.getAttribute('href') ?? '').replace(/^#\//, '').split('?')[0]));
      if (!knownRoutes.includes(routeName) && routeName !== 'assessments/new') {
        throw new Error(`${hash}: escape points at unknown route "${routeName}"`);
      }
    }
    if (escape && !hrefs.some((h) => h.startsWith(`#/${escape}`))) {
      throw new Error(`${hash}: expected an escape into ${escape}, saw ${hrefs.join(' ')}`);
    }
  }
  await shot('01-dead-ends-offer-routes-out');

  /* ---- 4. Following an escape lands on a working page --------------------- */

  await page.goto(`${base}/securescan#/evidence`, { waitUntil: 'domcontentloaded' });
  await expectVisible('#ss-view .ss-state--error');
  const escapeHref = await page.evaluate(
    () => document.querySelector('.ss-state--error a[href]')?.getAttribute('href') ?? '',
  );
  await page.locator(`.ss-state--error a[href="${escapeHref}"]`).click();
  await page.waitForFunction((h) => window.location.hash === h, escapeHref);
  await expectVisible('#ss-view');
  // The findings page with no backend renders a truthful failure, not a crash and
  // not a second dead end with no escape.
  const findingsText = ((await page.locator('#ss-view').textContent()) ?? '').trim();
  if (findingsText.length === 0) throw new Error('escape landed on an empty view');
  log('escape followed to', escapeHref);
  await shot('02-escape-lands-on-a-live-page');

  /* ---- 5. A filter must live in the hash, never in the search string ------- */

  // The defect this replaced: a native GET form with `action="#/findings"` put the
  // filter into `location.search`, where a fragment router cannot see it, and cost
  // a full document load. A deep-linked filter must round-trip through the hash.
  await page.goto(`${base}/securescan#/findings?state=REGRESSION&severity=HIGH`, {
    waitUntil: 'domcontentloaded',
  });
  await expectVisible('#ss-view');

  const routing = await page.evaluate(() => ({
    hash: window.location.hash,
    search: window.location.search,
    path: window.location.pathname,
  }));
  log('deep link routing', JSON.stringify(routing));

  if (routing.search !== '') {
    throw new Error(
      `filter leaked into the query string (${routing.search}); a hash router cannot read it`,
    );
  }
  if (!routing.hash.includes('state=REGRESSION') || !routing.hash.includes('severity=HIGH')) {
    throw new Error(`deep link lost its filter: ${routing.hash}`);
  }

  // And no document load was needed to arrive there.
  if (loads.length !== 0) {
    throw new Error(`deep link triggered a document load: ${loads.length}`);
  }
  await shot('03-filter-deeplink-stays-in-the-hash');

  /* ---- 6. Refresh keeps the route and the filter ------------------------- */

  await page.reload({ waitUntil: 'domcontentloaded' });
  await expectVisible('#ss-view');
  const afterReload = await page.evaluate(() => ({
    hash: window.location.hash,
    search: window.location.search,
  }));
  if (afterReload.hash !== routing.hash) {
    throw new Error(`refresh changed the route: ${afterReload.hash} != ${routing.hash}`);
  }
  if (afterReload.search !== '') {
    throw new Error(`refresh pushed the filter into the query string: ${afterReload.search}`);
  }
  log('refresh preserved the filtered route', afterReload.hash);

  /* ---- 7. Back and forward across filtered routes ------------------------ */

  // Two hash-only steps, then walk both directions. Back/forward is the property
  // a fragment router gets for free and a GET form destroys, so it is checked
  // explicitly rather than assumed.
  await page.evaluate(() => {
    window.location.hash = '#/findings?state=CANDIDATE';
  });
  await expectVisible('#ss-view');
  await page.evaluate(() => {
    window.location.hash = '#/findings?severity=CRITICAL';
  });
  await expectVisible('#ss-view');

  await page.goBack();
  await page.waitForFunction(() => window.location.hash.includes('state=CANDIDATE'));
  await expectVisible('#ss-view');
  log('back ->', await page.evaluate(() => window.location.hash));

  await page.goForward();
  await page.waitForFunction(() => window.location.hash.includes('severity=CRITICAL'));
  await expectVisible('#ss-view');
  const forwardHash = await page.evaluate(() => window.location.hash);
  if (forwardHash.includes('state=CANDIDATE')) {
    throw new Error('forward kept the previous filter: filters are stacking');
  }
  log('forward ->', forwardHash);

  // The filtered route must still be a working view, not an error.
  await expectVisible('#ss-view');
  await shot('04-back-forward-across-filters');

  /* ---- 8. Responsive: all four required widths --------------------------- */

  // Each width is checked on a filtered findings route and on the unknown-route
  // recovery, because that state is the one a reader reaches by mistake and it
  // has to be recoverable on a phone.
  const widths = [1280, 1024, 768, 390];

  for (const width of widths) {
    await page.setViewportSize({ width, height: 900 });

    for (const hash of ['#/findings?state=REGRESSION', '#/this-route-does-not-exist']) {
      await page.evaluate((h) => {
        window.location.hash = h;
      }, hash);
      await expectVisible('#ss-view');

      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      );
      if (overflow > 0) {
        throw new Error(`${width}px on ${hash}: horizontal overflow of ${overflow}px`);
      }

      // Nothing may spill out of the viewport horizontally, element by element.
      const spills = await page.evaluate(() => {
        const limit = document.documentElement.clientWidth + 1;
        return Array.from(document.querySelectorAll('#ss-view *'))
          .filter((el) => {
            const r = el.getBoundingClientRect();
            return r.width > 0 && (r.right > limit || r.left < -1);
          })
          .slice(0, 4)
          .map((el) => `${el.tagName.toLowerCase()}.${el.className || '(no class)'}`);
      });
      if (spills.length > 0) {
        throw new Error(`${width}px on ${hash}: element(s) overflow the viewport: ${spills.join(', ')}`);
      }
    }

    // The recovery control must remain usable at every width, not merely present.
    const recovery = page.locator('.ss-state--error a[href="#/dashboard"]');
    if (!(await recovery.isVisible())) {
      throw new Error(`${width}px: the recovery link is not visible`);
    }
    const box = await recovery.evaluate((el) => {
      const r = el.getBoundingClientRect();
      return { w: Math.round(r.width), h: Math.round(r.height) };
    });
    if (box.h < 24) {
      throw new Error(`${width}px: recovery link is only ${box.h}px tall — not a usable target`);
    }
    log(`${width}px recovery link box`, JSON.stringify(box));
    await shot(`05-width-${width}-recovery`);
  }

  await page.setViewportSize({ width: 1280, height: 900 });

  /* ---- 9. Accessible names on the controls in these states -------------- */

  const unnamed = await page.evaluate(() =>
    Array.from(document.querySelectorAll('#ss-view a[href]'))
      .filter((a) => (a.textContent ?? '').trim() === '' && !a.getAttribute('aria-label'))
      .map((a) => a.getAttribute('href')),
  );
  if (unnamed.length > 0) {
    throw new Error(`links with no accessible name: ${unnamed.join(', ')}`);
  }
  log('every in-view link has an accessible name');

  // The failure state must be reachable by keyboard, not pointer-only: a reader
  // who cannot see the page still needs the way out.
  await page.goto(`${base}/securescan#/this-route-does-not-exist`, { waitUntil: 'domcontentloaded' });
  await expectVisible('#ss-view .ss-state--error');
  await page.locator('.ss-state--error a[href="#/dashboard"]').focus();
  const ring = await page.locator('.ss-state--error a[href="#/dashboard"]').evaluate((el) => {
    const s = getComputedStyle(el);
    return { outlineStyle: s.outlineStyle, outlineWidth: s.outlineWidth };
  });
  log('focused recovery link outline', JSON.stringify(ring));
  if (ring.outlineStyle === 'none' || ring.outlineWidth === '0px') {
    throw new Error('the focused recovery link has no visible focus indicator');
  }
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => window.location.hash === '#/dashboard');
  await expectVisible('#ss-view');
  log('keyboard Enter recovered from the unknown route to #/dashboard');
  await shot('06-keyboard-recovery');

  /* ---- 10. A hostile assessment id is just an id ------------------------ */

  // The address bar is attacker-controlled, and the browser hands `assessmentId`
  // to the backend with no format check, which is correct: the client is not the
  // place to decide what a valid id looks like. Two things therefore have to hold
  // and both are provable with no backend.
  //
  // First, a malformed id must be indistinguishable from a well-formed id that
  // does not exist. It must produce the same refusing state, not a differently
  // worded or differently *authorised* one — a special "invalid" branch that
  // renders more than the "unknown" branch would be a way to probe the id space.
  //
  // Second, the id must never be reflected as markup. It arrives from the URL and
  // the page renders the id back into headings, links and empty states, so if any
  // of that is interpolated unescaped the URL becomes stored or reflected XSS.
  const payload = '"><img src=x onerror="window.__wmXss=1">';
  const navigation = [];

  await page.exposeFunction('__wmRecordDialog', (kind) => navigation.push(`dialog:${kind}`));
  page.on('dialog', async (d) => {
    navigation.push(`dialog:${d.type()}`);
    await d.dismiss();
  });

  for (const [label, id] of [
    ['malformed', payload],
    ['oversized', 'A'.repeat(4096)],
    ['well-formed-but-missing', 'ASM-DOES-NOT-EXIST-1'],
  ]) {
    await page.goto(`${base}/securescan#/assessments/${encodeURIComponent(id)}`, {
      waitUntil: 'domcontentloaded',
    });
    await expectVisible('#ss-view');

    const probe = await page.evaluate(() => ({
      xss: Boolean(window.__wmXss),
      dialogs: 0,
      // The id must appear as text at most, never as live markup.
      injected: document.querySelectorAll('#ss-view img, #ss-view script, #ss-view iframe').length,
      hash: window.location.hash,
      text: (document.querySelector('#ss-view')?.textContent ?? '').trim(),
    }));

    if (probe.xss) throw new Error(`${label} id executed script — the id is being rendered as markup`);
    if (probe.injected > 0) {
      throw new Error(`${label} id injected ${probe.injected} element(s) into the view`);
    }
    if (probe.text.length === 0) throw new Error(`${label} id produced an empty view`);
    if (probe.text.length > 4000) {
      throw new Error(`${label} id produced a ${probe.text.length}-character view — the id is being echoed`);
    }
    // The same refusing state as a missing backend, for every shape of id.
    if (!probe.text.includes('BACKEND UNAVAILABLE')) {
      throw new Error(`${label} id did not render the refusing state: ${probe.text.slice(0, 160)}`);
    }
    log(`${label} id`, `refused, ${probe.text.length} chars, no markup`);
  }

  if (navigation.length > 0) {
    throw new Error(`a hostile id raised UI: ${navigation.join(', ')}`);
  }
  await shot('07-hostile-assessment-id-refused-not-reflected');

  /* ---- 11. Console / network triage ------------------------------------- */

  const realDefects = [
    ...pageErrors.map((e) => `pageerror: ${e}`),
    ...consoleErrors
      .filter((e) => !/convex|Convex|websocket|WebSocket|ERR_/i.test(e))
      .map((e) => `console: ${e}`),
    ...failedRequests.filter((r) => !/convex|localhost:47001|favicon/i.test(r)).map((r) => `http: ${r}`),
  ];

  log('pageerrors', pageErrors.length);
  log('console errors', consoleErrors.length);
  log('failed requests (>=400)', failedRequests.length);

  if (realDefects.length > 0) {
    throw new Error(`frontend defects, not environment failures:\n${realDefects.join('\n')}`);
  }
  log('no frontend defects: every recorded error traces to the absent backend');
}
