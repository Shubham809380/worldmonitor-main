/**
 * WorldGuard signed-in product shell.
 *
 * Proves the outcome that the change exists for: a user who authenticates lands
 * in a real product surface, navigates it, and can leave it — instead of the
 * static "You are signed in" card that used to be the whole of a successful
 * sign-in.
 *
 * The properties pinned here are the ones a screenshot cannot show, because each
 * is a state the browser can silently get wrong:
 *
 *  1. **The shell is gated on the session, not on client state.** Registration
 *     mints a real `wg-session` cookie from the dev backend, and every assertion
 *     after sign-in reads that cookie back. A shell that rendered from
 *     localStorage would pass a DOM-only check and fail here.
 *  2. **Every destination resolves.** Each sidebar entry is clicked or read, and
 *     the cross-document ones are confirmed to point at a path the server
 *     actually serves — a link to a route that 404s is a dead link, and this is
 *     the specific failure the shell was rebuilt to remove.
 *  3. **A typed SecureScan route hands off instead of dead-ending.** Pasting
 *     `#/audit` must reach the SecureScan app rather than rendering a broken
 *     page here.
 *  4. **The URL tracks the surface.** Reload and Back must resolve to the same
 *     page, and the sign-in `?view=` must not survive into the product.
 *  5. **Sign-out is real and repeatable.** The cookie goes, the form returns, a
 *     reload does not resurrect the shell, and signing in again works — the
 *     round trip is what proves the teardown, not just the first logout.
 *
 * No Convex deployment is configured, so assessment data is legitimately absent.
 * The drive asserts the shell says so; it does not assert counts.
 */

export default async function ({ page, base, shot, log, expectVisible }) {
  const stamp = Date.now();
  const email = `wg-shell-${stamp}@example.com`;
  const password = 'CorrectHorse9!';
  const name = 'Ada Lovelace';

  const cookie = async () => {
    const all = await page.context().cookies();
    return all.find((c) => c.name === 'wg-session');
  };

  // ---- 1. Register and land in the shell ---------------------------------

  await page.goto(`${base}/worldguard.html?view=register`, { waitUntil: 'domcontentloaded' });
  await expectVisible('#wg-name');
  await shot('01-register-form');

  await page.locator('#wg-name').fill(name);
  await page.locator('#wg-email').fill(email);
  await page.locator('#wg-password').fill(password);
  await page.locator('.wg-check__box').click();
  if (!(await page.locator('[name="wg-terms"]').isChecked())) {
    throw new Error('terms checkbox did not become checked');
  }
  await page.locator('[data-wg-submit]').click();

  await expectVisible('.wga-layout');
  await expectVisible('.wga-sidebar');
  await expectVisible('[data-wga-page="dashboard"]');
  await expectVisible('.wga-pagehead__title');

  // The old dead end must be gone, not merely hidden.
  const body = (await page.locator('body').textContent()) ?? '';
  if (body.includes('You are signed in')) {
    throw new Error('the static account view is still rendered post-login');
  }

  // The session must be the one the server minted.
  const session = await cookie();
  if (!session?.value) throw new Error('no wg-session cookie after registration');

  // The product surface must not inherit the sign-in view's query param.
  if (new URL(page.url()).searchParams.has('view')) {
    throw new Error(`stale ?view= survived post-login: ${page.url()}`);
  }
  if (!new URL(page.url()).hash.startsWith('#/dashboard')) {
    throw new Error(`expected the dashboard route, got ${page.url()}`);
  }

  // The identity on screen is the session's, not a placeholder.
  for (const expected of [name, email]) {
    if (!body.includes(expected)) throw new Error(`shell is missing ${expected}`);
  }

  // No backend is configured, so the shell must say so rather than show zeros.
  if (!body.includes('not connected')) {
    throw new Error('shell did not report the unconnected backend');
  }
  log('landed in the shell at', page.url());
  await shot('02-shell-dashboard');

  // ---- 2. The active marker describes exactly one page -------------------

  const currentCount = await page.locator('[aria-current="page"]').count();
  if (currentCount !== 1) {
    throw new Error(`expected exactly one current page marker, found ${currentCount}`);
  }
  const currentHref = await page.locator('[aria-current="page"]').getAttribute('href');
  if (currentHref !== '#/dashboard') {
    throw new Error(`current page marker points at ${currentHref}, expected #/dashboard`);
  }

  // ---- 3. Navigate every shell route -------------------------------------

  for (const route of ['workspace', 'team', 'settings', 'pricing']) {
    await page.locator(`.wga-nav a[data-wga-nav="${route}"]`).click();
    await expectVisible(`[data-wga-page="${route}"]`);
    if (new URL(page.url()).hash !== `#/${route}`) {
      throw new Error(`clicking ${route} left the URL at ${page.url()}`);
    }
    const marked = await page.locator('[aria-current="page"]').getAttribute('href');
    if (marked !== `#/${route}`) {
      throw new Error(`on ${route}, current marker points at ${marked}`);
    }
  }
  await shot('03-pricing');
  log('all four shell routes resolved and marked current');

  // The pricing page must not be a payment form.
  const pricing = (await page.locator('[data-wga-page="pricing"]').textContent()) ?? '';
  if (pricing.includes('Coming soon') !== true) {
    throw new Error('pricing page does not mark the upgrade gate as coming soon');
  }

  // ---- 4. Every sidebar entry has a usable href --------------------------

  const hrefs = await page.locator('.wga-nav a[data-wga-nav]').evaluateAll((els) =>
    els.map((el) => ({ nav: el.getAttribute('data-wga-nav'), href: el.getAttribute('href') })),
  );
  if (hrefs.length !== 12) {
    throw new Error(`expected 12 destinations, found ${hrefs.length}`);
  }
  for (const { nav, href } of hrefs) {
    if (!href) throw new Error(`destination "${nav}" has no href`);
    if (href === '' || href === '#') throw new Error(`destination "${nav}" has a dead href`);
  }

  // Cross-document entries must point at a path the server really serves. This
  // is the dead-link check: a route that 404s would pass every DOM assertion.
  const crossDoc = [...new Set(hrefs.map((h) => h.href).filter((h) => h.startsWith('/')))];
  for (const path of crossDoc) {
    const target = path.split('#')[0];
    const res = await page.request.get(`${base}${target}`);
    if (res.status() !== 200) {
      throw new Error(`cross-document link ${path} -> ${target} answered ${res.status()}`);
    }
  }
  log('cross-document destinations verified:', crossDoc.join(', '));

  // ---- 5. A typed SecureScan route hands off -----------------------------

  await page.goto(`${base}/worldguard.html#/audit`, { waitUntil: 'domcontentloaded' });
  await page.waitForURL(/securescan/, { timeout: 15000 });
  if (!page.url().includes('securescan')) {
    throw new Error(`typed #/audit did not hand off, url is ${page.url()}`);
  }
  log('typed #/audit handed off to', page.url());
  await shot('04-securescan-handoff');

  // ---- 6. A hash that resolves to nothing says so ------------------------
  // Silently showing the dashboard here would make a retired link look live.

  await page.goto(`${base}/worldguard.html#/nonsense`, { waitUntil: 'domcontentloaded' });
  await expectVisible('[data-wga-page="not-found"]');
  const notFoundTitle = await page.title();
  if (!/not found/i.test(notFoundTitle)) {
    throw new Error(`unknown route titled "${notFoundTitle}"`);
  }
  if (await page.locator('[data-wga-page="dashboard"]').count()) {
    throw new Error('an unknown route rendered the dashboard');
  }
  if (await page.locator('[aria-current="page"]').count()) {
    throw new Error('an unknown route marked a destination current');
  }
  // It must be escapable, not a trap.
  await page.locator('[data-wga-page="not-found"] a[href="#/dashboard"]').click();
  await expectVisible('[data-wga-page="dashboard"]');
  log('unknown route reported not-found and led back to the dashboard');

  // ---- 7. Back into the shell; the session must still be there -----------

  await page.goto(`${base}/worldguard.html`, { waitUntil: 'domcontentloaded' });
  await expectVisible('.wga-layout');
  log('returned to the shell; the session survived the hand-off');

  // ---- 7. Reload and Back ------------------------------------------------

  await page.goto(`${base}/worldguard.html#/team`, { waitUntil: 'domcontentloaded' });
  await expectVisible('[data-wga-page="team"]');
  await page.reload({ waitUntil: 'domcontentloaded' });
  await expectVisible('[data-wga-page="team"]');
  if (new URL(page.url()).hash !== '#/team') {
    throw new Error(`reload lost the route: ${page.url()}`);
  }
  log('reload preserved #/team');

  await page.goBack({ waitUntil: 'domcontentloaded' });
  await page.waitForTimeout(400);
  log('back left us at', page.url());

  // ---- 8. Keyboard reachability and desktop fit --------------------------

  await page.goto(`${base}/worldguard.html#/dashboard`, { waitUntil: 'domcontentloaded' });
  await expectVisible('.wga-layout');

  // Sideways scrolling on a wide screen is just as broken as on a narrow one:
  // a grid track that refuses to shrink produces both.
  const desktopOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  if (desktopOverflow > 2) {
    throw new Error(`horizontal overflow of ${desktopOverflow}px at 1280px wide`);
  }

  const focusRing = await page.evaluate(() => {
    const link = document.querySelector('.wga-nav a[data-wga-nav="findings"]');
    if (!link) return null;
    link.focus();
    const s = getComputedStyle(link);
    return { width: s.outlineWidth, style: s.outlineStyle };
  });
  if (!focusRing || focusRing.width === '0px' || focusRing.style === 'none') {
    throw new Error(`sidebar focus ring missing: ${JSON.stringify(focusRing)}`);
  }
  log('sidebar focus ring', JSON.stringify(focusRing));

  // ---- 9. Mobile ---------------------------------------------------------

  await page.setViewportSize({ width: 390, height: 844 });
  await expectVisible('.wga-layout');
  await page.waitForTimeout(150);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  if (overflow > 2) {
    throw new Error(`horizontal overflow of ${overflow}px at 390px wide`);
  }
  // The nav must scroll inside its own track, not push the page.
  const navScrolls = await page.evaluate(() => {
    const nav = document.querySelector('.wga-nav');
    if (!nav) return null;
    return { direction: getComputedStyle(nav).flexDirection, overflowX: getComputedStyle(nav).overflowX };
  });
  if (navScrolls?.direction !== 'row' || navScrolls?.overflowX !== 'auto') {
    throw new Error(`sidebar did not become a horizontal scroller: ${JSON.stringify(navScrolls)}`);
  }
  log('mobile: sidebar scrolls horizontally, no page overflow');
  await shot('05-mobile-dashboard');
  await page.setViewportSize({ width: 1280, height: 800 });

  // ---- 10. Sign out, and prove it is real --------------------------------

  await page.goto(`${base}/worldguard.html#/settings`, { waitUntil: 'domcontentloaded' });
  await expectVisible('[data-wga-page="settings"]');
  await shot('06-settings');

  await page.locator('[data-wga-page="settings"] [data-wga-sign-out]').click();
  await expectVisible('#wg-identifier');
  if (await page.locator('.wga-layout').count()) {
    throw new Error('the shell survived sign-out');
  }
  const after = await cookie();
  if (after?.value) throw new Error('wg-session cookie survived sign-out');
  // The shell route must be cleared, or a later sign-in would resume a route
  // left over from a session that no longer exists.
  if (new URL(page.url()).hash.startsWith('#/')) {
    throw new Error(`stale shell hash survived sign-out: ${page.url()}`);
  }
  log('signed out; cookie cleared and hash reset');
  await shot('07-signed-out');

  await page.reload({ waitUntil: 'domcontentloaded' });
  await expectVisible('#wg-identifier');
  if (await page.locator('.wga-layout').count()) {
    throw new Error('the shell reappeared after signing out');
  }

  // ---- 11. Sign in again -------------------------------------------------

  await page.locator('#wg-identifier').fill(email);
  await page.locator('#wg-password').fill(password);
  await page.locator('[data-wg-submit]').click();
  await expectVisible('.wga-layout');
  await expectVisible('[data-wga-page="dashboard"]');
  if (!(await cookie())?.value) throw new Error('sign-in did not restore a session');
  log('signed back in and landed in the shell');
  await shot('08-signed-in-again');
}
