/**
 * SecureScan shell drive without a hosted backend.
 *
 * Proves what SecureScan renders before any network takes over: the shell boots
 * from the MPA entry, all six navigation sections are listed for every caller
 * (navigation is not authorization), hash routing works, every route renders a
 * truthful failure state instead of a crash when the backend cannot be reached,
 * and the layout stays within the viewport. Also proves keyboard navigation of
 * the nav strip. These are the parts of the browser surface that do not depend
 * on a Convex deployment; authentication/membership/forbidden verification is
 * impossible to prove here because the server that would refuse is not running
 * ("Not authenticated" below is an honest footer, not an auth verdict).
 */
export default async function ({ page, base, shot, log, expectVisible, context }) {
  const navLabels = [
    'Dashboard',
    'Assessments',
    'Findings',
    'Evidence',
    'Report',
    'Administration',
  ];

  await page.goto(`${base}/securescan`, { waitUntil: 'domcontentloaded' });
  page.on('pageerror', (err) => log('pageerror:', String(err).slice(0, 300)));

  await expectVisible('#ss-view');

  const brand = await page.locator('.ss-brand__name').textContent();
  if (brand !== 'SecureScan') throw new Error(`expected branded shell, got ${brand}`);

  const links = await page.locator('.ss-nav__link').allTextContents();
  const labels = links.map((t) => t.trim());
  for (const want of navLabels) {
    if (!labels.includes(want)) throw new Error(`nav missing section: ${want}`);
  }
  log('nav sections', labels.join(' / '));

  await expectVisible('#ss-view .ss-state');
  const dashText = (await page.locator('#ss-main').textContent()) ?? '';
  if (!dashText.includes('BACKEND UNAVAILABLE')) {
    throw new Error("dashboard should render the unavailable failure state without a backend");
  }
  await shot('01-boot-dashboard-failure');

  const footer = await page.locator('.ss-sidebar__foot').textContent();
  log('footer identity:', footer?.trim().split('\n')[0]?.trim());

  const titleByHash = {
    '#/dashboard': 'Security Assessment Overview',
    '#/assessments': 'Assessments',
    '#/findings': 'Findings',
    '#/evidence': 'Evidence',
    '#/report': 'Assessment Report',
    '#/admin': 'Administration',
  };

  for (const [hash, heading] of Object.entries(titleByHash)) {
    await page.locator(`.ss-nav__link[href="${hash}"]`).click();
    await page.waitForFunction(
      (h) => document.querySelector('.ss-page-title')?.textContent?.includes(h),
      heading,
    );
    if (!(await page.locator('#ss-main .ss-state').count())) {
      throw new Error(`route ${hash} rendered without an explaining state`);
    }
    log('route ok:', heading);
  }
  await shot('02-routes-render-failure-states');

  const overflowDesktop = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  if (overflowDesktop > 0) throw new Error(`desktop horizontal overflow: ${overflowDesktop}px`);
  log('desktop no overflow');

  await page.evaluate(() => {
    window.location.hash = '#/assessments/new';
  });
  await expectVisible('#ss-view form.ss-form');
  log('new assessment form rendered');
  await shot('03-new-assessment-form');

  await page.setViewportSize({ width: 390, height: 780 });
  await page.locator('.ss-nav__link[href="#/dashboard"]').click();
  await expectVisible('#ss-view .ss-state');
  const overflowMobile = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  if (overflowMobile > 0) throw new Error(`mobile horizontal overflow: ${overflowMobile}px`);
  await shot('04-mobile-dashboard');
  log('mobile no overflow');

  await page.setViewportSize({ width: 1280, height: 720 });
  const sidebarVisibleAtDesktop = await page.locator('.ss-sidebar').isVisible();
  if (!sidebarVisibleAtDesktop) throw new Error('sidebar not visible at desktop');
  log('sidebar responsive state ok');

  const focused = await page.keyboard.press('Tab');
  void focused;
  const activeEl = await page.evaluate(() => document.activeElement?.className ?? '');
  log('initial tab target class:', activeEl);

  await page.evaluate(() => window.location.hash === '#/assessments');
  await page.locator('.ss-nav__link[href="#/assessments"]').focus();
  await page.keyboard.press('Enter');
  await page.waitForFunction(() => window.location.hash.startsWith('#/assessments'));
  log('keyboard Enter navigated to #/assessments');
  await shot('05-keyboard-navigation');
}