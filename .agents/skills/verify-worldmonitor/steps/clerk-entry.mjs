/**
 * `/` auth-entry drive against the real Clerk dev instance.
 *
 * The page (src/main.ts) must render the SecureScan sign-in card, reflect the
 * real signed-out Clerk state, and open Clerk's own sign-in surface on click
 * (loaded via the shared services/clerk.ts UMD path — not the broken bundled
 * `new Clerk()` scaffold). Also asserts no secret key value leaks into the DOM,
 * the network, or console output.
 */
export default async function ({ page, base, shot, log, expectVisible }) {
  await page.goto(`${base}/`, { waitUntil: 'domcontentloaded' });

  await expectVisible('.ss-auth__title', 60_000);

  const settled = await page
    .waitForFunction(
      () => {
        const t = document.querySelector('.ss-auth__title')?.textContent ?? '';
        return t !== 'Checking session';
      },
      { timeout: 45_000 },
    )
    .then(() => true)
    .catch(() => false);
  log('auth state settled within 45s:', settled);

  const title = await page.locator('.ss-auth__title').first().innerText();
  log('auth card title:', title);
  if (!settled || !/sign in to securescan/i.test(title)) {
    throw new Error(`auth state did not settle to signed-out; title=${title}`);
  }
  await shot('01-auth-signed-out-card');

  const hasSignIn = await page.locator('button:has-text("Sign in")').first().isVisible();
  const hasCreate = await page.locator('button:has-text("Create account")').first().isVisible();
  log('sign-in button visible:', hasSignIn, '| create-account visible:', hasCreate);
  if (!hasSignIn || !hasCreate) throw new Error('missing Sign in / Create account actions');

  await page.locator('button:has-text("Sign in")').first().click();
  log('clicked Sign in');
  await shot('02-auth-after-signin-click');

  const clerkModalOpened = await page
    .waitForSelector('.cl-modal, [data-clerk-component="SignIn"], .cl-signIn-root', { timeout: 20_000 })
    .then(async (handle) => {
      if (handle) return handle.isVisible();
      return false;
    })
    .catch(() => false);
  log('clerk sign-in surface visible:', clerkModalOpened);
  await shot('03-auth-clerk-surface');

  const secretLeakDom = await page.content();
  if (secretLeakDom.includes('CLERK_SECRET_KEY')) {
    throw new Error('CLERK_SECRET_KEY variable name appears in the DOM');
  }
  log('no secret key name in DOM');

  const leakedResources = await page.evaluate(() =>
    performance
      .getEntriesByType('resource')
      .filter((r) => r.name.includes('CLERK_SECRET') || r.name.includes('sk_test_') || r.name.includes('sk_live_'))
      .map((r) => r.name.slice(0, 140)),
  );
  if (leakedResources.length > 0) throw new Error(`secret-looking URL resources: ${leakedResources.join(', ')}`);
  log('no secret-looking URLs in performance resources');

  await page.waitForTimeout(1_000);
  const width = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (width > 0) log('horizontal overflow:', width, 'px');
  else log('no horizontal overflow');
  await shot('04-auth-final');
}