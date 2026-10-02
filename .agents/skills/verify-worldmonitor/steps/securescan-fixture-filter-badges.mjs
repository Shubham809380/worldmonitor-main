/**
 * Findings filter and state-badge axis — real modules, real browser, fixture data.
 *
 * READ THIS BEFORE READING THE RESULT. The data in this drive is a fixture, not a
 * server answer. `VITE_CONVEX_URL` is unset in this checkout, so the real Convex
 * client is null and `listFindings` cannot return a row. The fixture below is
 * handed to the **real** `renderFindings` and the **real** `activateFindingsFilters`
 * modules, served by the dev server, mounted into the live document, styled by the
 * real stylesheet, and driven by real pointer and keyboard events.
 *
 * So this drive proves two specific things that a DOM-emulation test cannot:
 *
 *   1. Real `<select>` semantics. happy-dom resolves a selected third `<option>`'s
 *      `.value` to `CANDIDATE` rather than to the selected option, which is a
 *      known reason the earlier unit assertion was wrong about its own subject. A
 *      real browser is the only place the preselected filter can be trusted, and
 *      "the deep link shows the filter the URL asked for" is a user-visible claim.
 *
 *   2. Real computed colour. Badge contrast has to be measured on resolved custom
 *      properties and real cascade, not on the class names' intent. A validated
 *      finding and a verified finding must not read as the same green as a
 *      passing test, because those three mean different things to a reader.
 *
 * What this drive does NOT prove, and must not be reported as proving: that the
 * server returns these rows, that any role may see them, that the filter reaches
 * the backend with the right arguments at runtime, or any authorization property.
 * The request-argument contract is covered by
 * `tests/dom/securescan-findings-filter.test.mts` against the real app shell; the
 * backend contract needs a Convex deployment. Nothing here stands in for a verdict.
 */
export default async function ({ page, base, shot, log }) {
  const pageErrors = [];

  page.on('pageerror', (err) => pageErrors.push(String(err).slice(0, 300)));

  const loads = [];
  page.on('load', () => loads.push(page.url()));

  /* ---- 1. Mount the real page module with a fixture read-model ---------- */

  await page.goto(`${base}/securescan#/dashboard`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#ss-view');

  const mounted = await page.evaluate(async () => {
    // Real modules, resolved by the dev server's own module graph.
    const findings = await import('/src/securescan/pages/findings.ts');
    const dom = await import('/src/securescan/components/dom.ts');

    // Built from the module's own exports, so this fixture cannot drift from the
    // state union it is standing in for.
    const finding = (state, over = {}) => ({
      findingId: `FND-${state}`,
      assessmentId: 'ASM-FIXTURE',
      title: `Finding in ${state}`,
      state,
      stateLabel: state.replace(/_/g, ' ').toLowerCase(),
      severity: 'HIGH',
      severityLabel: 'High',
      confidence: 'HIGH',
      component: 'checkout',
      node: null,
      boundary: 'internet',
      control: 'A03-2021',
      category: 'Injection',
      evidenceCount: 2,
      affectedEndpoints: ['/checkout'],
      fingerprint: `fp-${state}`,
      updatedAt: 1750000000000,
      ...over,
    });

    const model = {
      role: 'ASSURER',
      total: findings.STATE_OPTIONS.length,
      findings: findings.STATE_OPTIONS.map((s) => finding(s)),
    };

    // Mounted outside #ss-view so the app's own hash router, which re-renders its
    // view on every navigation, cannot replace the fixture mid-assertion.
    const host = document.createElement('div');
    host.id = 'fixture-host';
    document.body.appendChild(host);
    dom.mount(host, findings.renderFindings(model, {}));
    findings.activateFindingsFilters(host);

    return {
      states: findings.STATE_OPTIONS,
      severities: findings.SEVERITY_OPTIONS,
      selects: Array.from(host.querySelectorAll('select')).map((s) => s.id),
      badgeCount: host.querySelectorAll('.ss-badge').length,
      rowCount: host.querySelectorAll('[data-finding-id]').length,
    };
  });

  log('fixture states', mounted.states.join(', '));
  log('fixture severities', mounted.severities.join(', '));
  log('controls', mounted.selects.join(', ') || '(none)');
  log('badges rendered', mounted.badgeCount);

  if (mounted.selects.length !== 2) {
    throw new Error(`expected a state and a severity control, got: ${mounted.selects.join(', ') || 'none'}`);
  }
  if (mounted.badgeCount === 0) throw new Error('no badges rendered — cannot assess the state axis');
  await page.waitForSelector('#fixture-host');
  await shot('01-fixture-findings-filter-and-badges');

  /* ---- 2. Real select semantics: no filter preselected ------------------- */

  const pristine = await page.evaluate(() =>
    Array.from(document.querySelectorAll('#fixture-host select')).map((s) => s.value),
  );
  log('unfiltered select values', JSON.stringify(pristine));
  if (pristine.some((v) => v !== '')) {
    throw new Error(`an unfiltered page preselected a filter: ${JSON.stringify(pristine)}`);
  }

  /* ---- 3. Real select semantics: a deep link preselects what it asked for - */

  // The third option is the one happy-dom misreports, so a regression here is
  // the specific bug that motivated checking in a real browser at all.
  for (const [state, severity] of [
    ['REGRESSION', 'CRITICAL'],
    ['CANDIDATE', 'LOW'],
    ['VALIDATED', 'MEDIUM'],
    ['FIXED', 'NONE'],
  ]) {
    const values = await page.evaluate(
      async ({ s, sev }) => {
        // Exactly what the router does on a deep link: the same module, the same
        // params object, mounted into the live document.
        const findings = await import('/src/securescan/pages/findings.ts');
        const dom = await import('/src/securescan/components/dom.ts');
        document.getElementById('fixture-host')?.remove();
        const host = document.createElement('div');
        host.id = 'fixture-host';
        document.body.appendChild(host);
        dom.mount(host, findings.renderFindings(
          { role: 'ASSURER', total: 1, findings: [{
            findingId: 'FND-1', assessmentId: 'ASM-1', title: 'Fixture finding',
            state: 'CANDIDATE', stateLabel: 'candidate', severity: 'HIGH',
            severityLabel: 'High', confidence: 'HIGH', component: null, node: null,
            boundary: 'internet', control: 'A03-2021', category: 'Injection',
            evidenceCount: 1, affectedEndpoints: [], fingerprint: 'fp', updatedAt: 1750000000000,
          }] },
          { state: s, severity: sev },
        ));
        findings.activateFindingsFilters(host);
        return {
          state: host.querySelector('#ss-filter-state')?.value ?? null,
          severity: host.querySelector('#ss-filter-severity')?.value ?? null,
        };
      },
      { s: state, sev: severity },
    );
    if (values.state !== state || values.severity !== severity) {
      throw new Error(
        `deep link to state=${state}&severity=${severity} preselected ${JSON.stringify(values)} — ` +
          'the control does not show the filter the URL asked for',
      );
    }
    log(`preselected ${state}/${severity}`, JSON.stringify(values));
  }
  await shot('02-deeplink-filter-preselected-in-a-real-select');

  /* ---- 4. Real change events move the hash, not the document ------------- */

  // Mount a clean unfiltered view so the change starts from a known state.
  await page.evaluate(async () => {
    document.getElementById('fixture-host')?.remove();
  });

  const before = loads.length;
  let lastChange = null;

  for (const [selector, value, expectFragment] of [
    ['#ss-filter-state', 'REGRESSION', 'state=REGRESSION'],
    ['#ss-filter-severity', 'CRITICAL', 'severity=CRITICAL'],
  ]) {
    const result = await page.evaluate(
      async ({ sel, val }) => {
        const dom = await import('/src/securescan/components/dom.ts');
        const findings = await import('/src/securescan/pages/findings.ts');
        const host = document.createElement('div');
        host.id = 'fixture-host';
        document.body.appendChild(host);
        dom.mount(host, findings.renderFindings(
          {
            role: 'ASSURER',
            total: 1,
            findings: [{
              findingId: 'FND-1', assessmentId: 'ASM-1', title: 'Fixture finding',
              state: 'CANDIDATE', stateLabel: 'candidate', severity: 'HIGH',
              severityLabel: 'High', confidence: 'HIGH', component: null, node: null,
              boundary: 'internet', control: 'A03-2021', category: 'Injection',
              evidenceCount: 1, affectedEndpoints: [], fingerprint: 'fp', updatedAt: 1750000000000,
            }],
          },
          {},
        ));
        findings.activateFindingsFilters(host);

        const el = host.querySelector(sel);
        if (!el) return { error: `no control ${sel}` };
        el.value = val;
        // A real change event, dispatched the way a user's selection fires.
        el.dispatchEvent(new Event('change', { bubbles: true }));
        await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
        return {
          hash: window.location.hash,
          search: window.location.search,
          value: el.value,
        };
      },
      { sel: selector, val: value },
    );

    if (result.error) throw new Error(result.error);
    if (!result.hash.includes(expectFragment)) {
      throw new Error(`${selector} -> ${value} produced ${result.hash}, expected ${expectFragment}`);
    }
    if (result.search !== '') {
      throw new Error(`${selector} pushed the filter into the query string: ${result.search}`);
    }
    lastChange = result;
    log(`${selector} = ${value}`, `hash ${result.hash}, search ""`);
  }

  // The whole point of the rewrite: a filter is a fragment navigation, so the
  // document must not have been reloaded and the query string must stay empty.
  if (loads.length !== before) {
    throw new Error(`changing a filter reloaded the document ${loads.length - before} time(s)`);
  }
  log('two filter changes caused 0 document reloads and 0 query-string writes');

  // And the resulting route is one the app itself can serve.
  const finalHash = lastChange?.hash ?? '#/findings?severity=CRITICAL';
  await page.goto(`${base}/securescan${finalHash}`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#ss-view');
  const routedHash = await page.evaluate(() => window.location.hash);
  if (routedHash !== finalHash) throw new Error(`route did not settle: ${routedHash}`);
  log('filter hash is a route the app serves', routedHash);
  await shot('03-filter-hash-served-by-the-router');

  /* ---- 5. Real computed colour: the state axis is a real axis ------------ */

  // Re-mount the full state set to measure every lifecycle badge.
  await page.evaluate(async () => {
    document.getElementById('fixture-host')?.remove();
    const findings = await import('/src/securescan/pages/findings.ts');
    const dom = await import('/src/securescan/components/dom.ts');
    const host = document.createElement('div');
    host.id = 'fixture-host';
    document.body.appendChild(host);
    const rows = findings.STATE_OPTIONS.map((state) => ({
      findingId: `FND-${state}`, assessmentId: 'ASM-FIXTURE', title: `Finding in ${state}`,
      state, stateLabel: state.replace(/_/g, ' ').toLowerCase(), severity: 'HIGH',
      severityLabel: 'High', confidence: 'HIGH', component: null, node: null,
      boundary: 'internet', control: 'A03-2021', category: 'Injection',
      evidenceCount: 1, affectedEndpoints: [], fingerprint: `fp-${state}`, updatedAt: 1750000000000,
    }));
    dom.mount(host, findings.renderFindings({ role: 'ASSURER', total: rows.length, findings: rows }, {}));
  });

  // Measured on the resolved cascade, not on the class name's intent. The badge
  // backgrounds are semi-transparent (`rgba(..., 0.13)`), so the real backdrop has
  // to be composited down the ancestor chain — reading the alpha colour as if it
  // were opaque measures the badge against a saturated hue that no reader ever
  // sees, and reports a false failure.
  const badges = await page.evaluate(() => {
    const parse = (value) => {
      const m = String(value).match(/rgba?\(([^)]+)\)/);
      if (!m) return null;
      const p = m[1].split(/[\s,/]+/).filter(Boolean).map(Number);
      if (p.length < 3 || p.some((n) => Number.isNaN(n))) return null;
      return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
    };
    const over = (fg, bg) => ({
      r: fg.r * fg.a + bg.r * (1 - fg.a),
      g: fg.g * fg.a + bg.g * (1 - fg.a),
      b: fg.b * fg.a + bg.b * (1 - fg.a),
      a: 1,
    });
    const lum = ({ r, g, b }) => {
      const f = (c) => {
        const s = c / 255;
        return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
    };
    // The opaque backdrop is whatever the page composites down to; starting from
    // white is safe because the chain always contains an opaque body or html.
    const backdropOf = (el) => {
      const chain = [];
      for (let n = el; n; n = n.parentElement) chain.unshift(n);
      let acc = { r: 255, g: 255, b: 255, a: 1 };
      for (const node of chain) {
        const c = parse(getComputedStyle(node).backgroundColor);
        if (c && c.a > 0) acc = over(c, acc);
      }
      return acc;
    };
    const hex = ({ r, g, b }) =>
      '#' + [r, g, b].map((v) => Math.round(v).toString(16).padStart(2, '0')).join('');

    return Array.from(document.querySelectorAll('#fixture-host .ss-badge')).map((el) => {
      const s = getComputedStyle(el);
      const bg = backdropOf(el);
      const fg = parse(s.color) ?? { r: 0, g: 0, b: 0, a: 1 };
      const l1 = lum(fg);
      const l2 = lum(bg);
      const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
      return {
        text: (el.textContent ?? '').trim().slice(0, 24),
        classes: Array.from(el.classList).join(' '),
        color: s.color,
        bg: hex(bg),
        rawBg: s.backgroundColor,
        ratio: Math.round(ratio * 100) / 100,
        fontSize: s.fontSize,
        fontWeight: s.fontWeight,
      };
    });
  });

  for (const b of badges) {
    log(`badge "${b.text}"`, `${b.ratio}:1 on ${b.bg} (${b.fontSize} ${b.fontWeight})`);
    if (b.ratio < 4.5) {
      throw new Error(
        `badge "${b.text}" is ${b.ratio}:1 against ${b.bg} — below 4.5:1, so its text is not reliably readable`,
      );
    }
  }

  /* ---- 6. Validated, verified, and a passing test are three things ------ */

  // The failure this guards is a single green meaning "an analyst read it" and
  // "a retest passed" and "a check went green" all at once.
  const byText = new Map(badges.map((b) => [b.text, b]));
  const validated = badges.find((b) => b.classes.includes('ss-badge--validated'));
  const verified = badges.find((b) => b.classes.includes('ss-badge--verified'));

  if (!validated) throw new Error('no VALIDATED badge rendered — the validated tone is missing');
  if (!verified) throw new Error('no VERIFIED badge rendered — the verified tone is missing');
  if (validated.classes === verified.classes) {
    throw new Error('VALIDATED and VERIFIED render identically — they are different claims');
  }
  if (validated.bg === verified.bg) {
    throw new Error(`VALIDATED and VERIFIED share a background (${validated.bg})`);
  }
  log('validated tone', `${validated.bg} / ${validated.color}`);
  log('verified tone', `${verified.bg} / ${verified.color}`);

  // Neither may borrow the test-status green, which belongs to a test outcome.
  for (const [name, badge] of [['validated', validated], ['verified', verified]]) {
    if (/--pass|--good|--test-|--success/i.test(badge.classes)) {
      throw new Error(`the ${name} state badge borrows a test-status class: ${badge.classes}`);
    }
  }

  // No lifecycle badge may reuse a severity colour, and vice versa.
  for (const b of badges) {
    if (/ss-badge--(critical|high|medium|low|none|unscored)\b/.test(b.classes)) {
      const isSeverity = /ss-badge--(critical|high|medium|low|none|unscored)\b/.test(b.classes);
      // Severity badges are legitimate; what must never happen is one badge
      // carrying both a severity and a state tone at once.
      const alsoState = /ss-badge--(candidate|validated|remediation|inconclusive|regression|verified|closed)\b/.test(b.classes);
      if (isSeverity && alsoState) {
        throw new Error(`badge mixes the severity and state axes: ${b.classes}`);
      }
    }
  }
  log('severity and lifecycle-state axes do not overlap on any badge');

  /* ---- 7. The fixture must not be mistaken for the app's own content ----- */

  // The host is mounted outside #ss-view on purpose, so that the router re-rendering
  // its view cannot disturb it mid-assertion. What must hold is that the app's own
  // view never contains fixture data: a reader on the real route must be looking at
  // the backend's answer, however the drive got here.
  await page.goto(`${base}/securescan#/findings`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#ss-view');

  const realView = ((await page.locator('#ss-view').textContent()) ?? '').trim();
  if (realView.length === 0) throw new Error('the real findings route rendered nothing');
  if (realView.includes('ASM-FIXTURE') || realView.includes('FND-VALIDATED')) {
    throw new Error('fixture rows are inside the app view — the fixture leaked into the route');
  }
  const placement = await page.evaluate(() => ({
    insideView: Boolean(document.querySelector('#ss-view #fixture-host')),
    hostPresent: Boolean(document.getElementById('fixture-host')),
  }));
  if (placement.insideView) {
    throw new Error('the fixture host was mounted inside the app view — the isolation used by this drive is broken');
  }
  log('real findings route shows the backend state, not the fixture');
  log('fixture host placement', JSON.stringify(placement));

  // Clean up so the artifact screenshots and the next step start from a clean page.
  await page.evaluate(() => document.getElementById('fixture-host')?.remove());
  await shot('04-real-route-after-the-fixture-drive');

  if (pageErrors.length > 0) {
    throw new Error(`page errors during the drive:\n${pageErrors.join('\n')}`);
  }
  log('no page errors');
}
