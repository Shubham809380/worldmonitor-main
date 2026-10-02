/**
 * Lifecycle handoff on the finding detail page — real modules, fixture data.
 *
 * READ THIS BEFORE READING THE RESULT. As in
 * `securescan-fixture-filter-badges.mjs`, the rows here are a fixture handed to the
 * real `renderFindingDetail`. `VITE_CONVEX_URL` is unset, so the real Convex client
 * is null and no finding can be fetched. What is real here is the page module, the
 * lifecycle state machine it consults (`finding-lifecycle.ts`), the stylesheet, and
 * the DOM the reader gets.
 *
 * Why this surface is worth driving at all: the handoff is a promise about who is
 * allowed to resolve a finding. A reader in REMEDIATION must be told that recording
 * a remediation is not the same as fixing it, and a reader in RETEST_REQUIRED must
 * be told that nothing they can click here will mark it verified. If those panels
 * ever render the wrong form, or no explanation at all, a user is left with either a
 * dead end or the belief that they have closed a vulnerability that a retest will
 * later reopen as a regression.
 *
 * Not proven here, and not claimed: that the backend enforces any of this. The
 * browser can only show what it is told, and with no server the authoritative half
 * of the contract is untested. What is tested is that the browser does not
 * contradict it.
 */
export default async function ({ page, base, shot, log }) {
  const pageErrors = [];
  page.on('pageerror', (err) => pageErrors.push(String(err).slice(0, 300)));

  /* ---- 1. Mount the real detail page for one state at a time ------------- */

  await page.goto(`${base}/securescan#/findings/FND-FIXTURE`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#ss-view');

  // `renderFindingDetail` returns a view object, not bare markup, because the page
  // can also need an activate step. Both halves are used here.
  const render = async (state) =>
    page.evaluate(async (s) => {
      const detail = await import('/src/securescan/pages/finding-detail.ts');
      const dom = await import('/src/securescan/components/dom.ts');
      const lifecycle = await import('/src/securescan/pages/finding-lifecycle.ts');

      const row = {
        findingId: 'FND-FIXTURE',
        assessmentId: 'ASM-FIXTURE',
        runId: 'RUN-FIXTURE',
        title: 'Fixture finding for lifecycle check',
        category: 'Injection',
        component: 'checkout',
        node: null,
        boundary: 'internet',
        control: 'A03-2021',
        severity: 'HIGH',
        severityLabel: 'High',
        confidence: 'HIGH',
        state: s,
        stateLabel: s.replace(/_/g, ' ').toLowerCase(),
        description: 'A description that says nothing about a real system.',
        rootCause: 'Root cause.',
        rootCauseId: 'RC-FIXTURE',
        businessImpact: 'Impact.',
        risk: null,
        affectedEndpoints: ['/checkout'],
        fingerprint: 'fp-fixture',
        historicalStatus: 'OPEN',
        remediationSummary: s === 'REMEDIATION' ? 'A remediation was recorded.' : null,
        remediationRecordedAt: s === 'REMEDIATION' ? 1750000000000 : null,
        lastRetestState: null,
        lastRetestedAt: null,
        createdAt: 1750000000000,
        updatedAt: 1750000000000,
      };

      const view = detail.renderFindingDetail(
        { role: 'ASSURER', finding: row, evidence: [], tests: [], events: [] },
        {},
      );

      document.getElementById('fixture-host')?.remove();
      const host = document.createElement('div');
      host.id = 'fixture-host';
      document.body.appendChild(host);
      dom.mount(host, view.body);
      view.activate?.(host);

      const text = (host.textContent ?? '').replace(/\s+/g, ' ').trim();
      const note = host.querySelector('[data-next-step]');
      return {
        state: s,
        offered: lifecycle.offeredTransitions(s),
        retestEligible: lifecycle.retestEligible(s),
        remediationPrecursor: lifecycle.remediationPrecursor(s),
        hasRemediationForm: Boolean(host.querySelector('#ss-fd-remediation')),
        hasRetestForm: Boolean(host.querySelector('#ss-fd-retest')),
        hasTransitionForm: Boolean(host.querySelector('#ss-fd-transition')),
        note: note ? (note.textContent ?? '').replace(/\s+/g, ' ').trim() : null,
        noteRole: note ? note.getAttribute('role') : null,
        noteFor: note ? note.getAttribute('data-next-step') : null,
        // A promise the reader can act on, or a dead end. Counted so "no panels at
        // all" is visible rather than inferred from an empty string.
        formCount: host.querySelectorAll('form.ss-form').length,
        textLength: text.length,
        hasAnyForm: host.querySelectorAll('form').length > 0,
      };
    }, state);

  /* ---- 2. VALIDATED: the remediation is recorded from here --------------- */

  // The remediation form belongs to the states that can *enter* REMEDIATION. Once a
  // finding is in REMEDIATION the remediation is already on the record, so offering
  // the form again would invite a second, contradictory one.
  const validated = await render('VALIDATED');
  log('VALIDATED', JSON.stringify({
    offered: validated.offered,
    remediationForm: validated.hasRemediationForm,
    retestForm: validated.hasRetestForm,
  }));
  if (!validated.hasRemediationForm) {
    throw new Error('VALIDATED does not offer the remediation form — a confirmed weakness has nowhere to record a fix');
  }

  /* ---- 3. REMEDIATION: a recorded fix is not a verified fix -------------- */

  const remediation = await render('REMEDIATION');
  log('REMEDIATION', JSON.stringify({
    offered: remediation.offered,
    remediationForm: remediation.hasRemediationForm,
    retestForm: remediation.hasRetestForm,
    transitionForm: remediation.hasTransitionForm,
  }));

  if (remediation.hasRemediationForm) {
    throw new Error('REMEDIATION offers a second remediation form; the remediation is already recorded');
  }
  if (remediation.hasRetestForm) {
    throw new Error('REMEDIATION offers the retest form before the finding is queued for one');
  }
  if (!remediation.hasTransitionForm) {
    throw new Error('REMEDIATION offers no way forward — the reader is stranded mid-lifecycle');
  }
  if (!remediation.note) {
    throw new Error('REMEDIATION renders no explanation of what happens next');
  }
  if (remediation.noteRole !== 'note') {
    throw new Error(`the handoff note is not announced as a note (role=${remediation.noteRole})`);
  }
  if (remediation.noteFor !== 'REMEDIATION') {
    throw new Error(`the handoff note is attributed to ${remediation.noteFor}, not the state it explains`);
  }
  // The specific promise: this state is not a resolution, and the reader is told so.
  if (!/retest/i.test(remediation.note)) {
    throw new Error(`the REMEDIATION note never mentions a retest: "${remediation.note}"`);
  }
  if (!/RETEST_REQUIRED/.test(remediation.note)) {
    throw new Error(`the REMEDIATION note does not name the state it hands off to: "${remediation.note}"`);
  }
  log('REMEDIATION note', remediation.note);

  /* ---- 4. RETEST_REQUIRED: only the engine can resolve it ---------------- */

  const retest = await render('RETEST_REQUIRED');
  log('RETEST_REQUIRED', JSON.stringify({
    offered: retest.offered,
    retestForm: retest.hasRetestForm,
    transitionForm: retest.hasTransitionForm,
  }));

  if (!retest.hasRetestForm) {
    throw new Error('RETEST_REQUIRED does not offer the retest form — nothing can move this finding on');
  }
  if (!retest.note) {
    throw new Error('RETEST_REQUIRED renders no explanation of who resolves it');
  }
  if (!/assessment engine|engine/i.test(retest.note)) {
    throw new Error(`the RETEST_REQUIRED note does not say the engine decides: "${retest.note}"`);
  }
  if (!/PASS|VERIFIED/.test(retest.note) || !/FAIL|REGRESSION/.test(retest.note)) {
    throw new Error(
      `the RETEST_REQUIRED note does not state both outcomes, so a reader cannot tell what a retest means: "${retest.note}"`,
    );
  }
  // The note promises "nothing here can shortcut that", so the page must actually
  // offer no transition at all. An empty offer list is the strongest form of that
  // guarantee: there is no control to click, not merely no useful one.
  if (retest.offered.length !== 0) {
    throw new Error(
      `RETEST_REQUIRED offers transitions to ${retest.offered.join(', ')}; a reader could mark a finding resolved without a retest`,
    );
  }
  if (retest.hasTransitionForm) {
    throw new Error('RETEST_REQUIRED renders a transition form while no transition is legal');
  }
  log('RETEST_REQUIRED offers no transitions at all', '(empty)');
  log('RETEST_REQUIRED note', retest.note);

  /* ---- 5. The page and the state machine must agree, for every state ----- */

  // Which states count as "closed" is a judgement call the module already makes
  // (ACCEPTED_RISK, for instance, is reopenable into remediation by design), so
  // rather than hardcoding a list and guessing wrong, this checks the invariant
  // that actually matters: nothing is rendered that the state machine says is
  // illegal, and no state is told about a next step that does not exist.
  //
  // That is the bug class worth catching. A form offered in a state that forbids it
  // is a write the server must reject; a note naming a transition that is not
  // offered sends a reader looking for a control that was never rendered.

  const allStates = await page.evaluate(async () => {
    const findings = await import('/src/securescan/pages/findings.ts');
    return [...findings.STATE_OPTIONS];
  });

  const disagreements = [];
  const emptyStates = [];
  const notes = [];

  for (const state of allStates) {
    const view = await render(state);

    if (view.textLength === 0) {
      emptyStates.push(state);
      continue;
    }
    if (view.hasRemediationForm !== view.remediationPrecursor) {
      disagreements.push(
        `${state}: remediation form ${view.hasRemediationForm ? 'shown' : 'absent'} but remediationPrecursor=${view.remediationPrecursor}`,
      );
    }
    if (view.hasRetestForm !== view.retestEligible) {
      disagreements.push(
        `${state}: retest form ${view.hasRetestForm ? 'shown' : 'absent'} but retestEligible=${view.retestEligible}`,
      );
    }
    if (view.hasTransitionForm !== view.offered.length > 0) {
      disagreements.push(
        `${state}: transition form ${view.hasTransitionForm ? 'shown' : 'absent'} but offered=[${view.offered.join(', ')}]`,
      );
    }
    if (view.note) {
      notes.push(`${state}: ${view.note}`);
      // A note that promises a specific state must promise one the reader can
      // actually reach from here.
      const promised = /RETEST_REQUIRED/.test(view.note);
      if (promised && !view.offered.includes('RETEST_REQUIRED')) {
        disagreements.push(
          `${state}: the note points at RETEST_REQUIRED, which is not offered from here`,
        );
      }
    }

    // A state with no way forward and nothing outstanding must say so by saying
    // nothing at all, not by rendering an empty panel or an invented step.
    const outstanding =
      view.hasRemediationForm || view.hasRetestForm || view.hasTransitionForm || view.formCount > 0;
    if (!outstanding && view.note !== null) {
      disagreements.push(`${state}: has no outstanding work but still renders a next step`);
    }
  }

  if (emptyStates.length > 0) {
    throw new Error(`states that render nothing:\n${emptyStates.join('\n')}`);
  }
  if (disagreements.length > 0) {
    throw new Error(
      `the page and finding-lifecycle.ts disagree:\n${disagreements.join('\n')}`,
    );
  }
  log('all states render content', allStates.join(', '));
  log('page and state machine agree across', `${allStates.length} states`);
  for (const note of notes) log('handoff note', note);

  // A state whose work is done must not render a next step. VERIFIED and the
  // judgement-closed states are the ones where that would mislead.
  for (const closed of ['VERIFIED', 'FALSE_POSITIVE', 'ACCEPTED_RISK', 'INFORMATIONAL', 'FIXED']) {
    const view = await render(closed);
    log(closed, JSON.stringify({
      offered: view.offered,
      retestForm: view.hasRetestForm,
      remediationForm: view.hasRemediationForm,
      hasNote: view.note !== null,
    }));
    if (view.note !== null) {
      throw new Error(`${closed} renders a "next step" note for a closed finding: "${view.note}"`);
    }
  }
  // VERIFIED is closed yet still re-checkable, so a regressed fix can be caught.
  const verified = await render('VERIFIED');
  if (!verified.hasRetestForm) {
    throw new Error(
      'VERIFIED does not offer a retest, so a fix that later regresses cannot be re-checked from the finding',
    );
  }
  log('VERIFIED stays re-checkable for a fix that later regresses');
  await shot('01-lifecycle-closed-states-have-no-false-next-step');

  /* ---- 6. The forms are real forms, not decoration ----------------------- */

  const formShape = await page.evaluate(() => {
    const host = document.getElementById('fixture-host');
    return Array.from(host.querySelectorAll('form.ss-form')).map((f) => ({
      id: f.id,
      method: (f.getAttribute('method') ?? '(none)').toLowerCase(),
      // A form that GETs would reload the document and write to location.search,
      // which is the same class of bug the findings filter had.
      action: f.getAttribute('action'),
      hasSubmit: Boolean(f.querySelector('button[type="submit"], button:not([type])')),
    }));
  });
  for (const form of formShape) {
    log(`form #${form.id}`, `method=${form.method}, action=${form.action ?? '(none)'}, submit=${form.hasSubmit}`);
    if (form.hasSubmit === false) {
      throw new Error(`form #${form.id} has no submit control — it cannot be used`);
    }
    if (form.method === 'get' || form.action) {
      throw new Error(
        `form #${form.id} is a ${form.method.toUpperCase()} form with action=${form.action}; a mutation must not navigate`,
      );
    }
  }

  await shot('02-lifecycle-forms-are-real');
  await page.evaluate(() => document.getElementById('fixture-host')?.remove());

  if (pageErrors.length > 0) {
    throw new Error(`page errors during the drive:\n${pageErrors.join('\n')}`);
  }
  log('no page errors');
}
