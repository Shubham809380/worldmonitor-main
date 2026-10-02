/**
 * Audit Center routing and rendering guard.
 *
 * The audit chain was being written and verified server-side with no reader at
 * all, so this surface is new. Three things are pinned here because each one is
 * a way the page could quietly become untrustworthy:
 *
 *  1. **The route carries the assessment id.** The chain is assessment-scoped,
 *     so a route that drops or mis-parses the id would render a chooser with no
 *     explanation, or — worse — attribute one assessment's entries to another.
 *  2. **Denials stay visible.** A filter or a default view that showed only
 *     `ALLOWED` entries would turn an audit log into a list of successes. The
 *     count of denied entries is asserted against the fixture.
 *  3. **Stored text is data, not markup.** `detail`, `reasonCode`, and
 *     `sourceIp` are server-recorded strings that can contain an attacker-chosen
 *     target name. They must land as text.
 *
 * The server is stubbed rather than reached, so this proves what the page does
 * with a *response*; the refusal of a non-admin is asserted by rendering the
 * failure path, not by re-implementing `authorize` here.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';

import { hrefFor, parseRoute, ROUTES } from '@/securescan/routing';
import { renderAudit } from '@/securescan/pages/audit';
import { mount } from '@/securescan/components/dom';
import type {
  AssessmentListReadModel,
  AuditEntryReadModel,
  AuditVerifyReadModel,
  Result,
  ResultFailure,
} from '@/securescan/services/api';

const listMyAssessments = vi.fn();
const listAudit = vi.fn();
const verifyAudit = vi.fn();

vi.mock('@/securescan/services/api', () => ({
  listMyAssessments: (...args: unknown[]) => listMyAssessments(...args),
  listAudit: (...args: unknown[]) => listAudit(...args),
  verifyAudit: (...args: unknown[]) => verifyAudit(...args),
}));

const ASSESSMENT_ID = 'ASM-2026-0001';

const ASSESSMENTS: AssessmentListReadModel = {
  role: 'ADMIN',
  assessments: [
    {
      assessmentId: ASSESSMENT_ID,
      name: 'Payments edge estate',
      state: 'ACTIVE',
      ownerUserId: 'usr_owner',
      latestRunId: 'RUN-1',
      abortReason: null,
      updatedAt: 1_767_225_600_000,
      createdAt: 1_767_139_200_000,
    },
  ],
};

function entry(overrides: Partial<AuditEntryReadModel> = {}): AuditEntryReadModel {
  return {
    seq: 1,
    actorUserId: 'usr_owner',
    actorRole: 'ADMIN',
    action: 'assessment.created',
    resourceType: 'assessment',
    resourceId: ASSESSMENT_ID,
    outcome: 'ALLOWED',
    reasonCode: 'OK',
    detail: '',
    sourceUserAgent: 'convextest',
    sourceIp: '203.0.113.7',
    at: 1_767_225_600_000,
    hash: 'a'.repeat(64),
    ...overrides,
  };
}

const ENTRIES: AuditEntryReadModel[] = [
  entry({ seq: 1 }),
  entry({
    seq: 2,
    actorUserId: 'usr_viewer',
    actorRole: 'VIEWER',
    action: 'finding.transition',
    outcome: 'DENIED',
    reasonCode: 'ROLE_FORBIDDEN',
    at: 1_767_225_601_000,
  }),
  entry({
    seq: 3,
    actorRole: 'SECURITY_ANALYST',
    action: 'finding.retest',
    detail: 'retest passed against <img src=x onerror=alert(1)>',
    at: 1_767_225_602_000,
  }),
];

const INTACT: AuditVerifyReadModel = {
  assessmentId: ASSESSMENT_ID,
  intact: true,
  problems: [],
  entryCount: 3,
  headHash: 'c'.repeat(64),
};

const BROKEN: AuditVerifyReadModel = {
  assessmentId: ASSESSMENT_ID,
  intact: false,
  problems: ['entry 2 hash does not match its content', 'head hash does not match entry 3'],
  entryCount: 3,
  headHash: 'c'.repeat(64),
};

function ok<T>(value: T): Result<T> {
  return { ok: true, value };
}

function fail(kind: ResultFailure['kind']): ResultFailure {
  return { ok: false, kind, message: 'refused' };
}

function render(params: Record<string, string> = {}): Promise<HTMLElement> {
  const view = renderAudit(params);
  return view.then((rendered) => {
    const host = document.createElement('div');
    mount(host, rendered.body);
    if (rendered.activate) rendered.activate(host as HTMLElement);
    return host;
  });
}

beforeEach(() => {
  listMyAssessments.mockReset().mockResolvedValue(ok(ASSESSMENTS));
  listAudit.mockReset().mockResolvedValue(ok(ENTRIES));
  verifyAudit.mockReset().mockResolvedValue(ok(INTACT));
});

describe('audit routing', () => {
  it('parses the assessment id out of the hash', () => {
    const route = parseRoute(`#/audit?assessmentId=${ASSESSMENT_ID}`);
    expect(route.name).toBe('audit');
    expect(route.params.assessmentId).toBe(ASSESSMENT_ID);
    expect(route.title).toBe('Audit Center');
  });

  it('builds an href that survives the id round-trip', () => {
    const href = hrefFor('audit', { assessmentId: ASSESSMENT_ID });
    expect(href).toBe(`#/audit?assessmentId=${ASSESSMENT_ID}`);
    expect(parseRoute(href).params.assessmentId).toBe(ASSESSMENT_ID);
  });

  it('percent-encodes the assessment id rather than trusting it', () => {
    // The id is server-issued, but the value arrives through the URL and the
    // encoder is what stops a crafted query from smuggling a second parameter.
    const href = hrefFor('audit', { assessmentId: 'a/../b?x=1' });
    expect(href).toContain('%2F');
    expect(parseRoute(href).params.assessmentId).toBe('a/../b?x=1');
  });

  it('is registered as an admin surface in the route table', () => {
    expect(ROUTES.audit?.adminOnly).toBe(true);
  });

  it('falls back to the dashboard rather than throwing on an unknown view', () => {
    expect(parseRoute('#/nope').name).toBe('unknown');
    expect(parseRoute('#/nope').heading).toBe(ROUTES.dashboard?.heading);
  });
});

describe('audit centre without a chosen assessment', () => {
  it('asks which assessment to open instead of rendering an empty chain', async () => {
    const host = await render();
    expect(host.querySelector('#ss-audit-picker')).not.toBeNull();
    expect(host.querySelector('#ss-audit-table')).toBeNull();
    expect(host.textContent).toContain('NO ASSESSMENTS'.replace('NO ASSESSMENTS', 'Payments edge estate'));
  });

  it('never calls the chain queries before an assessment is chosen', async () => {
    await render();
    expect(listAudit).not.toHaveBeenCalled();
    expect(verifyAudit).not.toHaveBeenCalled();
  });

  it('treats an unreadable assessment id as a bad link, not a server outage', async () => {
    const host = await render({ assessmentId: 'ASM-does-not-exist' });
    expect(host.querySelector('#ss-audit-picker')).not.toBeNull();
    expect(host.textContent).not.toContain('BACKEND UNAVAILABLE');
    expect(listAudit).not.toHaveBeenCalled();
  });
});

describe('audit chain rendering', () => {
  it('renders one row per chain entry and reports the count', async () => {
    const host = await render({ assessmentId: ASSESSMENT_ID });
    const rows = host.querySelectorAll('#ss-audit-table tbody tr');
    expect(rows).toHaveLength(3);
    expect(host.textContent).toContain('Chain (3)');
  });

  it('shows denied entries as well as allowed ones', async () => {
    const host = await render({ assessmentId: ASSESSMENT_ID });
    expect(host.textContent).toContain('Allowed 2');
    expect(host.textContent).toContain('Denied 1');
    expect(host.querySelectorAll('#ss-audit-table tbody tr[data-outcome="DENIED"]')).toHaveLength(1);
  });

  it('filters by outcome without touching what the server returned', async () => {
    const host = await render({ assessmentId: ASSESSMENT_ID });
    const deniedButton = host.querySelector<HTMLButtonElement>('[data-outcome-filter="DENIED"]');
    deniedButton?.click();

    const rows = Array.from(host.querySelectorAll<HTMLTableRowElement>('#ss-audit-table tbody tr'));
    const visible = rows.filter((row) => !row.hidden);
    expect(visible).toHaveLength(1);
    expect(visible[0]?.dataset.outcome).toBe('DENIED');
    // The filter is a view over records already fetched; it must not re-query.
    expect(listAudit).toHaveBeenCalledTimes(1);
  });

  it('marks exactly one filter as pressed at a time', async () => {
    const host = await render({ assessmentId: ASSESSMENT_ID });
    host.querySelector<HTMLButtonElement>('[data-outcome-filter="DENIED"]')?.click();
    const pressed = Array.from(host.querySelectorAll<HTMLButtonElement>('[data-outcome-filter]')).filter(
      (button) => button.getAttribute('aria-pressed') === 'true',
    );
    expect(pressed).toHaveLength(1);
    expect(pressed[0]?.dataset.outcomeFilter).toBe('DENIED');
  });

  it('renders stored text as data, not markup', async () => {
    const host = await render({ assessmentId: ASSESSMENT_ID });
    // The payload is inert: no element was constructed from it...
    expect(host.querySelector('img')).toBeNull();
    // ...and the angle brackets are entity-encoded in the serialised form.
    // Asserting on the bare substring `onerror=` would be wrong, because the
    // escaped text legitimately still contains those characters.
    expect(host.innerHTML).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect(host.innerHTML).not.toContain('<img src=x');
    // It is still fully readable as the text an analyst recorded.
    expect(host.textContent).toContain('<img src=x onerror=alert(1)>');
  });
});

describe('chain integrity', () => {
  it('states a verified chain plainly', async () => {
    const host = await render({ assessmentId: ASSESSMENT_ID });
    expect(host.textContent).toContain('Chain verified');
    expect(host.textContent).not.toContain('Chain verification failed');
  });

  it('refuses to present a broken chain as a trusted record', async () => {
    verifyAudit.mockResolvedValue(ok(BROKEN));
    const host = await render({ assessmentId: ASSESSMENT_ID });
    expect(host.textContent).toContain('Chain verification failed');
    for (const problem of BROKEN.problems) {
      expect(host.textContent).toContain(problem);
    }
  });

  it('warns when the fetch did not reach the start of a longer chain', async () => {
    verifyAudit.mockResolvedValue(ok({ ...INTACT, entryCount: 900 }));
    const host = await render({ assessmentId: ASSESSMENT_ID });
    expect(host.textContent).toContain('Showing the first entries');
    expect(host.textContent).toContain('900');
  });
});

describe('server refusals', () => {
  it('renders the admin refusal rather than hiding the route', async () => {
    listAudit.mockResolvedValue(fail('forbidden'));
    const host = await render({ assessmentId: ASSESSMENT_ID });
    expect(host.textContent).toContain('NOT PERMITTED');
  });

  it('names a missing membership for an account that has none', async () => {
    listMyAssessments.mockResolvedValue(fail('no_membership'));
    const host = await render();
    expect(host.textContent).toContain('NO SECURESCAN MEMBERSHIP');
  });

  it('does not present a backend outage as an empty chain', async () => {
    verifyAudit.mockResolvedValue(fail('unavailable'));
    const host = await render({ assessmentId: ASSESSMENT_ID });
    expect(host.textContent).toContain('BACKEND UNAVAILABLE');
    expect(host.textContent).not.toContain('NO ENTRIES RECORDED');
  });
});
