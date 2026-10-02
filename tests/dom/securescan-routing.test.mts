/**
 * SecureScan routing and link helpers.
 *
 * These are the only places a server-issued id becomes a URL, so the rules that
 * matter are: the path wins over the query, the reserved `new` segment cannot
 * shadow a real assessment, and a class attribute stays an attribute instead of
 * becoming escaped text.
 */
import { describe, expect, it } from 'vitest';

import { html, mount } from '@/securescan/components/dom';
import { idLine, link } from '@/securescan/components/links';
import { formatTime } from '@/securescan/components/ui';
import { hrefFor, parseRoute } from '@/securescan/routing';

describe('route parsing', () => {
  it('lets the path win over the query for the same parameter', () => {
    // Regression: the query was read last, so `#/assessments/ASM-1?assessmentId=ASM-2`
    // rendered one assessment's heading and fetched the other's data.
    const route = parseRoute('#/assessments/ASM-1?assessmentId=ASM-2');
    expect(route.name).toBe('assessments-detail');
    expect(route.params.assessmentId).toBe('ASM-1');
  });

  it('applies the same rule to findings', () => {
    const route = parseRoute('#/findings/FND-1?findingId=FND-2');
    expect(route.name).toBe('findings-detail');
    expect(route.params.findingId).toBe('FND-1');
  });

  it('still accepts a filter that only exists in the query', () => {
    const route = parseRoute('#/findings?state=CANDIDATE&severity=HIGH');
    expect(route.name).toBe('findings');
    expect(route.params.state).toBe('CANDIDATE');
    expect(route.params.severity).toBe('HIGH');
  });

  it('reserves the "new" segment for the create route', () => {
    expect(parseRoute('#/assessments/new').name).toBe('assessments-new');
  });

  it('reaches an assessment whose id is the reserved word', () => {
    // Without the query fallback this id would be unaddressable: the create
    // route claims `new`, so the detail page could never be opened for it.
    const route = parseRoute('#/assessments?assessmentId=new');
    expect(route.name).toBe('assessments-detail');
    expect(route.params.assessmentId).toBe('new');
  });

  it('treats a bare assessments path with no id as the list', () => {
    expect(parseRoute('#/assessments').name).toBe('assessments');
  });

  it('reports an unrecognised path as unknown rather than the dashboard', () => {
    expect(parseRoute('#/nope').name).toBe('unknown');
  });

  it('survives a malformed percent-escape', () => {
    // A broken deep link must render a not-found view, not throw and blank the
    // shell.
    expect(() => parseRoute('#/assessments/%E0%A4%A')).not.toThrow();
    expect(parseRoute('#/assessments/%E0%A4%A').params.assessmentId).toBe('%E0%A4%A');
  });
});

describe('href construction', () => {
  it('encodes ids so a hostile id cannot become a scheme', () => {
    const href = hrefFor('findings-detail', { findingId: 'javascript:alert(1)' });
    expect(href).not.toContain('javascript:');
    expect(href).toContain('%3A');
  });

  it('emits one canonical URL for the create route', () => {
    expect(hrefFor('assessments-new')).toBe('#/assessments/new');
    expect(parseRoute(hrefFor('assessments-new')).name).toBe('assessments-new');
  });

  it('round-trips a detail route through hrefFor and parseRoute', () => {
    for (const [name, params, key] of [
      ['assessments-detail', { assessmentId: 'ASM 1/2' }, 'assessmentId'],
      ['findings-detail', { findingId: 'FND-1' }, 'findingId'],
    ] as const) {
      const route = parseRoute(hrefFor(name, params));
      expect(route.name).toBe(name);
      expect(route.params[key]).toBe(params[key]);
    }
  });

  it('routes a reserved-word assessment id away from the create page', () => {
    const href = hrefFor('assessments-detail', { assessmentId: 'new' });
    expect(href).not.toBe('#/assessments/new');
    expect(parseRoute(href).name).toBe('assessments-detail');
  });
});

describe('link rendering', () => {
  function render(label: string, className?: string): HTMLElement {
    const host = document.createElement('div');
    mount(host, link(label, 'findings', {}, className));
    return host;
  }

  it('applies a class as an attribute rather than as escaped text', () => {
    // Regression: the conditional was interpolated as a value, so `html`
    // escaped its quotes and the anchor rendered with no class at all.
    const anchor = render('Findings', 'ss-btn ss-btn--sm').querySelector('a');
    expect(anchor?.getAttribute('class')).toBe('ss-btn ss-btn--sm');
    expect(render('Findings', 'ss-btn').textContent).not.toContain('class=');
  });

  it('omits the attribute entirely when no class is given', () => {
    const anchor = render('Findings').querySelector('a');
    expect(anchor?.hasAttribute('class')).toBe(false);
  });

  it('cannot be broken out of the class attribute', () => {
    const anchor = render('x', 'a" onclick="alert(1)').querySelector('a');
    expect(anchor?.getAttribute('onclick')).toBeNull();
  });

  it('renders the id line with a separator', () => {
    const host = document.createElement('div');
    mount(host, idLine(['f_1', null, 'CSP', '']));
    expect(host.textContent).toBe('f_1 · CSP');
  });
});

describe('formatTime', () => {
  it('returns a dash rather than throwing on an out-of-range date', () => {
    // `Intl.DateTimeFormat#format` throws a RangeError on an invalid Date. A
    // single bad timestamp used to take the entire view down.
    expect(() => formatTime(8.64e15 + 1)).not.toThrow();
    expect(formatTime(8.64e15 + 1)).toBe('-');
    expect(formatTime(-8.64e15 - 1)).toBe('-');
  });

  it('still handles absent and non-finite values', () => {
    expect(formatTime(null)).toBe('-');
    expect(formatTime(undefined)).toBe('-');
    expect(formatTime(Number.NaN)).toBe('-');
    expect(formatTime(Number.POSITIVE_INFINITY)).toBe('-');
  });

  it('formats a real timestamp', () => {
    expect(formatTime(Date.parse('2026-09-01T12:00:00.000Z'))).toContain('2026');
  });
});

describe('SafeMarkup interop', () => {
  it('keeps raw markup raw and escapes interpolated strings', () => {
    const host = document.createElement('div');
    mount(host, html`<span>${'<b>x</b>'}</span>`);
    expect(host.querySelector('b')).toBeNull();
    expect(host.textContent).toBe('<b>x</b>');
  });
});
