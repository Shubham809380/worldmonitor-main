// @vitest-environment node

/**
 * Credit and quota engine — billing period resolution.
 *
 * The properties asserted here are the ones that decide whether a customer is
 * charged for the right cycle:
 *
 *  - **The provider owns the boundary.** A provider period is validated and
 *    passed through, never recomputed, so proration, trial and timezone are the
 *    provider's already-correct answer.
 *  - **A malformed provider period is a hard error.** Falling back to the
 *    calendar would hand a live subscriber a free month because of a provider
 *    bug — the expensive direction, and invisible until the provider fixed it.
 *  - **Periods tile.** Half-open `[start, end)` so rollover is total: an
 *    instant on a boundary belongs to exactly one period.
 *  - **Unbounded periods are refused.** A monthly grant re-granted against a
 *    boundary that never arrives is an unbounded liability.
 *  - **The calendar fallback is UTC-anchored**, so a caller cannot shift which
 *    cycle they are billed into by moving.
 */

import { describe, expect, test } from 'vitest';
import {
  BillingPeriodError,
  MAX_PROVIDER_PERIOD_MS,
  calendarPeriodUtc,
  containsInstant,
  isActiveSubscriptionStatus,
  operatorPeriod,
  providerPeriod,
  resolveBillingPeriod,
} from '../credits';

const DAY = 24 * 60 * 60 * 1000;

describe('calendarPeriodUtc', () => {
  test('covers the whole of the month containing `at`', () => {
    const at = Date.UTC(2026, 9, 15, 12, 0, 0);
    const period = calendarPeriodUtc(at);

    expect(period.start).toBe(Date.UTC(2026, 9, 1));
    expect(period.end).toBe(Date.UTC(2026, 10, 1));
    expect(period.source).toBe('CALENDAR_UTC');
  });

  test('December rolls into the following January without a special case', () => {
    const period = calendarPeriodUtc(Date.UTC(2026, 11, 25));
    expect(period.start).toBe(Date.UTC(2026, 11, 1));
    expect(period.end).toBe(Date.UTC(2027, 0, 1));
  });

  test("is UTC-anchored, so the caller's own timezone cannot move the boundary", () => {
    // 1 Oct 2026 00:30 UTC is 30 September for a UTC+4 observer. The period
    // must still be October: anchoring to the caller's zone would let them
    // shift which cycle they are billed into.
    const period = calendarPeriodUtc(Date.UTC(2026, 9, 1, 0, 30));
    expect(period.start).toBe(Date.UTC(2026, 9, 1));
  });

  test('is half-open so consecutive months tile without overlap or gaps', () => {
    const october = calendarPeriodUtc(Date.UTC(2026, 9, 15));
    const november = calendarPeriodUtc(Date.UTC(2026, 10, 15));
    expect(october.end).toBe(november.start);
  });

  test('handles a leap day without hand-written day arithmetic', () => {
    const period = calendarPeriodUtc(Date.UTC(2024, 1, 29));
    expect(period.start).toBe(Date.UTC(2024, 1, 1));
    expect(period.end).toBe(Date.UTC(2024, 2, 1));
  });

  test('rejects a non-finite instant rather than producing a nonsense period', () => {
    expect(() => calendarPeriodUtc(Number.NaN)).toThrow(BillingPeriodError);
    expect(() => calendarPeriodUtc(Number.POSITIVE_INFINITY)).toThrow(BillingPeriodError);
  });
});

describe('providerPeriod', () => {
  test('passes a provider period through unchanged', () => {
    const period = providerPeriod({
      periodStart: Date.UTC(2026, 9, 1),
      periodEnd: Date.UTC(2026, 10, 1),
      status: 'active',
    });
    expect(period.source).toBe('PROVIDER');
    expect(period.start).toBe(Date.UTC(2026, 9, 1));
  });

  test('accepts an annual period', () => {
    expect(() =>
      providerPeriod({
        periodStart: Date.UTC(2026, 0, 1),
        periodEnd: Date.UTC(2027, 0, 1),
        status: 'active',
      }),
    ).not.toThrow();
  });

  test('rejects a period longer than the maximum instead of granting against it forever', () => {
    expect(() =>
      providerPeriod({
        periodStart: Date.UTC(2026, 0, 1),
        periodEnd: Date.UTC(2036, 0, 1),
        status: 'active',
      }),
    ).toThrow(/maximum/);
  });

  test('accepts a period exactly at the maximum', () => {
    expect(() =>
      providerPeriod({
        periodStart: 1,
        periodEnd: 1 + MAX_PROVIDER_PERIOD_MS,
        status: 'active',
      }),
    ).not.toThrow();
  });

  test('rejects a period one millisecond over the maximum', () => {
    expect(() =>
      providerPeriod({
        periodStart: 1,
        periodEnd: 2 + MAX_PROVIDER_PERIOD_MS,
        status: 'active',
      }),
    ).toThrow(/maximum/);
  });

  test('rejects an inverted period', () => {
    expect(() =>
      providerPeriod({
        periodStart: Date.UTC(2026, 10, 1),
        periodEnd: Date.UTC(2026, 9, 1),
        status: 'active',
      }),
    ).toThrow(/must be after start/);
  });

  test('rejects a zero-length period', () => {
    const t = Date.UTC(2026, 9, 1);
    expect(() => providerPeriod({ periodStart: t, periodEnd: t, status: 'active' })).toThrow(
      /must be after start/,
    );
  });

  test('rejects a non-positive start', () => {
    expect(() => providerPeriod({ periodStart: 0, periodEnd: 1000, status: 'active' })).toThrow(
      /positive epoch/,
    );
  });

  test('rejects a non-finite boundary', () => {
    expect(() =>
      providerPeriod({
        periodStart: Number.NaN,
        periodEnd: Date.UTC(2026, 10, 1),
        status: 'active',
      }),
    ).toThrow(/finite/);
  });

  test('does not treat a non-active subscription as an invalid period', () => {
    // A lapsed subscription still has a real period. Reporting it as corrupt
    // would conflate "lapsed" with "malformed", which have different remedies.
    const period = providerPeriod({
      periodStart: Date.UTC(2026, 9, 1),
      periodEnd: Date.UTC(2026, 10, 1),
      status: 'expired',
    });
    expect(period.source).toBe('PROVIDER');
  });
});

describe('operatorPeriod', () => {
  test('pins a contract that outlives the provider maximum', () => {
    const period = operatorPeriod(Date.UTC(2026, 0, 1), Date.UTC(2029, 0, 1));
    expect(period.source).toBe('OPERATOR');
  });

  test('still rejects an inverted operator period', () => {
    expect(() => operatorPeriod(2000, 1000)).toThrow(BillingPeriodError);
  });
});

describe('resolveBillingPeriod', () => {
  test('prefers the provider period when a subscription exists', () => {
    const period = resolveBillingPeriod({
      at: Date.UTC(2026, 9, 15),
      subscription: {
        periodStart: Date.UTC(2026, 9, 5),
        periodEnd: Date.UTC(2026, 10, 5),
        status: 'active',
      },
    });
    expect(period.source).toBe('PROVIDER');
    expect(period.start).toBe(Date.UTC(2026, 9, 5));
  });

  test('falls back to the calendar only when there is no subscription', () => {
    const period = resolveBillingPeriod({
      at: Date.UTC(2026, 9, 15),
      subscription: null,
    });
    expect(period.source).toBe('CALENDAR_UTC');
  });

  test('propagates a malformed provider period instead of falling back to the calendar', () => {
    expect(() =>
      resolveBillingPeriod({
        at: Date.UTC(2026, 9, 15),
        subscription: {
          periodStart: Date.UTC(2026, 10, 1),
          periodEnd: Date.UTC(2026, 9, 1),
          status: 'active',
        },
      }),
    ).toThrow(BillingPeriodError);
  });
});

describe('containsInstant', () => {
  const period = {
    start: Date.UTC(2026, 9, 1),
    end: Date.UTC(2026, 10, 1),
    source: 'CALENDAR_UTC' as const,
  };

  test('includes the start and excludes the end', () => {
    expect(containsInstant(period, period.start)).toBe(true);
    expect(containsInstant(period, period.end)).toBe(false);
  });

  test('an instant exactly on a boundary belongs to the later period', () => {
    const next = calendarPeriodUtc(period.end);
    expect(containsInstant(period, period.end)).toBe(false);
    expect(containsInstant(next, period.end)).toBe(true);
  });

  test('covers the full interior', () => {
    expect(containsInstant(period, period.start + DAY)).toBe(true);
    expect(containsInstant(period, period.end - 1)).toBe(true);
  });
});

describe('isActiveSubscriptionStatus', () => {
  test('grants service only for statuses that grant it', () => {
    expect(isActiveSubscriptionStatus('active')).toBe(true);
    expect(isActiveSubscriptionStatus('trialing')).toBe(true);
  });

  test('does not grant service for a lapsed subscription', () => {
    for (const status of ['on_hold', 'expired', 'cancelled', 'past_due', 'suspended']) {
      expect(isActiveSubscriptionStatus(status)).toBe(false);
    }
  });

  test('does not grant service for a status it has never heard of', () => {
    // An unrecognised status is not a grant. Defaulting open here would let a
    // renamed provider state silently enable service.
    expect(isActiveSubscriptionStatus('some_future_status')).toBe(false);
  });
});
