import { describe, expect, it } from 'vitest';
import {
  DEFAULT_THRESHOLDS,
  evaluateBurnRate,
  evaluateDay,
  hoursToZero,
  learnBaseline,
  median,
  unitCost,
  type UsageSample,
} from '../detectors.js';

/**
 * Every figure below is real, taken from the Twilio account attacked in the
 * qrypt.chat SMS-pumping incident (2026-06/07). Daily rows for June and July
 * come from `Usage/Records/Daily`; pre-incident days are reconstructed from the
 * monthly aggregates, which is why they are round-ish but volume-accurate.
 *
 * The suite exists to pin down one behaviour above all: fire on June 29-30,
 * stay quiet on October 2025. October was genuinely expensive ($0.1844/msg)
 * and genuinely legitimate — real users on Indian, Nigerian and Sri Lankan
 * numbers. A detector that cannot tell those apart is useless in production,
 * because it either misses fraud or blocks a real market.
 */

// Ordinary pre-incident traffic: a handful of signups a day, mostly domestic
// with an international user mixed in.
const NORMAL_HISTORY: UsageSample[] = [
  { date: '2026-05-02', count: 3, cost: 0.025, destination: '1' },
  { date: '2026-05-06', count: 5, cost: 0.042, destination: '1' },
  { date: '2026-05-09', count: 2, cost: 0.017, destination: '1' },
  { date: '2026-05-14', count: 4, cost: 0.128, destination: '358' },
  { date: '2026-05-17', count: 6, cost: 0.05, destination: '1' },
  { date: '2026-05-21', count: 1, cost: 0.008, destination: '1' },
  { date: '2026-05-24', count: 8, cost: 0.19, destination: '91' },
  { date: '2026-05-28', count: 3, cost: 0.025, destination: '1' },
  { date: '2026-06-21', count: 9, cost: 2.8163, destination: '234' },
  { date: '2026-06-22', count: 2, cost: 0.0166, destination: '1' },
  { date: '2026-06-24', count: 1, cost: 0.3151, destination: '92' },
];

const baseline = learnBaseline(NORMAL_HISTORY);

describe('helpers', () => {
  it('computes a median that ignores outliers', () => {
    expect(median([1, 2, 3, 4, 500])).toBe(3);
    expect(median([2, 4])).toBe(3);
    expect(median([])).toBe(0);
  });

  it('derives unit cost and survives zero-count buckets', () => {
    expect(unitCost({ count: 283, cost: 93.31 })).toBeCloseTo(0.3297, 4);
    expect(unitCost({ count: 0, cost: 0 })).toBe(0);
  });

  it('treats provider-negative prices as spend', () => {
    // Twilio reports outbound price as a negative number.
    expect(unitCost({ count: 1, cost: -0.4588 })).toBeCloseTo(0.4588, 4);
  });
});

describe('baseline learning', () => {
  it('learns from clean history', () => {
    expect(baseline.samples).toBe(NORMAL_HISTORY.length);
    expect(baseline.dailyCount).toBeGreaterThan(0);
    expect(baseline.destinations).toContain('1');
    expect(baseline.destinations).toContain('358');
  });

  it('quarantines known-bad days so an attack cannot poison the baseline', () => {
    const poisoned = [
      ...NORMAL_HISTORY,
      { date: '2026-06-29', count: 237, cost: 78.95, destination: '380' },
      { date: '2026-06-30', count: 283, cost: 93.31, destination: '996' },
    ];

    const naive = learnBaseline(poisoned);
    const quarantined = learnBaseline(poisoned, new Set(['2026-06-29', '2026-06-30']));

    expect(quarantined.dailyCount).toBeLessThan(naive.dailyCount);
    expect(quarantined.destinations).not.toContain('996');
  });
});

describe('the June 29-30 attack — must fire', () => {
  it('flags 2026-06-30 as containable', () => {
    // Real: 283 messages, $93.31, overwhelmingly +996 / +380 / +770.
    const verdict = evaluateDay(
      [
        { date: '2026-06-30', count: 171, cost: 56.2, destination: '996' },
        { date: '2026-06-30', count: 112, cost: 37.11, destination: '380' },
      ],
      baseline,
    );

    expect(verdict.contain).toBe(true);
    expect(verdict.severity).toBe('critical');
    expect(verdict.spend).toBeCloseTo(93.31, 2);
    expect(verdict.hits.map((h) => h.detector)).toContain('volume');
  });

  it('flags 2026-06-29 as containable', () => {
    const verdict = evaluateDay(
      [{ date: '2026-06-29', count: 237, cost: 78.95, destination: '380' }],
      baseline,
    );

    expect(verdict.contain).toBe(true);
    expect(verdict.severity).toBe('critical');
  });

  it('flags the smaller 2026-07-27 wave too', () => {
    // Real: 26 messages, $8.5022 — an order of magnitude smaller than June,
    // and still must be caught.
    const verdict = evaluateDay(
      [
        { date: '2026-07-27', count: 10, cost: 4.59, destination: '996' },
        { date: '2026-07-27', count: 11, cost: 2.6, destination: '959' },
        { date: '2026-07-27', count: 5, cost: 1.31, destination: '358' },
      ],
      baseline,
    );

    expect(verdict.contain).toBe(true);
  });
});

describe('October 2025 legitimate traffic — must stay quiet', () => {
  it('does not recommend containment for expensive but real international users', () => {
    // Real month: 202 messages, $37.25, $0.1844/msg — roughly 7 a day to
    // destinations already in the baseline. Expensive, entirely genuine.
    const verdict = evaluateDay(
      [
        { date: '2025-10-14', count: 4, cost: 0.74, destination: '91' },
        { date: '2025-10-14', count: 3, cost: 0.55, destination: '234' },
      ],
      baseline,
    );

    expect(verdict.contain).toBe(false);
    expect(verdict.severity).not.toBe('critical');
  });

  it('stays quiet on an ordinary domestic day', () => {
    const verdict = evaluateDay(
      [{ date: '2026-05-30', count: 4, cost: 0.033, destination: '1' }],
      baseline,
    );

    expect(verdict.hits).toHaveLength(0);
    expect(verdict.contain).toBe(false);
  });

  it('ignores days below the noise floor', () => {
    const verdict = evaluateDay(
      [{ date: '2026-05-31', count: 1, cost: 0.4588, destination: '996' }],
      baseline,
    );

    // Single pricey message to a new destination is suspicious but not worth
    // waking anyone: under minDailySpend, so it is suppressed entirely.
    expect(verdict.contain).toBe(false);
  });

  it('needs corroboration before containing', () => {
    // A brand-new destination alone must never contain.
    const soloSignal = evaluateDay(
      [{ date: '2026-06-05', count: 5, cost: 0.05, destination: '49' }],
      baseline,
    );

    expect(soloSignal.hits.every((h) => h.detector === 'new_destination')).toBe(true);
    expect(soloSignal.contain).toBe(false);
  });
});

describe('burn rate', () => {
  it('projects time to zero', () => {
    expect(hoursToZero(17.93, 4.0)).toBeCloseTo(4.48, 2);
    expect(hoursToZero(17.93, 0)).toBe(Infinity);
  });

  it('stays silent when the balance is comfortable', () => {
    expect(evaluateBurnRate(500, 1, 6, false)).toBeNull();
  });

  it('escalates to critical when auto-recharge can draw on a card', () => {
    // The real account survived on luck: the balance hit zero and the attack
    // died. With auto-recharge on there is no such floor.
    const withRecharge = evaluateBurnRate(17.93, 4.0, 6, true);
    const withoutRecharge = evaluateBurnRate(17.93, 4.0, 6, false);

    expect(withRecharge?.severity).toBe('critical');
    expect(withoutRecharge?.severity).toBe('high');
    expect(withRecharge?.message).toContain('auto-recharge');
  });
});

describe('thresholds', () => {
  it('exposes tunable defaults', () => {
    expect(DEFAULT_THRESHOLDS.containSignals).toBe(2);
    expect(DEFAULT_THRESHOLDS.unitCostFactor).toBeGreaterThan(1);
  });

  it('respects a stricter containment requirement', () => {
    // A cheap-but-huge burst into an unseen market: volume + new_destination
    // fire, unit cost does not (domestic pricing). Exactly two signals, so
    // raising the bar to three flips containment off while the alert remains.
    const samples = [{ date: '2026-06-05', count: 200, cost: 1.66, destination: '44' }];

    const atDefault = evaluateDay(samples, baseline, DEFAULT_THRESHOLDS);
    const atStrict = evaluateDay(samples, baseline, { ...DEFAULT_THRESHOLDS, containSignals: 3 });

    expect(atDefault.hits).toHaveLength(2);
    expect(atDefault.contain).toBe(true);

    expect(atStrict.hits).toHaveLength(2);
    expect(atStrict.contain).toBe(false);
    expect(atStrict.severity).not.toBe('info');
  });

  it('reports every signal that fired on the worst day', () => {
    // June 29 trips all three independent detectors — the clearest possible
    // evidence, and what makes containment defensible rather than a guess.
    const verdict = evaluateDay(
      [{ date: '2026-06-29', count: 237, cost: 78.95, destination: '380' }],
      baseline,
    );

    expect(verdict.hits.map((h) => h.detector).sort()).toEqual([
      'new_destination',
      'unit_cost',
      'volume',
    ]);
  });
});
