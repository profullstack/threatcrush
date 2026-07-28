/**
 * Pure detection logic for third-party spend anomalies.
 *
 * Deliberately free of I/O so every rule is testable against real incident
 * data. See `__tests__/detectors.test.ts`, which replays the qrypt.chat
 * SMS-pumping incident of 2026-06/07 through these functions.
 *
 * The central difficulty is NOT spotting expensive traffic — it is telling
 * expensive-and-fraudulent apart from expensive-and-legitimate. On the
 * reference account, October 2025 averaged $0.1844/msg from real users dialling
 * international destinations, while June 2026 averaged $0.3291/msg from fraud.
 * A unit-cost threshold alone cannot separate those without either missing the
 * fraud or blocking a genuine market. What separates them is *shape*: real
 * international growth arrives spread across a month at normal daily volume,
 * whereas pumping arrives as a volume spike into destinations with no history.
 *
 * So detectors are scored independently and combined. Containment requires
 * agreement between signals; a lone elevated unit cost is worth an alert, not
 * a kill switch.
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/** One provider-reported bucket of usage, normalized across providers. */
export interface UsageSample {
  /** ISO date, `YYYY-MM-DD`. Daily granularity is the detection unit. */
  date: string;
  /** Units billed (messages, calls, tokens, GB). */
  count: number;
  /** Total cost in the account currency. */
  cost: number;
  /**
   * Destination key — country calling code, region, endpoint. Optional
   * because not every provider reports one.
   */
  destination?: string;
}

/** Learned normal behaviour, persisted between daemon restarts. */
export interface Baseline {
  /** Median cost per unit. Median, not mean — one fraud day would drag a mean. */
  unitCost: number;
  /** Median units per active day. */
  dailyCount: number;
  /** Destinations seen during learning. */
  destinations: string[];
  /** Number of daily samples that fed this baseline. */
  samples: number;
}

export interface DetectorHit {
  detector: 'unit_cost' | 'volume' | 'new_destination' | 'burn_rate';
  severity: Severity;
  /** Observed / baseline, where meaningful. */
  ratio?: number;
  message: string;
  details: Record<string, unknown>;
}

export interface Verdict {
  hits: DetectorHit[];
  severity: Severity;
  /** True when enough independent signals agree to justify containment. */
  contain: boolean;
  /** Total spend across the evaluated samples. */
  spend: number;
}

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function maxSeverity(severities: Severity[]): Severity {
  return severities.reduce<Severity>(
    (worst, s) => (SEVERITY_RANK[s] > SEVERITY_RANK[worst] ? s : worst),
    'info',
  );
}

/** Median of a numeric list. Returns 0 for an empty list. */
export function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

/** Cost per unit for a sample, guarding against divide-by-zero. */
export function unitCost(sample: Pick<UsageSample, 'count' | 'cost'>): number {
  return sample.count > 0 ? Math.abs(sample.cost) / sample.count : 0;
}

/**
 * Learn a baseline from historical daily samples.
 *
 * `exclude` lets the caller quarantine days already judged anomalous, so an
 * ongoing attack cannot normalize itself into the baseline over time — the
 * slow-ramp poisoning risk called out in PRD 0001.
 */
export function learnBaseline(history: UsageSample[], exclude: Set<string> = new Set()): Baseline {
  const clean = history.filter((s) => s.count > 0 && !exclude.has(s.date));

  return {
    unitCost: median(clean.map(unitCost)),
    dailyCount: median(clean.map((s) => s.count)),
    destinations: [...new Set(clean.map((s) => s.destination).filter((d): d is string => !!d))],
    samples: clean.length,
  };
}

export interface Thresholds {
  /** Unit cost multiple over baseline before flagging. */
  unitCostFactor: number;
  /** Daily volume multiple over baseline before flagging. */
  volumeFactor: number;
  /** Ignore days cheaper than this — noise floor for tiny accounts. */
  minDailySpend: number;
  /** Independent signals required before recommending containment. */
  containSignals: number;
}

export const DEFAULT_THRESHOLDS: Thresholds = {
  // The reference incident ran 15-21x baseline; legitimate international
  // traffic reached ~9x. 5x flags both — which is intended, because a lone
  // unit-cost hit only ever produces an alert, never containment.
  unitCostFactor: 5,
  volumeFactor: 10,
  minDailySpend: 1,
  containSignals: 2,
};

/**
 * Evaluate one day's usage against the baseline.
 *
 * Samples should all share a date; pass a day's per-destination breakdown to
 * get destination attribution in the result.
 */
export function evaluateDay(
  samples: UsageSample[],
  baseline: Baseline,
  thresholds: Thresholds = DEFAULT_THRESHOLDS,
): Verdict {
  const spend = samples.reduce((sum, s) => sum + Math.abs(s.cost), 0);
  const count = samples.reduce((sum, s) => sum + s.count, 0);
  const hits: DetectorHit[] = [];

  // Nothing meaningful happened, or we have no baseline to compare against.
  if (count === 0 || baseline.samples === 0 || spend < thresholds.minDailySpend) {
    return { hits, severity: 'info', contain: false, spend };
  }

  const observedUnitCost = unitCost({ count, cost: spend });

  // ─── Unit-cost anomaly ───
  // The economic signature of pumping: the attacker's revenue share IS the
  // price premium, so it cannot be hidden without making the attack pointless.
  if (baseline.unitCost > 0) {
    const ratio = observedUnitCost / baseline.unitCost;
    if (ratio >= thresholds.unitCostFactor) {
      hits.push({
        detector: 'unit_cost',
        severity: ratio >= thresholds.unitCostFactor * 3 ? 'high' : 'medium',
        ratio,
        message: `Unit cost ${observedUnitCost.toFixed(4)} is ${ratio.toFixed(1)}x baseline ${baseline.unitCost.toFixed(4)}`,
        details: { observed: observedUnitCost, baseline: baseline.unitCost, ratio },
      });
    }
  }

  // ─── Volume anomaly ───
  // What distinguishes a pumping run from organic international growth.
  if (baseline.dailyCount > 0) {
    const ratio = count / baseline.dailyCount;
    if (ratio >= thresholds.volumeFactor) {
      hits.push({
        detector: 'volume',
        severity: ratio >= thresholds.volumeFactor * 5 ? 'high' : 'medium',
        ratio,
        message: `Volume ${count} units is ${ratio.toFixed(1)}x baseline ${baseline.dailyCount}`,
        details: { observed: count, baseline: baseline.dailyCount, ratio },
      });
    }
  }

  // ─── New-destination anomaly ───
  const known = new Set(baseline.destinations);
  const fresh = [
    ...new Set(
      samples
        .filter((s) => s.destination && !known.has(s.destination) && s.count > 0)
        .map((s) => s.destination as string),
    ),
  ];
  if (fresh.length > 0) {
    hits.push({
      detector: 'new_destination',
      severity: fresh.length >= 3 ? 'medium' : 'low',
      message: `Spend to ${fresh.length} destination(s) with no history: ${fresh.join(', ')}`,
      details: { destinations: fresh },
    });
  }

  // Containment needs corroboration. One signal is an alert; several agreeing
  // is an incident. This is what keeps legitimate expansion into a new, pricey
  // market from tripping a kill switch.
  const contain = hits.length >= thresholds.containSignals;
  const severity = contain ? 'critical' : maxSeverity(hits.map((h) => h.severity));

  return { hits, severity, contain, spend };
}

/**
 * Project how long the remaining balance lasts at the observed burn rate.
 * Returns `Infinity` when nothing is being spent.
 */
export function hoursToZero(balance: number, spendPerHour: number): number {
  if (spendPerHour <= 0) return Infinity;
  return balance / spendPerHour;
}

/**
 * Balance-exhaustion detector.
 *
 * Worth alerting on independently: an account about to hit zero either stops
 * serving users, or — with auto-recharge enabled — silently starts drawing on
 * a stored card, which is the unbounded-loss mode.
 */
export function evaluateBurnRate(
  balance: number,
  spendPerHour: number,
  warnHours: number,
  autoRechargeEnabled: boolean,
): DetectorHit | null {
  const hours = hoursToZero(balance, spendPerHour);
  if (hours > warnHours) return null;

  return {
    detector: 'burn_rate',
    severity: autoRechargeEnabled ? 'critical' : 'high',
    message: autoRechargeEnabled
      ? `Balance ${balance.toFixed(2)} exhausts in ~${hours.toFixed(1)}h and auto-recharge will draw on the payment method`
      : `Balance ${balance.toFixed(2)} exhausts in ~${hours.toFixed(1)}h`,
    details: { balance, spendPerHour, hoursToZero: hours, autoRechargeEnabled },
  };
}
