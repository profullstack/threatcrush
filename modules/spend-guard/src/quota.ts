/**
 * Quota-pace detection — the generic drain detector.
 *
 * Most metered services expose a credit/quota endpoint readable with the same
 * key the app already uses: credits remaining, a limit, and a reset date. That
 * is enough to catch a drain on any provider, without a billing API and without
 * a privileged admin credential.
 *
 * The rule is deliberately simple and provider-agnostic: compare how much of
 * the quota is gone against how much of the billing period has elapsed. Burning
 * 80% of the month's credits in the first 20% of the month is anomalous whether
 * the units are SMS, search credits, TTS characters or compute units.
 *
 * This catches what a raw "credits remaining" alarm cannot. Waiting for a
 * low-balance threshold tells you only after the money is spent; pace tells you
 * while it is being spent, which is the difference between a $12 incident and a
 * $172 one.
 */

// Reuse the shared severity scale rather than declaring a parallel one — two
// definitions would drift and collide on re-export.
import type { Severity } from './detectors.js';

export interface QuotaSnapshot {
  /** Provider/app label, e.g. "valueserp" or "elevenlabs:brisk". */
  label: string;
  /** Units consumed this period. */
  used: number;
  /** Total units for the period. */
  limit: number;
  /** Epoch ms when the quota resets. */
  resetAt: number;
  /** Human unit name, for the alert text. */
  unit: string;
  /** Period length in ms. Defaults to 30 days when the provider omits it. */
  periodMs?: number;
}

export interface QuotaVerdict {
  label: string;
  severity: Severity;
  /** usedFraction / elapsedFraction. 1.0 means exactly on pace. */
  paceRatio: number;
  usedFraction: number;
  elapsedFraction: number;
  /** Projected epoch ms of exhaustion, or null if it will not exhaust. */
  projectedExhaustion: number | null;
  /** True when the quota will run out before the period resets. */
  willExhaust: boolean;
  message: string;
}

const DEFAULT_PERIOD_MS = 30 * 24 * 60 * 60 * 1000;

export interface QuotaThresholds {
  /** Pace multiple over "on schedule" before flagging. */
  paceFactor: number;
  /** Ignore until this fraction of quota is consumed — avoids noise at period start. */
  minUsedFraction: number;
  /** Fraction of quota remaining below which severity escalates regardless of pace. */
  criticalRemaining: number;
  /** Fraction consumed at which severity escalates regardless of pace. */
  highUsedFraction: number;
}

export const DEFAULT_QUOTA_THRESHOLDS: QuotaThresholds = {
  paceFactor: 2.0,
  minUsedFraction: 0.1,
  criticalRemaining: 0.1,
  highUsedFraction: 0.75,
};

/**
 * Evaluate a quota snapshot.
 *
 * `now` is injected rather than read from the clock so the rule is testable.
 */
export function evaluateQuota(
  snap: QuotaSnapshot,
  now: number,
  thresholds: QuotaThresholds = DEFAULT_QUOTA_THRESHOLDS,
): QuotaVerdict {
  const periodMs = snap.periodMs ?? DEFAULT_PERIOD_MS;
  const periodStart = snap.resetAt - periodMs;

  const usedFraction = snap.limit > 0 ? snap.used / snap.limit : 0;
  const elapsedFraction = clamp((now - periodStart) / periodMs, 0.0001, 1);
  const paceRatio = elapsedFraction > 0 ? usedFraction / elapsedFraction : 0;

  const remainingFraction = 1 - usedFraction;
  const remainingUnits = Math.max(snap.limit - snap.used, 0);

  // Project exhaustion from the observed burn rate over the elapsed period.
  const unitsPerMs = (now - periodStart) > 0 ? snap.used / (now - periodStart) : 0;
  const projectedExhaustion =
    unitsPerMs > 0 ? Math.round(now + remainingUnits / unitsPerMs) : null;
  const willExhaust = projectedExhaustion !== null && projectedExhaustion < snap.resetAt;

  let severity: Severity = 'info';
  if (usedFraction >= 1) {
    severity = 'critical';
  } else if (remainingFraction <= thresholds.criticalRemaining) {
    severity = 'critical';
  } else if (usedFraction >= thresholds.minUsedFraction && paceRatio >= thresholds.paceFactor) {
    // Severity scales with how far off-pace the burn is.
    //
    // Note: any paceRatio > 1 already implies the quota runs out before reset
    // (projected total consumption == paceRatio), so `willExhaust` cannot
    // discriminate here — every flagged burn would exhaust. Grading by
    // magnitude is what actually separates "drifting over budget" from
    // "something is draining this".
    //
    // Absolute consumption escalates independently of pace: a quota already
    // 75% gone is serious even at a modest multiple, because the headroom left
    // to react in is small.
    const farOffPace = paceRatio >= thresholds.paceFactor * 2;
    const mostlyConsumed = usedFraction >= thresholds.highUsedFraction;
    severity = farOffPace || mostlyConsumed ? 'high' : 'medium';
  }

  const pct = (n: number) => `${Math.round(n * 100)}%`;
  const message =
    usedFraction >= 1
      ? `${snap.label}: quota EXHAUSTED (${snap.used}/${snap.limit} ${snap.unit})`
      : `${snap.label}: ${pct(usedFraction)} of quota used at ${pct(elapsedFraction)} through the period ` +
        `(${paceRatio.toFixed(1)}x pace, ${remainingUnits} ${snap.unit} left)` +
        (willExhaust ? ' — projected to run out before reset' : '');

  return {
    label: snap.label,
    severity,
    paceRatio,
    usedFraction,
    elapsedFraction,
    projectedExhaustion,
    willExhaust,
    message,
  };
}

function clamp(n: number, lo: number, hi: number): number {
  return Math.min(Math.max(n, lo), hi);
}
