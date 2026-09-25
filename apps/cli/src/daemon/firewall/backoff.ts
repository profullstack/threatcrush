/**
 * Escalating ban durations for repeat offenders (PRD 0010 R8).
 *
 * The ladder is the Fibonacci sequence in minutes — 1, 2, 3, 5, 8, 13, … — so
 * a host that trips a rule once and goes away costs it a minute, while one that
 * keeps coming back climbs to hours without anyone writing a permanent rule.
 * Growth is gentler than doubling at the bottom (where false positives live)
 * and still steep at the top (where the real brute-forcers live).
 */

/** Minutes for the nth offence, 1-indexed. Grows Fibonacci-wise, forever. */
export function fibonacciMinutes(strike: number): number {
  const n = Math.max(1, Math.floor(strike));
  let prev = 1;
  let curr = 1;
  // strike 1 → 1, strike 2 → 2, strike 3 → 3, strike 4 → 5, strike 5 → 8 …
  for (let i = 1; i < n; i++) {
    const next = prev + curr;
    prev = curr;
    curr = next;
  }
  return curr;
}

/**
 * Ban length in seconds for the nth offence, clamped to `maxSeconds`.
 * The clamp is what keeps R2 true — everything expires — once the ladder runs
 * past a day.
 */
export function banSeconds(strike: number, maxSeconds: number): number {
  const seconds = fibonacciMinutes(strike) * 60;
  return Math.min(seconds, Math.max(60, maxSeconds));
}

export interface Strike {
  /** How many times this source has been banned inside the memory window. */
  count: number;
  /** When the most recent offence was recorded, epoch ms. */
  last: number;
}

/**
 * The strike ledger is deliberately separate from the blocklist: an entry has
 * to outlive the ban it produced, or every offender starts again at one minute
 * and the ladder never climbs. It is forgotten after `memorySeconds` of good
 * behaviour, so a recycled address is not punished for its predecessor.
 */
export function recordStrike(
  strikes: Record<string, Strike>,
  ip: string,
  now: number,
  memorySeconds: number,
): number {
  const existing = strikes[ip];
  const expired = !existing || now - existing.last > memorySeconds * 1000;
  const count = expired ? 1 : existing.count + 1;
  strikes[ip] = { count, last: now };
  return count;
}

/** Drops ledger entries that have aged out. Called on the expiry sweep. */
export function pruneStrikes(
  strikes: Record<string, Strike>,
  now: number,
  memorySeconds: number,
): Record<string, Strike> {
  const kept: Record<string, Strike> = {};
  for (const [ip, strike] of Object.entries(strikes)) {
    if (now - strike.last <= memorySeconds * 1000) kept[ip] = strike;
  }
  return kept;
}

/** `30s`, `10m`, `2h`, `1d` — the config and `--ttl` spelling. Seconds, or null. */
export function parseDuration(value: string | number | undefined): number | null {
  if (typeof value === 'number') return Number.isFinite(value) && value > 0 ? value : null;
  if (!value) return null;
  const match = String(value).trim().match(/^(\d+)\s*(s|m|h|d)?$/i);
  if (!match) return null;
  const units: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };
  return Number(match[1]) * (units[(match[2] || 's').toLowerCase()] ?? 1);
}

/** `8m`, `2h 30m`, `45s` — for the TUI and the CLI, which both show time left. */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds <= 0) return '0s';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  if (m > 0) return s > 0 && m < 10 ? `${m}m ${s}s` : `${m}m`;
  return `${s}s`;
}
