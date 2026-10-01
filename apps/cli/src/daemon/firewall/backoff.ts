/**
 * Escalating ban durations for repeat offenders (PRD 0010 R8).
 *
 * Every offence doubles the ban: 15m, 30m, 1h, 2h, 4h, 8h, 16h, … from the
 * first detection, clamped to `max_ban`. This replaced a Fibonacci ladder in
 * minutes (1m, 2m, 3m, 5m …) that a scanner simply waited out: on dev1, 175
 * addresses were banned 1,430 times between them, most of them eight or more
 * times, because each ban was over before the next sweep of the internet.
 */

/** The default first ban. Long enough that a scanner moves on, short enough to survive a false positive. */
export const DEFAULT_FIRST_BAN_SECONDS = 15 * 60;

/** Multiplier on the first ban for the nth offence, 1-indexed: 1, 2, 4, 8, … */
export function backoffFactor(strike: number): number {
  const n = Math.max(1, Math.floor(strike));
  // 2^52 is past any ceiling anyone will configure; stop before Infinity.
  return 2 ** Math.min(n - 1, 52);
}

/**
 * Ban length in seconds for the nth offence, clamped to `maxSeconds`.
 * The clamp is what keeps R2 true — everything expires — however far an
 * address climbs.
 */
export function banSeconds(
  strike: number,
  maxSeconds: number,
  firstSeconds: number = DEFAULT_FIRST_BAN_SECONDS,
): number {
  const first = Math.max(60, firstSeconds);
  return Math.min(first * backoffFactor(strike), Math.max(first, maxSeconds));
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
