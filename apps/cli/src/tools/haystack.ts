/**
 * Password Haystacks — how big is the "search space" of a password, and how
 * long would an exhaustive brute-force take?
 *
 * An independent re-implementation of the idea behind GRC's Password Haystacks
 * page (not affiliated with GRC). It is a search-space calculator, NOT a
 * password-quality oracle: it answers "how long to exhaustively try every
 * string of this composition and length", which is the brute-force worst case.
 * It does not model dictionary or pattern attacks, so a long-but-guessable
 * password can still be weak. Everything here is pure and offline.
 */

export interface CharsetUse {
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
  other: boolean;
}

const POOL = { lower: 26, upper: 26, digits: 10, symbols: 33, other: 0 } as const;

export function charsetOf(password: string): { use: CharsetUse; size: number } {
  const use: CharsetUse = { lower: false, upper: false, digits: false, symbols: false, other: false };
  for (const ch of password) {
    if (ch >= 'a' && ch <= 'z') use.lower = true;
    else if (ch >= 'A' && ch <= 'Z') use.upper = true;
    else if (ch >= '0' && ch <= '9') use.digits = true;
    else if (ch.charCodeAt(0) >= 32 && ch.charCodeAt(0) < 127) use.symbols = true;
    else use.other = true;
  }
  let size = 0;
  if (use.lower) size += POOL.lower;
  if (use.upper) size += POOL.upper;
  if (use.digits) size += POOL.digits;
  if (use.symbols) size += POOL.symbols;
  if (use.other) size += 70; // conservative extra pool for non-ASCII
  return { use, size };
}

/** Number of printable characters (code points), not UTF-16 units. */
export function lengthOf(password: string): number {
  return [...password].length;
}

/** Search space = sum over i=1..len of pool^i (every string up to this length). */
export function searchSpace(poolSize: number, length: number): bigint {
  if (poolSize <= 0 || length <= 0) return 0n;
  const pool = BigInt(poolSize);
  let total = 0n;
  let term = 1n;
  for (let i = 1; i <= length; i++) {
    term *= pool;
    total += term;
  }
  return total;
}

export function entropyBits(poolSize: number, length: number): number {
  if (poolSize <= 1 || length <= 0) return 0;
  return Math.round(length * Math.log2(poolSize) * 10) / 10;
}

/** Guess rates GRC popularised, in guesses per second. */
export const RATES = {
  online: 1_000n, // throttled online attack
  offlineFast: 100_000_000_000n, // 1e11 fast offline
  massiveArray: 100_000_000_000_000n, // 1e14 massive cracking array
} as const;

const SECONDS = {
  minute: 60n, hour: 3600n, day: 86_400n, month: 2_592_000n, year: 31_536_000n,
  century: 3_153_600_000n,
};

/** Human string for a BigInt number of seconds (worst-case exhaustive search). */
export function humanizeSeconds(sec: bigint): string {
  if (sec <= 0n) return 'instantly';
  if (sec < SECONDS.minute) return `${sec} second${sec === 1n ? '' : 's'}`;
  if (sec < SECONDS.hour) return `${sec / SECONDS.minute} minutes`;
  if (sec < SECONDS.day) return `${sec / SECONDS.hour} hours`;
  if (sec < SECONDS.month) return `${sec / SECONDS.day} days`;
  if (sec < SECONDS.year) return `${sec / SECONDS.month} months`;
  const years = sec / SECONDS.year;
  if (years < 1_000n) return `${years} years`;
  if (years < 1_000_000n) return `${years / 1_000n} thousand years`;
  if (years < 1_000_000_000n) return `${years / 1_000_000n} million years`;
  if (years < 1_000_000_000_000n) return `${years / 1_000_000_000n} billion years`;
  if (years < 1_000_000_000_000_000n) return `${years / 1_000_000_000_000n} trillion years`;
  return `${years / 1_000_000_000_000_000n} quadrillion+ years`;
}

export interface HaystackResult {
  length: number;
  charset: CharsetUse;
  poolSize: number;
  searchSpace: string; // decimal string (can be astronomically large)
  entropyBits: number;
  times: { online: string; offlineFast: string; massiveArray: string };
}

export function analyzePassword(password: string): HaystackResult {
  const length = lengthOf(password);
  const { use, size } = charsetOf(password);
  const space = searchSpace(size, length);
  const t = (rate: bigint) => humanizeSeconds(rate > 0n ? space / rate : 0n);
  return {
    length,
    charset: use,
    poolSize: size,
    searchSpace: space.toString(),
    entropyBits: entropyBits(size, length),
    times: {
      online: t(RATES.online),
      offlineFast: t(RATES.offlineFast),
      massiveArray: t(RATES.massiveArray),
    },
  };
}
