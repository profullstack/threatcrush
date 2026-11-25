/**
 * Password Haystacks search-space calculator (browser-safe, pure).
 *
 * Independent re-implementation of the idea behind GRC's Haystacks page (not
 * affiliated). Mirrors apps/cli/src/tools/haystack.ts. Worst-case exhaustive
 * search only — not a dictionary/guess-ability score.
 */

const POOL = { lower: 26, upper: 26, digits: 10, symbols: 33, other: 70 };

export interface HaystackResult {
  length: number;
  poolSize: number;
  sets: string[];
  entropyBits: number;
  searchSpace: string;
  times: { online: string; offlineFast: string; massiveArray: string };
}

function charset(password: string) {
  const use = { lower: false, upper: false, digits: false, symbols: false, other: false };
  for (const ch of password) {
    const c = ch.charCodeAt(0);
    if (ch >= "a" && ch <= "z") use.lower = true;
    else if (ch >= "A" && ch <= "Z") use.upper = true;
    else if (ch >= "0" && ch <= "9") use.digits = true;
    else if (c >= 32 && c < 127) use.symbols = true;
    else use.other = true;
  }
  let size = 0;
  if (use.lower) size += POOL.lower;
  if (use.upper) size += POOL.upper;
  if (use.digits) size += POOL.digits;
  if (use.symbols) size += POOL.symbols;
  if (use.other) size += POOL.other;
  const sets = [use.lower && "a-z", use.upper && "A-Z", use.digits && "0-9", use.symbols && "symbols", use.other && "other"].filter(Boolean) as string[];
  return { size, sets };
}

const ZERO = BigInt(0);
const ONE = BigInt(1);

function searchSpace(pool: number, length: number): bigint {
  if (pool <= 0 || length <= 0) return ZERO;
  const p = BigInt(pool);
  let total = ZERO, term = ONE;
  for (let i = 1; i <= length; i++) { term *= p; total += term; }
  return total;
}

const S = {
  minute: BigInt(60), hour: BigInt(3600), day: BigInt(86400),
  month: BigInt(2592000), year: BigInt(31536000),
};
const K = BigInt(1000), M = BigInt(1_000_000), B = BigInt(1_000_000_000);
const T = BigInt(1_000_000_000_000), Q = BigInt(1_000_000_000_000_000);

function humanize(sec: bigint): string {
  if (sec <= ZERO) return "instantly";
  if (sec < S.minute) return `${sec} seconds`;
  if (sec < S.hour) return `${sec / S.minute} minutes`;
  if (sec < S.day) return `${sec / S.hour} hours`;
  if (sec < S.month) return `${sec / S.day} days`;
  if (sec < S.year) return `${sec / S.month} months`;
  const y = sec / S.year;
  if (y < K) return `${y} years`;
  if (y < M) return `${y / K} thousand years`;
  if (y < B) return `${y / M} million years`;
  if (y < T) return `${y / B} billion years`;
  if (y < Q) return `${y / T} trillion years`;
  return `${y / Q} quadrillion+ years`;
}

export function analyzePassword(password: string): HaystackResult {
  const length = [...password].length;
  const { size, sets } = charset(password);
  const space = searchSpace(size, length);
  const t = (rate: bigint) => humanize(rate > ZERO ? space / rate : ZERO);
  return {
    length,
    poolSize: size,
    sets,
    entropyBits: size > 1 && length > 0 ? Math.round(length * Math.log2(size) * 10) / 10 : 0,
    searchSpace: space.toString(),
    times: { online: t(K), offlineFast: t(BigInt(100_000_000_000)), massiveArray: t(BigInt(100_000_000_000_000)) },
  };
}
