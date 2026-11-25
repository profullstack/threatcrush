import { describe, expect, it } from 'vitest';
import { analyzePassword, charsetOf, searchSpace, entropyBits, humanizeSeconds } from '../haystack.js';
import { generatePassword, perfectSet, CHARSETS, type RandomSource } from '../genpass.js';
import { normalizeFingerprint, fingerprintsMatch, getFingerprint, type CertSource } from '../fingerprint.js';
import { summarizeLatencies, rankResults, benchmarkDns, PUBLIC_RESOLVERS, type DnsProbe } from '../dnsbench.js';

describe('haystack', () => {
  it('detects character pools and pool size', () => {
    expect(charsetOf('abc').size).toBe(26);
    expect(charsetOf('Abc1').size).toBe(26 + 26 + 10);
    expect(charsetOf('Abc1!').size).toBe(26 + 26 + 10 + 33);
  });

  it('search space sums pool^1..pool^len', () => {
    // pool 2, len 3 → 2 + 4 + 8 = 14
    expect(searchSpace(2, 3)).toBe(14n);
    expect(searchSpace(0, 5)).toBe(0n);
    expect(searchSpace(10, 0)).toBe(0n);
  });

  it('entropy bits ~ len*log2(pool)', () => {
    expect(entropyBits(2, 8)).toBe(8); // 8 * 1
    expect(entropyBits(1, 8)).toBe(0);
  });

  it('humanizeSeconds scales to geological time', () => {
    expect(humanizeSeconds(0n)).toBe('instantly');
    expect(humanizeSeconds(30n)).toContain('second');
    expect(humanizeSeconds(31_536_000n * 5n)).toBe('5 years');
    expect(humanizeSeconds(31_536_000n * 5_000_000n)).toContain('million years');
  });

  it('analyzePassword produces a longer time for a longer, richer password', () => {
    const weak = analyzePassword('aaaa');
    const strong = analyzePassword('Tr0ub4dour&3xtraLong!!');
    expect(BigInt(strong.searchSpace)).toBeGreaterThan(BigInt(weak.searchSpace));
    expect(strong.entropyBits).toBeGreaterThan(weak.entropyBits);
  });
});

describe('genpass', () => {
  // A deterministic RNG: bytes 0,1,2,3,... so output is predictable.
  const seqRandom: RandomSource = (n) => Uint8Array.from({ length: n }, (_, i) => i % 256);

  it('produces the requested length using only the alphabet', () => {
    const pw = generatePassword(20, CHARSETS.hex);
    expect(pw).toHaveLength(20);
    expect([...pw].every((c) => CHARSETS.hex.includes(c))).toBe(true);
  });

  it('is deterministic given a fixed RNG (rejection sampling honoured)', () => {
    expect(generatePassword(8, 'abcd', seqRandom)).toBe(generatePassword(8, 'abcd', seqRandom));
  });

  it('rejects an alphabet with <2 distinct chars', () => {
    expect(() => generatePassword(4, 'aaaa')).toThrow();
  });

  it('perfectSet returns the three expected lengths', () => {
    const s = perfectSet();
    expect(s.hex64).toHaveLength(64);
    expect(s.alnum63).toHaveLength(63);
    expect(s.ascii63).toHaveLength(63);
  });

  it('two generations differ (real CSPRNG)', () => {
    expect(generatePassword(32, CHARSETS.ascii)).not.toBe(generatePassword(32, CHARSETS.ascii));
  });
});

describe('fingerprint', () => {
  it('normalizes and compares fingerprints regardless of case/colons', () => {
    expect(normalizeFingerprint('ab:cd:EF')).toBe('ABCDEF');
    expect(fingerprintsMatch('ab:cd:ef', 'ABCDEF')).toBe(true);
    expect(fingerprintsMatch('abcd', 'ef01')).toBe(false);
    expect(fingerprintsMatch('', '')).toBe(false);
  });

  it('getFingerprint maps a peer cert from an injected source', async () => {
    const source: CertSource = async () => ({
      fingerprint256: 'AA:BB:CC',
      fingerprint: '11:22',
      subject: { CN: 'example.com' },
      issuer: { O: "Let's Encrypt" },
      valid_from: 'Jan 1 2026', valid_to: 'Apr 1 2026',
      serialNumber: 'DEAD', subjectaltname: 'DNS:example.com',
    });
    const fp = await getFingerprint('example.com', 443, { source });
    expect(fp.sha256).toBe('AA:BB:CC');
    expect(fp.subjectCN).toBe('example.com');
    expect(fp.issuer).toBe("Let's Encrypt");
  });
});

describe('dnsbench', () => {
  it('summarizeLatencies computes reliability and avg/min/max', () => {
    const s = summarizeLatencies([10, 20, null, 30]);
    expect(s.queries).toBe(4);
    expect(s.successes).toBe(3);
    expect(s.reliabilityPct).toBe(75);
    expect(s.avgMs).toBe(20);
    expect(s.minMs).toBe(10);
    expect(s.maxMs).toBe(30);
  });

  it('summarizeLatencies handles all-failures', () => {
    const s = summarizeLatencies([null, null]);
    expect(s.avgMs).toBeNull();
    expect(s.reliabilityPct).toBe(0);
  });

  it('rankResults orders by avg latency, failures last', () => {
    const ranked = rankResults([
      { name: 'slow', ip: '', queries: 1, successes: 1, reliabilityPct: 100, avgMs: 50, minMs: 50, maxMs: 50 },
      { name: 'dead', ip: '', queries: 1, successes: 0, reliabilityPct: 0, avgMs: null, minMs: null, maxMs: null },
      { name: 'fast', ip: '', queries: 1, successes: 1, reliabilityPct: 100, avgMs: 5, minMs: 5, maxMs: 5 },
    ]);
    expect(ranked.map((r) => r.name)).toEqual(['fast', 'slow', 'dead']);
  });

  it('benchmarkDns uses the injected probe and ranks resolvers', async () => {
    const probe: DnsProbe = async (ip) => (ip === '1.1.1.1' ? 3 : ip === '8.8.8.8' ? 9 : null);
    const results = await benchmarkDns(PUBLIC_RESOLVERS.slice(0, 3), { names: ['a.com'], probe });
    expect(results[0].ip).toBe('1.1.1.1');
    expect(results[0].avgMs).toBe(3);
    expect(results[results.length - 1].avgMs).toBeNull();
  });
});
