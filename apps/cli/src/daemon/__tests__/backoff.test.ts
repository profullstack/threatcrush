import { describe, it, expect } from 'vitest';
import {
  backoffFactor,
  banSeconds,
  formatDuration,
  parseDuration,
  pruneStrikes,
  recordStrike,
  type Strike,
} from '../firewall/backoff.js';

describe('backoffFactor', () => {
  it('doubles on every offence', () => {
    expect([1, 2, 3, 4, 5, 6].map(backoffFactor)).toEqual([1, 2, 4, 8, 16, 32]);
  });

  it('treats a zeroth or negative offence as the first', () => {
    expect(backoffFactor(0)).toBe(1);
    expect(backoffFactor(-3)).toBe(1);
  });

  it('stays finite however far an address climbs', () => {
    expect(Number.isFinite(backoffFactor(10_000))).toBe(true);
  });
});

describe('banSeconds', () => {
  it('starts at fifteen minutes and doubles', () => {
    expect([1, 2, 3, 4, 5].map((n) => banSeconds(n, 7 * 86400))).toEqual([900, 1800, 3600, 7200, 14400]);
  });

  it('starts from a configured first ban', () => {
    expect(banSeconds(1, 86400, 3600)).toBe(3600);
    expect(banSeconds(3, 86400, 3600)).toBe(14400);
  });

  it('clamps to the ceiling so nothing becomes permanent', () => {
    expect(banSeconds(30, 86400)).toBe(86400);
    expect(banSeconds(10_000, 7 * 86400)).toBe(7 * 86400);
  });

  it('never bans for less than a minute even with silly settings', () => {
    expect(banSeconds(1, 5, 5)).toBe(60);
  });

  it('never cuts the first ban short with a ceiling below it', () => {
    expect(banSeconds(1, 300)).toBe(900);
  });
});

describe('recordStrike', () => {
  it('escalates while the offence is remembered', () => {
    const strikes: Record<string, Strike> = {};
    const now = 1_000_000;
    expect(recordStrike(strikes, '1.2.3.4', now, 3600)).toBe(1);
    expect(recordStrike(strikes, '1.2.3.4', now + 1000, 3600)).toBe(2);
    expect(recordStrike(strikes, '1.2.3.4', now + 2000, 3600)).toBe(3);
  });

  it('starts over once the memory window has passed', () => {
    const strikes: Record<string, Strike> = {};
    const now = 1_000_000;
    recordStrike(strikes, '1.2.3.4', now, 60);
    // 61 seconds of good behaviour: a recycled address is not punished for its
    // predecessor.
    expect(recordStrike(strikes, '1.2.3.4', now + 61_000, 60)).toBe(1);
  });

  it('tracks addresses independently', () => {
    const strikes: Record<string, Strike> = {};
    const now = 1_000_000;
    recordStrike(strikes, '1.2.3.4', now, 3600);
    recordStrike(strikes, '1.2.3.4', now, 3600);
    expect(recordStrike(strikes, '5.6.7.8', now, 3600)).toBe(1);
  });
});

describe('pruneStrikes', () => {
  it('drops entries past the memory window and keeps the rest', () => {
    const now = 1_000_000;
    const strikes: Record<string, Strike> = {
      old: { count: 4, last: now - 120_000 },
      fresh: { count: 1, last: now - 1000 },
    };
    const kept = pruneStrikes(strikes, now, 60);
    expect(Object.keys(kept)).toEqual(['fresh']);
  });
});

describe('parseDuration', () => {
  it('reads the config and --ttl spellings', () => {
    expect(parseDuration('30s')).toBe(30);
    expect(parseDuration('10m')).toBe(600);
    expect(parseDuration('2h')).toBe(7200);
    expect(parseDuration('1d')).toBe(86400);
    expect(parseDuration('45')).toBe(45);
  });

  it('returns null for what it cannot read', () => {
    expect(parseDuration('soon')).toBeNull();
    expect(parseDuration('')).toBeNull();
    expect(parseDuration(undefined)).toBeNull();
  });
});

describe('formatDuration', () => {
  it('reads as a human would say it', () => {
    expect(formatDuration(45)).toBe('45s');
    expect(formatDuration(60)).toBe('1m');
    expect(formatDuration(90)).toBe('1m 30s');
    expect(formatDuration(3600)).toBe('1h');
    expect(formatDuration(86400)).toBe('1d');
  });

  it('floors an elapsed ban at zero rather than going negative', () => {
    expect(formatDuration(-10)).toBe('0s');
  });
});
