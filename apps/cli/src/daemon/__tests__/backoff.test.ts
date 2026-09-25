import { describe, it, expect } from 'vitest';
import {
  banSeconds,
  fibonacciMinutes,
  formatDuration,
  parseDuration,
  pruneStrikes,
  recordStrike,
  type Strike,
} from '../firewall/backoff.js';

describe('fibonacciMinutes', () => {
  it('walks 1, 2, 3, 5, 8, 13 for the first six offences', () => {
    expect([1, 2, 3, 4, 5, 6].map(fibonacciMinutes)).toEqual([1, 2, 3, 5, 8, 13]);
  });

  it('treats a zeroth or negative offence as the first', () => {
    expect(fibonacciMinutes(0)).toBe(1);
    expect(fibonacciMinutes(-3)).toBe(1);
  });
});

describe('banSeconds', () => {
  it('converts the ladder to seconds', () => {
    expect(banSeconds(1, 86400)).toBe(60);
    expect(banSeconds(5, 86400)).toBe(480);
  });

  it('clamps to the ceiling so nothing becomes permanent', () => {
    // The 30th Fibonacci minute is far past a day.
    expect(banSeconds(30, 86400)).toBe(86400);
  });

  it('never bans for less than a minute even with a silly ceiling', () => {
    expect(banSeconds(1, 5)).toBe(60);
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
