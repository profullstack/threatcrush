import { describe, expect, it, vi } from 'vitest';
import {
  computeDrawdownPerHour,
  DeepSeekBalance,
  MoonshotBalance,
} from '../providers/balance-apis.js';
import { evaluateBurnRate } from '../detectors.js';

/** Live payloads captured 2026-07-28. */
const DEEPSEEK_LIVE = {
  is_available: true,
  balance_infos: [
    { currency: 'USD', total_balance: '2.77', granted_balance: '0.00', topped_up_balance: '2.77' },
  ],
};

const MOONSHOT_LIVE = {
  code: 0,
  data: { available_balance: 86.59115, voucher_balance: 0, cash_balance: 86.59115 },
  scode: '0x0',
  status: true,
};

const HOUR = 3_600_000;

describe('DeepSeekBalance', () => {
  it('parses the live payload', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(DEEPSEEK_LIVE), { status: 200 }));
    const s = await new DeepSeekBalance('k', 'deepseek', fetchImpl as unknown as typeof fetch).fetchPrepaidBalance();

    expect(s.balance).toBeCloseTo(2.77, 2);
    expect(s.currency).toBe('USD');
  });

  it('sends a bearer token', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(DEEPSEEK_LIVE), { status: 200 }));
    await new DeepSeekBalance('secret', 'deepseek', fetchImpl as unknown as typeof fetch).fetchPrepaidBalance();

    const headers = (fetchImpl.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(headers.Authorization).toBe('Bearer secret');
  });
});

describe('MoonshotBalance', () => {
  it('parses the live payload', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(MOONSHOT_LIVE), { status: 200 }));
    const s = await new MoonshotBalance('k', 'moonshot', undefined, fetchImpl as unknown as typeof fetch).fetchPrepaidBalance();

    expect(s.balance).toBeCloseTo(86.59115, 5);
  });

  it('defaults to the international host', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(MOONSHOT_LIVE), { status: 200 }));
    await new MoonshotBalance('k', 'moonshot', undefined, fetchImpl as unknown as typeof fetch).fetchPrepaidBalance();

    expect(fetchImpl.mock.calls[0][0]).toBe('https://api.moonshot.ai/v1/users/me/balance');
  });

  it('explains a 401 as a possible host mismatch, not just a bad key', async () => {
    // A .cn key on the .ai host returns 401 and looks identical to a revoked
    // credential — observed in practice, so the error has to say so.
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 401 }));
    await expect(
      new MoonshotBalance('k', 'moonshot', undefined, fetchImpl as unknown as typeof fetch).fetchPrepaidBalance(),
    ).rejects.toThrow(/not interchangeable/);
  });
});

describe('computeDrawdownPerHour', () => {
  it('measures spend between two observations', () => {
    const rate = computeDrawdownPerHour(
      { balance: 100, at: 0 },
      { balance: 90, at: 2 * HOUR },
    );
    expect(rate).toBeCloseTo(5, 5); // $10 over 2h
  });

  it('treats a top-up as zero spend, never negative', () => {
    expect(computeDrawdownPerHour({ balance: 10, at: 0 }, { balance: 100, at: HOUR })).toBe(0);
  });

  it('is safe when no time has passed', () => {
    expect(computeDrawdownPerHour({ balance: 100, at: 5 }, { balance: 50, at: 5 })).toBe(0);
  });
});

describe('drawdown feeding the burn-rate detector', () => {
  it('flags DeepSeek at its real balance under a modest drain', () => {
    // Real balance is $2.77. At $1/h that is under 3 hours of runway.
    const rate = computeDrawdownPerHour({ balance: 4.77, at: 0 }, { balance: 2.77, at: 2 * HOUR });
    const hit = evaluateBurnRate(2.77, rate, 6, false);

    expect(rate).toBeCloseTo(1, 5);
    expect(hit?.severity).toBe('high');
  });

  it('escalates to critical when auto-recharge can refill from a card', () => {
    const hit = evaluateBurnRate(2.77, 1, 6, true);
    expect(hit?.severity).toBe('critical');
  });

  it('stays quiet on a healthy balance with light usage', () => {
    // Moonshot at $86.59, drawing ~$0.10/h — hundreds of hours of runway.
    expect(evaluateBurnRate(86.59, 0.1, 6, false)).toBeNull();
  });
});
