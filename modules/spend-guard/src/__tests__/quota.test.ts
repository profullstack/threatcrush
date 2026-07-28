import { describe, expect, it, vi } from 'vitest';
import { DEFAULT_QUOTA_THRESHOLDS, evaluateQuota, type QuotaSnapshot } from '../quota.js';
import { ElevenLabsQuota, ValueSerpQuota } from '../providers/quota-apis.js';

const DAY = 24 * 60 * 60 * 1000;
const MONTH = 30 * DAY;

/** Live payloads captured 2026-07-28 from real accounts. */
const VALUESERP_LIVE = {
  request_info: { success: true },
  account_info: {
    plan: '25k',
    monthly_credits_limit: 25000,
    monthly_credits_remaining: 24535,
    monthly_credits_reset_at: '2026-08-13T16:40:25.000Z',
  },
};

const ELEVENLABS_LIVE = {
  tier: 'starter',
  character_count: 4003,
  character_limit: 90000,
  status: 'active',
  next_character_count_reset_unix: 1786794486,
};

const snap = (over: Partial<QuotaSnapshot> = {}): QuotaSnapshot => ({
  label: 'test',
  used: 0,
  limit: 1000,
  resetAt: Date.parse('2026-08-01T00:00:00Z'),
  unit: 'credits',
  periodMs: MONTH,
  ...over,
});

describe('evaluateQuota — pace vs period', () => {
  const reset = Date.parse('2026-08-01T00:00:00Z');
  const start = reset - MONTH;

  it('stays quiet when consumption tracks the period', () => {
    // Halfway through the month, half the quota gone. Exactly on pace.
    const v = evaluateQuota(snap({ used: 500, resetAt: reset }), start + MONTH / 2);
    expect(v.paceRatio).toBeCloseTo(1, 1);
    expect(v.severity).toBe('info');
    expect(v.willExhaust).toBe(false);
  });

  it('flags a fast burn that will exhaust before reset', () => {
    // 10% into the month, 60% of quota gone — 6x pace, runs out early.
    const v = evaluateQuota(snap({ used: 600, resetAt: reset }), start + MONTH * 0.1);
    expect(v.paceRatio).toBeGreaterThan(5);
    expect(v.willExhaust).toBe(true);
    expect(v.severity).toBe('high');
    expect(v.message).toContain('projected to run out');
  });

  it('grades a mildly-off-pace burn below a severe one', () => {
    // 20% in, 45% used — 2.25x pace: over budget, but not the 4x+ that says
    // something is actively draining.
    const mild = evaluateQuota(snap({ used: 450, resetAt: reset }), start + MONTH * 0.2);
    expect(mild.paceRatio).toBeGreaterThan(DEFAULT_QUOTA_THRESHOLDS.paceFactor);
    expect(mild.paceRatio).toBeLessThan(DEFAULT_QUOTA_THRESHOLDS.paceFactor * 2);
    expect(mild.severity).toBe('medium');

    // 10% in, 60% used — 6x pace.
    const severe = evaluateQuota(snap({ used: 600, resetAt: reset }), start + MONTH * 0.1);
    expect(severe.severity).toBe('high');
  });

  it('any off-pace burn is by definition projected to exhaust', () => {
    // Documents why severity grades on magnitude rather than on willExhaust:
    // projected total consumption equals paceRatio, so pace > 1 always exhausts
    // and the flag cannot discriminate between flagged cases.
    const v = evaluateQuota(snap({ used: 450, resetAt: reset }), start + MONTH * 0.2);
    expect(v.paceRatio).toBeGreaterThan(1);
    expect(v.willExhaust).toBe(true);
  });

  it('does not fire on noise at the very start of a period', () => {
    // 1% in, 5% used — a huge pace ratio, but only 5% of quota is gone.
    const v = evaluateQuota(snap({ used: 50, resetAt: reset }), start + MONTH * 0.01);
    expect(v.paceRatio).toBeGreaterThan(4);
    expect(v.severity).toBe('info');
  });

  it('escalates to critical when nearly exhausted', () => {
    const v = evaluateQuota(snap({ used: 950, resetAt: reset }), start + MONTH * 0.9);
    expect(v.severity).toBe('critical');
  });

  it('reports an exhausted quota explicitly', () => {
    const v = evaluateQuota(snap({ used: 1000, resetAt: reset }), start + MONTH * 0.5);
    expect(v.severity).toBe('critical');
    expect(v.message).toContain('EXHAUSTED');
  });

  it('survives a zero limit without dividing by zero', () => {
    const v = evaluateQuota(snap({ used: 0, limit: 0 }), start + MONTH * 0.5);
    expect(Number.isFinite(v.paceRatio)).toBe(true);
    expect(v.severity).toBe('info');
  });

  it('would have caught the Alchemy drain shape', () => {
    // Normal months ran ~$65 of a $200 allowance; the drain month hit the cap.
    // Modelled as: a third of the way in, already 85% consumed.
    const v = evaluateQuota(
      snap({ label: 'alchemy', used: 850, limit: 1000, resetAt: reset, unit: 'CU' }),
      start + MONTH / 3,
    );
    expect(v.severity).toBe('high');
    expect(v.willExhaust).toBe(true);
  });
});

describe('ValueSerpQuota', () => {
  it('parses the live payload', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(VALUESERP_LIVE), { status: 200 }));
    const q = await new ValueSerpQuota('k', 'valueserp', fetchImpl as unknown as typeof fetch).fetchQuota();

    expect(q.limit).toBe(25000);
    expect(q.used).toBe(465); // 25000 - 24535
    expect(q.unit).toBe('credits');
    expect(q.resetAt).toBe(Date.parse('2026-08-13T16:40:25.000Z'));
  });

  it('reports healthy for the real current numbers', () => {
    // 465 of 25,000 used — genuinely fine, and must not alert.
    const v = evaluateQuota(
      { label: 'valueserp', used: 465, limit: 25000, resetAt: Date.parse('2026-08-13T16:40:25.000Z'), unit: 'credits' },
      Date.parse('2026-07-28T16:00:00Z'),
    );
    expect(v.severity).toBe('info');
  });

  it('raises ProviderError on failure', async () => {
    const fetchImpl = vi.fn(async () => new Response('{}', { status: 401 }));
    await expect(
      new ValueSerpQuota('k', 'valueserp', fetchImpl as unknown as typeof fetch).fetchQuota(),
    ).rejects.toThrow(/ValueSERP/);
  });
});

describe('ElevenLabsQuota', () => {
  it('parses the live payload and converts seconds to ms', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(ELEVENLABS_LIVE), { status: 200 }));
    const q = await new ElevenLabsQuota('k', 'elevenlabs', fetchImpl as unknown as typeof fetch).fetchQuota();

    expect(q.used).toBe(4003);
    expect(q.limit).toBe(90000);
    expect(q.unit).toBe('characters');
    expect(q.resetAt).toBe(1786794486 * 1000);
  });

  it('sends the xi-api-key header', async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(ELEVENLABS_LIVE), { status: 200 }));
    await new ElevenLabsQuota('secret', 'elevenlabs', fetchImpl as unknown as typeof fetch).fetchQuota();

    const headers = (fetchImpl.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(headers['xi-api-key']).toBe('secret');
  });
});
