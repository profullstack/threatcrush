import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import crypto from 'node:crypto';

// Mock for the create-invoice tests (hoisted by vi.mock)
const mockFundingInsert = vi.fn().mockResolvedValue({ error: null });

vi.mock('@/lib/supabase', () => ({
  getSupabaseAdmin: () => ({
    from: () => ({
      insert: mockFundingInsert,
    }),
  }),
}));

describe('lib/coinpay-client', () => {
  let originalEnv: NodeJS.ProcessEnv;
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    originalEnv = { ...process.env };
    process.env.COINPAYPORTAL_API_KEY = 'cp_test_key';
    process.env.COINPAYPORTAL_BUSINESS_ID = 'biz-uuid';
    process.env.NEXT_PUBLIC_APP_URL = 'https://threatcrush.com';
    process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'test-anon-key';
    process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-key';
    vi.resetModules();
    fetchSpy = vi.spyOn(globalThis, 'fetch') as never;
  });

  afterEach(() => {
    process.env = originalEnv;
    fetchSpy.mockRestore();
  });

  describe('verifyCoinpayWebhook', () => {
    it('verifies a valid HMAC signature', async () => {
      const { verifyCoinpayWebhook } = await import('@/lib/coinpay-client');
      const secret = 'whsecret_test';
      const body = JSON.stringify({ id: 'evt_1', type: 'payment.confirmed' });
      const ts = Math.floor(Date.now() / 1000).toString();
      const sig = crypto.createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');
      const header = `t=${ts},v1=${sig}`;
      expect(verifyCoinpayWebhook(body, header, secret)).toBe(true);
    });

    it('rejects a tampered body', async () => {
      const { verifyCoinpayWebhook } = await import('@/lib/coinpay-client');
      const secret = 'whsecret_test';
      const body = JSON.stringify({ id: 'evt_1', type: 'payment.confirmed' });
      const ts = Math.floor(Date.now() / 1000).toString();
      const sig = crypto.createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');
      const header = `t=${ts},v1=${sig}`;
      expect(verifyCoinpayWebhook('{"tampered":true}', header, secret)).toBe(false);
    });

    it('rejects a stale timestamp', async () => {
      const { verifyCoinpayWebhook } = await import('@/lib/coinpay-client');
      const secret = 'whsecret_test';
      const body = '{}';
      const ts = (Math.floor(Date.now() / 1000) - 600).toString();
      const sig = crypto.createHmac('sha256', secret).update(`${ts}.${body}`).digest('hex');
      const header = `t=${ts},v1=${sig}`;
      expect(verifyCoinpayWebhook(body, header, secret)).toBe(false);
    });

    it('rejects missing signature header', async () => {
      const { verifyCoinpayWebhook } = await import('@/lib/coinpay-client');
      expect(verifyCoinpayWebhook('{}', null, 'secret')).toBe(false);
    });

    it('rejects malformed header', async () => {
      const { verifyCoinpayWebhook } = await import('@/lib/coinpay-client');
      expect(verifyCoinpayWebhook('{}', 'garbage', 'secret')).toBe(false);
    });
  });

  describe('createCoinpayPayment payload shape', () => {
    function mockCpResponse(extra: Record<string, unknown> = {}) {
      return {
        ok: true,
        status: 201,
        json: async () => ({
          success: true,
          payment: {
            id: 'pay_123',
            payment_address: '0xabc',
            amount_crypto: 1.234,
            currency: 'usdc_pol',
            expires_at: '2030-01-01T00:00:00Z',
            ...extra,
          },
        }),
        text: async () => '',
      } as unknown as Response;
    }

    it('crypto: sends payment_method=crypto with chosen currency and webhook URL', async () => {
      fetchSpy.mockResolvedValueOnce(mockCpResponse());
      const { createCoinpayPayment } = await import('@/lib/coinpay-client');
      await createCoinpayPayment({ amount_usd: 5, currency: 'sol' });

      expect(fetchSpy).toHaveBeenCalledTimes(1);
      const call = fetchSpy.mock.calls[0];
      expect(call[0]).toBe('https://coinpayportal.com/api/payments/create');
      const init = call[1] as RequestInit;
      const body = JSON.parse(init.body as string);
      expect(body.payment_method).toBe('crypto');
      expect(body.currency).toBe('sol');
      expect(body.business_id).toBe('biz-uuid');
      expect(body.webhook_url).toBe('https://threatcrush.com/api/webhooks/coinpay');
      expect(body.success_url).toBe('https://threatcrush.com/investors?payment=success');
      expect(body.cancel_url).toBe('https://threatcrush.com/investors?payment=cancelled');
    });

    it('card: sends payment_method=both with usdc_pol fallback', async () => {
      fetchSpy.mockResolvedValueOnce(
        mockCpResponse({ stripe_checkout_url: 'https://checkout.stripe.com/abc' })
      );
      const { createCoinpayPayment } = await import('@/lib/coinpay-client');
      await createCoinpayPayment({ amount_usd: 25, currency: 'card' });

      const call = fetchSpy.mock.calls[0];
      const init = call[1] as RequestInit;
      const body = JSON.parse(init.body as string);
      expect(body.payment_method).toBe('both');
      expect(body.currency).toBe('usdc_pol');
      expect(body.webhook_url).toBe('https://threatcrush.com/api/webhooks/coinpay');
      expect(body.success_url).toBe('https://threatcrush.com/investors?payment=success');
    });

    it('throws on non-2xx response with body in error', async () => {
      fetchSpy.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({}),
        text: async () => '{"error":"bad merchant"}',
      } as unknown as Response);
      const { createCoinpayPayment } = await import('@/lib/coinpay-client');
      await expect(
        createCoinpayPayment({ amount_usd: 1, currency: 'sol' })
      ).rejects.toThrow(/CoinPay create failed 400.*bad merchant/);
    });
  });
});

describe('contract: POST /api/funding/create-invoice', () => {
  let originalEnv: NodeJS.ProcessEnv;
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    originalEnv = { ...process.env };
    process.env.COINPAYPORTAL_API_KEY = 'cp_test_key';
    process.env.COINPAYPORTAL_BUSINESS_ID = 'biz-uuid';
    process.env.NEXT_PUBLIC_APP_URL = 'https://threatcrush.com';
    process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY = 'test-anon-key';
    process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-key';
    vi.resetModules();
    vi.clearAllMocks();
    fetchSpy = vi.spyOn(globalThis, 'fetch') as never;
  });

  afterEach(() => {
    process.env = originalEnv;
    fetchSpy.mockRestore();
  });

  function mockCpOk(extra: Record<string, unknown> = {}) {
    return {
      ok: true,
      status: 201,
      json: async () => ({
        success: true,
        payment: {
          id: 'pay_xyz',
          payment_address: '0xabc',
          amount_crypto: 1.5,
          currency: 'usdc_pol',
          expires_at: '2030-01-01T00:00:00Z',
          ...extra,
        },
      }),
      text: async () => '',
    } as unknown as Response;
  }

  function jsonRequest(body: unknown): Request {
    return new Request('http://test/api/funding/create-invoice', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  it('returns 400 on invalid amount', async () => {
    const { POST } = await import('@/app/api/funding/create-invoice/route');
    const res = await POST(jsonRequest({ amount_usd: 0, currency: 'sol' }) as never);
    expect(res.status).toBe(400);
  });

  it('returns 400 on unknown currency', async () => {
    const { POST } = await import('@/app/api/funding/create-invoice/route');
    const res = await POST(jsonRequest({ amount_usd: 5, currency: 'doge' }) as never);
    expect(res.status).toBe(400);
  });

  it('crypto: returns payment_id, address, amount_crypto', async () => {
    fetchSpy.mockResolvedValueOnce(mockCpOk());
    const { POST } = await import('@/app/api/funding/create-invoice/route');
    const res = await POST(jsonRequest({ amount_usd: 5, currency: 'sol' }) as never);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.payment_id).toBe('pay_xyz');
    expect(json.address).toBe('0xabc');
    expect(json.amount_crypto).toBe(1.5);
  });

  it('card: returns stripe_checkout_url so client redirects to Stripe', async () => {
    fetchSpy.mockResolvedValueOnce(
      mockCpOk({ stripe_checkout_url: 'https://checkout.stripe.com/abc' })
    );
    const { POST } = await import('@/app/api/funding/create-invoice/route');
    const res = await POST(jsonRequest({ amount_usd: 25, currency: 'card' }) as never);
    expect(res.status).toBe(200);
    const json = await res.json();
    expect(json.checkout_url).toBe('https://checkout.stripe.com/abc');
  });

  it('returns 502 if CoinPay omits payment id', async () => {
    fetchSpy.mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: async () => ({ success: true, payment: {} }),
      text: async () => '',
    } as unknown as Response);
    const { POST } = await import('@/app/api/funding/create-invoice/route');
    const res = await POST(jsonRequest({ amount_usd: 5, currency: 'sol' }) as never);
    expect(res.status).toBe(502);
  });
});
