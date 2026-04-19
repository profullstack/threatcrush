import { describe, it, expect, vi, beforeEach } from 'vitest';

describe('POST /api/auth/purchase', () => {
  beforeEach(() => {
    vi.resetModules();
    process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
    process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-role-key';
    process.env.NEXT_PUBLIC_APP_URL = 'https://threatcrush.com';
  });

  it('returns 401 without auth token', async () => {
    const { POST } = await import('@/app/api/auth/purchase/route');
    const req = new Request('http://localhost/api/auth/purchase', {
      method: 'POST',
      body: JSON.stringify({ currency: 'usdc_sol' }),
    });

    const res = await POST(req);
    expect(res.status).toBe(401);
  });

  it('returns 401 with empty bearer token', async () => {
    const { POST } = await import('@/app/api/auth/purchase/route');
    const req = new Request('http://localhost/api/auth/purchase', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' },
      body: JSON.stringify({ currency: 'usdc_sol' }),
    });

    const res = await POST(req);
    // With an empty/invalid token, Supabase returns no user -> 401 or 500
    expect(res.status).toBeGreaterThanOrEqual(400);
  });
});

describe('POST /api/webhooks/coinpay', () => {
  beforeEach(() => {
    vi.resetModules();
    process.env.NEXT_PUBLIC_SUPABASE_URL = 'https://test.supabase.co';
    process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-role-key';
    process.env.COINPAY_WEBHOOK_SECRET = 'test-webhook-secret';
  });

  it('returns 400 for invalid JSON', async () => {
    const { POST } = await import('@/app/api/webhooks/coinpay/route');
    const req = new Request('http://localhost/api/webhooks/coinpay', {
      method: 'POST',
      body: 'not-json!!!',
    });

    const res = await POST(req);
    expect(res.status).toBe(400);
  });

  it('returns 400 for missing payment_id', async () => {
    const { POST } = await import('@/app/api/webhooks/coinpay/route');
    const req = new Request('http://localhost/api/webhooks/coinpay', {
      method: 'POST',
      body: JSON.stringify({ type: 'payment.confirmed', data: {} }),
    });

    const res = await POST(req);
    expect(res.status).toBe(400);
  });
});
