import crypto from 'crypto';

const COINPAY_API_URL =
  (process.env.COINPAYPORTAL_API_URL || 'https://coinpayportal.com').replace(/\/$/, '') + '/api';

export type CoinpayCurrency =
  | 'card'
  | 'usdc_pol'
  | 'usdc_sol'
  | 'usdc_eth'
  | 'usdt'
  | 'pol'
  | 'sol'
  | 'btc'
  | 'eth';

export const SUPPORTED_CURRENCIES: Record<CoinpayCurrency, { name: string; symbol: string }> = {
  card: { name: 'Credit / Debit Card', symbol: 'Card' },
  usdc_pol: { name: 'USDC (Polygon)', symbol: 'USDC' },
  usdc_sol: { name: 'USDC (Solana)', symbol: 'USDC' },
  usdc_eth: { name: 'USDC (Ethereum)', symbol: 'USDC' },
  usdt: { name: 'USDT', symbol: 'USDT' },
  pol: { name: 'Polygon', symbol: 'POL' },
  sol: { name: 'Solana', symbol: 'SOL' },
  btc: { name: 'Bitcoin', symbol: 'BTC' },
  eth: { name: 'Ethereum', symbol: 'ETH' },
};

export interface CoinpayCreatePaymentResponse {
  success?: boolean;
  payment_id?: string;
  address?: string;
  amount_crypto?: number;
  currency?: string;
  expires_at?: string;
  checkout_url?: string;
  payment?: {
    id?: string;
    payment_address?: string;
    amount_crypto?: number;
    crypto_amount?: number;
    currency?: string;
    expires_at?: string;
    checkout_url?: string;
    stripe_checkout_url?: string;
    stripe_session_id?: string;
    [key: string]: unknown;
  };
}

export interface CoinpayWebhookPayload {
  id: string;
  type:
    | 'payment.confirmed'
    | 'payment.forwarded'
    | 'payment.expired'
    | 'payment.failed'
    | string;
  data: {
    payment_id: string;
    status: string;
    amount_crypto?: string | number;
    amount_usd?: string | number;
    currency?: string;
    payment_address?: string;
    tx_hash?: string;
    merchant_tx_hash?: string;
    metadata?: Record<string, unknown>;
  };
  created_at?: string;
  business_id?: string;
}

/** A CoinPay call that failed. `status` is CoinPay's HTTP status when it answered. */
export class CoinpayError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'CoinpayError';
  }
}

/** COINPAYPORTAL_API_KEY / COINPAYPORTAL_BUSINESS_ID are not set. */
export class CoinpayNotConfiguredError extends CoinpayError {
  constructor() {
    super('CoinPay credentials not configured');
    this.name = 'CoinpayNotConfiguredError';
  }
}

/**
 * HTTP status + message a payment-status route answers with when the live
 * CoinPay lookup throws (anything else, including a network failure, is 502).
 */
export function paymentStatusFailure(err: unknown): { status: number; error: string } {
  if (err instanceof CoinpayNotConfiguredError) {
    return { status: 503, error: 'Payment status is unavailable: payment provider not configured' };
  }
  if (err instanceof CoinpayError && err.status === 404) {
    return { status: 404, error: 'Payment not found' };
  }
  return { status: 502, error: 'Could not fetch payment status from the payment provider' };
}

function getCreds(): { apiKey: string; merchantId: string } {
  const apiKey = process.env.COINPAYPORTAL_API_KEY;
  const merchantId = process.env.COINPAYPORTAL_BUSINESS_ID;
  if (!apiKey || !merchantId) {
    throw new CoinpayNotConfiguredError();
  }
  return { apiKey, merchantId };
}

export async function createCoinpayPayment(opts: {
  amount_usd: number;
  currency: CoinpayCurrency;
  description?: string;
  redirect_url?: string;
  metadata?: Record<string, unknown>;
}): Promise<CoinpayCreatePaymentResponse> {
  const { apiKey, merchantId } = getCreds();
  const baseUrl =
    process.env.NEXT_PUBLIC_APP_URL || process.env.APP_URL || 'https://threatcrush.com';
  const res = await fetch(`${COINPAY_API_URL}/payments/create`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    cache: 'no-store',
    body: JSON.stringify({
      business_id: merchantId,
      amount_usd: opts.amount_usd,
      // For card payments CoinPay still requires a currency. We use
      // payment_method=both and redirect the user to stripe_checkout_url.
      ...(opts.currency === 'card'
        ? { payment_method: 'both', currency: 'usdc_pol' }
        : { payment_method: 'crypto', currency: opts.currency }),
      description: opts.description ?? 'threatcrush funding',
      success_url: `${baseUrl}/investors?payment=success`,
      cancel_url: `${baseUrl}/investors?payment=cancelled`,
      redirect_url: opts.redirect_url ?? `${baseUrl}/investors?payment=success`,
      webhook_url: `${baseUrl}/api/webhooks/coinpay`,
      metadata: { type: 'funding', ...(opts.metadata ?? {}) },
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    console.error(`[coinpay] create failed ${res.status}: ${text}`);
    throw new Error(`CoinPay create failed ${res.status}: ${text.slice(0, 300)}`);
  }
  const json = await res.json();
  console.log('[coinpay] create response:', JSON.stringify(json));
  return json;
}

export interface CoinpayPaymentStatus {
  status: string;
  tx_hash?: string | null;
}

export async function getCoinpayPaymentStatus(paymentId: string): Promise<CoinpayPaymentStatus> {
  const { apiKey } = getCreds();
  // Encoded: the id comes from the query string, and a raw `../` would walk
  // the authenticated request to another CoinPay endpoint.
  const res = await fetch(`${COINPAY_API_URL}/payments/${encodeURIComponent(paymentId)}`, {
    headers: { Authorization: `Bearer ${apiKey}` },
    cache: 'no-store',
  });
  if (!res.ok) {
    throw new CoinpayError(`CoinPay status failed: ${res.status}`, res.status);
  }
  const json = (await res.json()) as {
    payment?: { status?: string; tx_hash?: string | null };
    status?: string;
  };
  const status = json.payment?.status ?? json.status ?? 'pending';
  return { status, tx_hash: json.payment?.tx_hash ?? null };
}

/**
 * Verify CoinPay webhook signature.
 * Header format: X-CoinPay-Signature: t=timestamp,v1=hexsig
 * Signed payload: `${timestamp}.${rawBody}` HMAC-SHA256 with webhook secret.
 */
export function verifyCoinpayWebhook(
  rawBody: string,
  signatureHeader: string | null,
  secret: string
): boolean {
  if (!signatureHeader) return false;
  try {
    const parts = signatureHeader.split(',');
    const tPart = parts.find((p) => p.startsWith('t='));
    const vPart = parts.find((p) => p.startsWith('v1='));
    if (!tPart || !vPart) return false;
    const timestamp = tPart.slice(2);
    const sig = vPart.slice(3);
    const ts = parseInt(timestamp, 10);
    if (Math.abs(Math.floor(Date.now() / 1000) - ts) > 300) return false;
    const expected = crypto
      .createHmac('sha256', secret)
      .update(`${timestamp}.${rawBody}`)
      .digest('hex');
    const a = Buffer.from(sig, 'hex');
    const b = Buffer.from(expected, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}
