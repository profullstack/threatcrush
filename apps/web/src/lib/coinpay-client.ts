import crypto from 'crypto';

const COINPAY_API_URL =
  (process.env.COINPAYPORTAL_API_URL || 'https://coinpayportal.com').replace(/\/$/, '') + '/api';

/**
 * Every way to pay the threatcrush.com CoinPay business takes: the 15 chains it
 * holds wallets for (lowercase ids, the form this client has always used), plus
 * `paypal` through CoinPay's PayPal rail. `usdt` is the old id for USDT on
 * Ethereum. No card: the house has no card rail (Stripe is off).
 */
export type CoinpayCurrency =
  | 'usdc_pol'
  | 'usdc_sol'
  | 'usdt_pol'
  | 'usdt_sol'
  | 'usdc_eth'
  | 'usdt_eth'
  | 'usdt'
  | 'pol'
  | 'sol'
  | 'eth'
  | 'btc'
  | 'bch'
  | 'doge'
  | 'xrp'
  | 'ada'
  | 'bnb'
  | 'paypal';

export const SUPPORTED_CURRENCIES: Record<CoinpayCurrency, { name: string; symbol: string }> = {
  usdc_pol: { name: 'USDC (Polygon)', symbol: 'USDC' },
  usdc_sol: { name: 'USDC (Solana)', symbol: 'USDC' },
  usdt_pol: { name: 'USDT (Polygon)', symbol: 'USDT' },
  usdt_sol: { name: 'USDT (Solana)', symbol: 'USDT' },
  usdc_eth: { name: 'USDC (Ethereum)', symbol: 'USDC' },
  usdt_eth: { name: 'USDT (Ethereum)', symbol: 'USDT' },
  usdt: { name: 'USDT (Ethereum)', symbol: 'USDT' },
  pol: { name: 'Polygon', symbol: 'POL' },
  sol: { name: 'Solana', symbol: 'SOL' },
  eth: { name: 'Ethereum', symbol: 'ETH' },
  btc: { name: 'Bitcoin', symbol: 'BTC' },
  bch: { name: 'Bitcoin Cash', symbol: 'BCH' },
  doge: { name: 'Dogecoin', symbol: 'DOGE' },
  xrp: { name: 'XRP', symbol: 'XRP' },
  ada: { name: 'Cardano', symbol: 'ADA' },
  bnb: { name: 'BNB', symbol: 'BNB' },
  paypal: { name: 'PayPal', symbol: 'PayPal' },
};

/** The ids a picker should show (the legacy `usdt` alias left out). */
export const CURRENCY_CHOICES = (Object.keys(SUPPORTED_CURRENCIES) as CoinpayCurrency[]).filter((c) => c !== 'usdt');

export function isCoinpayCurrency(value: unknown): value is CoinpayCurrency {
  return typeof value === 'string' && Object.hasOwn(SUPPORTED_CURRENCIES, value);
}

/** CoinPay's blockchain id for a coin. */
function blockchainOf(c: Exclude<CoinpayCurrency, 'paypal'>): string {
  return c === 'usdt' ? 'USDT_ETH' : c.toUpperCase();
}

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
  cancel_url?: string;
  metadata?: Record<string, unknown>;
}): Promise<CoinpayCreatePaymentResponse> {
  const { apiKey, merchantId } = getCreds();
  const baseUrl =
    process.env.NEXT_PUBLIC_APP_URL || process.env.APP_URL || 'https://threatcrush.com';
  const successUrl = opts.redirect_url ?? `${baseUrl}/investors?payment=success`;
  const cancelUrl = opts.cancel_url ?? `${baseUrl}/investors?payment=cancelled`;
  // Every payment names the site, so CoinPay's own records say where it came from.
  const metadata: Record<string, string> = {};
  for (const [k, v] of Object.entries({ type: 'funding', ...(opts.metadata ?? {}), property: 'threatcrush.com' })) {
    if (v !== null && v !== undefined && v !== '') metadata[k] = String(v);
  }
  if (!metadata.account_id && metadata.user_id) metadata.account_id = metadata.user_id;

  if (opts.currency === 'paypal') {
    const res = await fetch(`${COINPAY_API_URL}/paypal/payments/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
      cache: 'no-store',
      body: JSON.stringify({
        business_id: merchantId,
        amount: opts.amount_usd,
        currency: 'USD',
        description: opts.description ?? 'threatcrush funding',
        customer_email: metadata.email || metadata.contributor_email || undefined,
        metadata,
        success_url: successUrl,
        cancel_url: cancelUrl,
      }),
    });
    const json = (await res.json().catch(() => ({}))) as { transaction_id?: string; error?: string };
    if (!res.ok || !json.transaction_id) {
      console.error(`[coinpay] PayPal create failed ${res.status}: ${json.error ?? ''}`);
      throw new CoinpayError(`CoinPay PayPal create failed ${res.status}`, res.status);
    }
    const checkoutUrl = `${COINPAY_API_URL.replace(/\/api$/, '')}/pay/paypal/${encodeURIComponent(json.transaction_id)}`;
    return {
      success: true,
      payment_id: json.transaction_id,
      currency: 'paypal',
      checkout_url: checkoutUrl,
      payment: { id: json.transaction_id, currency: 'paypal', checkout_url: checkoutUrl },
    };
  }

  const res = await fetch(`${COINPAY_API_URL}/payments/create`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    cache: 'no-store',
    body: JSON.stringify({
      business_id: merchantId,
      amount: opts.amount_usd,
      currency: 'USD',
      blockchain: blockchainOf(opts.currency),
      payment_method: 'crypto',
      description: opts.description ?? 'threatcrush funding',
      success_url: successUrl,
      cancel_url: cancelUrl,
      redirect_url: successUrl,
      webhook_url: `${baseUrl}/api/webhooks/coinpay`,
      expires_in_minutes: 60,
      metadata,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    console.error(`[coinpay] create failed ${res.status}: ${text.slice(0, 300)}`);
    throw new CoinpayError(`CoinPay create failed ${res.status}: ${text.slice(0, 300)}`, res.status);
  }
  const json = (await res.json()) as CoinpayCreatePaymentResponse;
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
