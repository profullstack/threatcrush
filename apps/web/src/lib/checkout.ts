import "server-only";

/**
 * One checkout for everything ThreatCrush sells: Reputation Pro, paid modules
 * and the $400 human-reviewed scan. Modelled on smshub's src/lib/coinpay/checkout.ts.
 *
 * Three rails, all through CoinPay with the business key (cp_live_...):
 *
 *  - COINPAY: CoinPay's hosted checkout session (POST /api/checkout/sessions),
 *    where the buyer picks any coin or PayPal on CoinPay's page. Feature-detected:
 *    the endpoint is new, and until it answers we offer the two rails below.
 *  - a coin: POST /api/payments/create with `blockchain`, one of every chain
 *    the threatcrush.com CoinPay business holds a wallet for.
 *  - PAYPAL: POST /api/paypal/payments/create (the business is connected to the
 *    house PayPal REST app, so CoinPay takes 0%).
 *
 * Every rail carries the same metadata: property, account_id, email, product,
 * so a payment is traceable to the site and the buyer from CoinPay alone. The
 * single webhook at /api/webhooks/coinpay settles all three.
 */

export const PROPERTY = "threatcrush.com";

/** Chains the threatcrush.com CoinPay business holds wallets for, cheapest first. */
export const CHECKOUT_COINS = [
  "USDC_POL",
  "USDC_SOL",
  "USDT_POL",
  "USDT_SOL",
  "USDC_ETH",
  "USDT_ETH",
  "POL",
  "SOL",
  "ETH",
  "BTC",
  "BCH",
  "DOGE",
  "XRP",
  "ADA",
  "BNB",
] as const;
export type CheckoutCoin = (typeof CHECKOUT_COINS)[number];

export const COIN_LABELS: Record<CheckoutCoin, string> = {
  USDC_POL: "USDC (Polygon)",
  USDC_SOL: "USDC (Solana)",
  USDT_POL: "USDT (Polygon)",
  USDT_SOL: "USDT (Solana)",
  USDC_ETH: "USDC (Ethereum)",
  USDT_ETH: "USDT (Ethereum)",
  POL: "Polygon (POL)",
  SOL: "Solana (SOL)",
  ETH: "Ethereum (ETH)",
  BTC: "Bitcoin (BTC)",
  BCH: "Bitcoin Cash (BCH)",
  DOGE: "Dogecoin (DOGE)",
  XRP: "XRP",
  ADA: "Cardano (ADA)",
  BNB: "BNB",
};

export const HOSTED_METHOD = "COINPAY" as const;
export const PAYPAL_METHOD = "PAYPAL" as const;
export type CheckoutMethod = CheckoutCoin | typeof PAYPAL_METHOD | typeof HOSTED_METHOD;

/** Legacy lowercase ids the CLI and older clients send (usdc_pol, usdt, btc ...). */
const LEGACY: Record<string, CheckoutCoin> = {
  usdt: "USDT_ETH",
  usdc: "USDC_ETH",
};

/** A method id from any client, or null when it is not one we take. */
export function normalizeMethod(raw: unknown): CheckoutMethod | null {
  const s = String(raw ?? "").trim();
  if (!s) return null;
  if (LEGACY[s.toLowerCase()]) return LEGACY[s.toLowerCase()];
  const up = s.toUpperCase();
  if (up === PAYPAL_METHOD || up === HOSTED_METHOD) return up;
  return (CHECKOUT_COINS as readonly string[]).includes(up) ? (up as CheckoutCoin) : null;
}

export interface CoinPayConfig {
  apiUrl: string;
  apiKey: string;
  businessId: string;
}

export function coinpayConfig(env: NodeJS.ProcessEnv = process.env): CoinPayConfig | null {
  // Bracket access keeps Next from inlining these at build time.
  const apiKey = env["COINPAYPORTAL_API_KEY"] || "";
  const businessId = env["COINPAYPORTAL_BUSINESS_ID"] || "";
  if (!apiKey || !businessId) return null;
  let apiUrl = (env["COINPAYPORTAL_API_URL"] || "https://coinpayportal.com").replace(/\/+$/, "");
  if (!apiUrl.endsWith("/api")) apiUrl += "/api";
  return { apiUrl, apiKey, businessId };
}

export class CheckoutError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "CheckoutError";
  }
}

export interface CheckoutRequest {
  amountUsd: number;
  description: string;
  email: string | null;
  accountId: string;
  /** What is being bought: reputation-pro, link-watch, scan. */
  product: string;
  metadata: Record<string, string | number | null | undefined>;
  successUrl: string;
  cancelUrl: string;
  /** Stable per order, so a retried click cannot open two payments. */
  idempotencyKey: string;
}

export interface CheckoutStarted {
  provider: "coinpay_session" | "coinpay" | "paypal";
  method: CheckoutMethod;
  /** Stored as coinpay_payment_id; the webhook finds the order by it. */
  id: string;
  /** Where to send the buyer. */
  url: string;
  address?: string | null;
  amountCrypto?: string | null;
  expiresAt?: string | null;
}

/** Every value a string: CoinPay stores metadata as jsonb, and the webhook compares strings. */
export function checkoutMetadata(req: CheckoutRequest): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.metadata)) {
    if (v !== null && v !== undefined && v !== "") out[k] = String(v);
  }
  out.property = PROPERTY;
  out.account_id = req.accountId;
  out.product = req.product;
  if (req.email) out.email = req.email;
  return out;
}

function base(cfg: CoinPayConfig): string {
  return cfg.apiUrl.replace(/\/api$/, "");
}

// ─── Hosted session feature detection ───

let hostedProbe: { at: number; ok: boolean } | null = null;
const PROBE_TTL_MS = 10 * 60 * 1000;

/**
 * Whether CoinPay answers POST /api/checkout/sessions. An empty body to a live
 * endpoint is a 400; a missing one is a 404 (or 405). Cached ten minutes so the
 * pricing page never waits on it twice.
 */
export async function hostedCheckoutAvailable(
  cfg: CoinPayConfig | null = coinpayConfig(),
  fetchImpl: typeof fetch = fetch,
  now: number = Date.now(),
): Promise<boolean> {
  if (!cfg) return false;
  if (hostedProbe && now - hostedProbe.at < PROBE_TTL_MS) return hostedProbe.ok;
  let ok = false;
  try {
    const res = await fetchImpl(`${cfg.apiUrl}/checkout/sessions`, {
      method: "POST",
      headers: { Authorization: `Bearer ${cfg.apiKey}`, "Content-Type": "application/json" },
      body: "{}",
      cache: "no-store",
      signal: AbortSignal.timeout(4000),
    });
    ok = res.status !== 404 && res.status !== 405 && res.status < 500;
  } catch {
    ok = false;
  }
  hostedProbe = { at: now, ok };
  return ok;
}

/** Tests only. */
export function resetHostedProbe() {
  hostedProbe = null;
}

// ─── Rails ───

async function readJson(res: Response): Promise<Record<string, unknown>> {
  return (await res.json().catch(() => ({}))) as Record<string, unknown>;
}

export async function createHostedSession(
  cfg: CoinPayConfig,
  req: CheckoutRequest,
  fetchImpl: typeof fetch = fetch,
): Promise<CheckoutStarted> {
  const metadata = checkoutMetadata(req);
  const res = await fetchImpl(`${cfg.apiUrl}/checkout/sessions`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${cfg.apiKey}`,
      "Content-Type": "application/json",
      "Idempotency-Key": req.idempotencyKey,
    },
    cache: "no-store",
    body: JSON.stringify({
      business_id: cfg.businessId,
      amount: req.amountUsd,
      currency: "USD",
      description: req.description,
      customer_email: req.email ?? undefined,
      account_id: req.accountId,
      property: PROPERTY,
      metadata,
      success_url: req.successUrl,
      cancel_url: req.cancelUrl,
      expires_in_minutes: 60,
    }),
  });
  const body = await readJson(res);
  const session = (body.session ?? body) as Record<string, unknown>;
  const id = typeof session.id === "string" ? session.id : null;
  const url = typeof session.url === "string" ? session.url : null;
  if (res.status === 404 || res.status === 405) {
    hostedProbe = { at: Date.now(), ok: false };
    throw new CheckoutError("CoinPay checkout is not available yet. Pick a coin or PayPal.", 409);
  }
  if (!res.ok || !id || !url) {
    throw new CheckoutError(String(body.error ?? `CoinPay answered ${res.status}`), 502);
  }
  return { provider: "coinpay_session", method: HOSTED_METHOD, id, url, expiresAt: (session.expires_at as string) ?? null };
}

export async function createCoinPayment(
  cfg: CoinPayConfig,
  req: CheckoutRequest,
  coin: CheckoutCoin,
  fetchImpl: typeof fetch = fetch,
): Promise<CheckoutStarted> {
  const res = await fetchImpl(`${cfg.apiUrl}/payments/create`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${cfg.apiKey}`,
      "Content-Type": "application/json",
      "Idempotency-Key": req.idempotencyKey,
    },
    cache: "no-store",
    body: JSON.stringify({
      business_id: cfg.businessId,
      amount: req.amountUsd,
      currency: "USD",
      blockchain: coin,
      payment_method: "crypto",
      description: req.description,
      metadata: checkoutMetadata(req),
      redirect_url: req.successUrl,
      success_url: req.successUrl,
      cancel_url: req.cancelUrl,
      webhook_url: `${process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com"}/api/webhooks/coinpay`,
      expires_in_minutes: 60,
    }),
  });
  const body = await readJson(res);
  const p = (body.payment ?? {}) as Record<string, unknown>;
  const id = (p.id as string | undefined) ?? (body.payment_id as string | undefined);
  if (!res.ok || !id) {
    throw new CheckoutError(String(body.error ?? `CoinPay answered ${res.status}`), 502);
  }
  const crypto = p.crypto_amount ?? p.amount_crypto;
  return {
    provider: "coinpay",
    method: coin,
    id,
    url: `${base(cfg)}/pay/${encodeURIComponent(id)}`,
    address: (p.payment_address as string | undefined) ?? null,
    amountCrypto: crypto != null ? String(crypto) : null,
    expiresAt: (p.expires_at as string | undefined) ?? null,
  };
}

/**
 * `amount` is MAJOR units (dollars) on CoinPay's PayPal rail. The returned
 * transaction id is the `payment_id` of the payment.confirmed webhook CoinPay
 * sends on capture.
 */
export async function createPaypalPayment(
  cfg: CoinPayConfig,
  req: CheckoutRequest,
  fetchImpl: typeof fetch = fetch,
): Promise<CheckoutStarted> {
  const res = await fetchImpl(`${cfg.apiUrl}/paypal/payments/create`, {
    method: "POST",
    headers: { Authorization: `Bearer ${cfg.apiKey}`, "Content-Type": "application/json" },
    cache: "no-store",
    body: JSON.stringify({
      business_id: cfg.businessId,
      amount: req.amountUsd,
      currency: "USD",
      description: req.description,
      customer_email: req.email ?? undefined,
      metadata: checkoutMetadata(req),
      success_url: req.successUrl,
      cancel_url: req.cancelUrl,
      invoiceNumber: req.idempotencyKey,
    }),
  });
  const body = await readJson(res);
  const id = typeof body.transaction_id === "string" ? body.transaction_id : null;
  if (!res.ok || !id) {
    throw new CheckoutError(String(body.error ?? `CoinPay PayPal answered ${res.status}`), 502);
  }
  // Built from our own config rather than trusted from the response.
  return { provider: "paypal", method: PAYPAL_METHOD, id, url: `${base(cfg)}/pay/paypal/${encodeURIComponent(id)}` };
}

export async function startCheckout(
  method: CheckoutMethod,
  req: CheckoutRequest,
  cfg: CoinPayConfig | null = coinpayConfig(),
  fetchImpl: typeof fetch = fetch,
): Promise<CheckoutStarted> {
  if (!cfg) throw new CheckoutError("Payments are not configured on this server.", 503);
  if (method === HOSTED_METHOD) return createHostedSession(cfg, req, fetchImpl);
  if (method === PAYPAL_METHOD) return createPaypalPayment(cfg, req, fetchImpl);
  return createCoinPayment(cfg, req, method, fetchImpl);
}

/** The ids a webhook may name an order by: the payment, and the hosted session it came from. */
export function webhookOrderIds(payload: unknown): string[] {
  const p = (payload ?? {}) as Record<string, unknown>;
  const d = (p.data && typeof p.data === "object" ? p.data : p) as Record<string, unknown>;
  const ids = [d.payment_id, d.checkout_session_id, p.checkout_session_id, p.data ? d.id : null];
  return [...new Set(ids.filter((x): x is string => typeof x === "string" && x.length > 0))];
}

/** The ways to pay right now, best first, for a picker. */
export async function availableMethods(): Promise<{ hosted: boolean; methods: Array<{ id: CheckoutMethod; label: string }> }> {
  const hosted = await hostedCheckoutAvailable();
  return {
    hosted,
    methods: [
      ...(hosted ? [{ id: HOSTED_METHOD as CheckoutMethod, label: "Any coin or PayPal (CoinPay checkout)" }] : []),
      { id: CHECKOUT_COINS[0], label: COIN_LABELS[CHECKOUT_COINS[0]] },
      { id: PAYPAL_METHOD, label: "PayPal" },
      ...CHECKOUT_COINS.slice(1).map((c) => ({ id: c as CheckoutMethod, label: COIN_LABELS[c] })),
    ],
  };
}
