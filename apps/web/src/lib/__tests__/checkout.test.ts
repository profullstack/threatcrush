import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  CHECKOUT_COINS,
  checkoutMetadata,
  hostedCheckoutAvailable,
  normalizeMethod,
  resetHostedProbe,
  startCheckout,
  webhookOrderIds,
  type CheckoutRequest,
  type CoinPayConfig,
} from "@/lib/checkout";

const cfg: CoinPayConfig = { apiUrl: "https://coinpayportal.com/api", apiKey: "cp_live_x", businessId: "biz" };

const req: CheckoutRequest = {
  amountUsd: 400,
  description: "ThreatCrush Security Scan",
  email: "buyer@example.com",
  accountId: "user-1",
  product: "scan",
  metadata: { plan: "scan", org_id: null },
  successUrl: "https://threatcrush.com/hire?payment=success",
  cancelUrl: "https://threatcrush.com/pricing?payment=cancelled",
  idempotencyKey: "tc-scan-1",
};

function res(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

describe("checkout methods", () => {
  it("offers every chain the business holds a wallet for", () => {
    expect(CHECKOUT_COINS).toHaveLength(15);
    for (const c of ["BTC", "ETH", "SOL", "POL", "BCH", "DOGE", "XRP", "ADA", "BNB", "USDC_POL", "USDT_SOL"]) {
      expect(CHECKOUT_COINS).toContain(c);
    }
  });

  it("normalizes old lowercase ids, PayPal and the hosted checkout", () => {
    expect(normalizeMethod("usdc_pol")).toBe("USDC_POL");
    expect(normalizeMethod("usdt")).toBe("USDT_ETH");
    expect(normalizeMethod("paypal")).toBe("PAYPAL");
    expect(normalizeMethod("coinpay")).toBe("COINPAY");
    expect(normalizeMethod("card")).toBeNull();
    expect(normalizeMethod("")).toBeNull();
  });

  it("always sends property, account_id, email and product as strings", () => {
    expect(checkoutMetadata(req)).toEqual({
      plan: "scan",
      property: "threatcrush.com",
      account_id: "user-1",
      email: "buyer@example.com",
      product: "scan",
    });
  });
});

describe("hosted checkout feature detection", () => {
  beforeEach(() => resetHostedProbe());

  it("is off while CoinPay answers 404", async () => {
    const f = vi.fn().mockResolvedValue(res(404, {}));
    expect(await hostedCheckoutAvailable(cfg, f as never, 0)).toBe(false);
  });

  it("is on once the endpoint answers (a 400 for the empty probe body)", async () => {
    const f = vi.fn().mockResolvedValue(res(400, { error: "amount is required" }));
    expect(await hostedCheckoutAvailable(cfg, f as never, 0)).toBe(true);
    // cached
    expect(await hostedCheckoutAvailable(cfg, f as never, 1000)).toBe(true);
    expect(f).toHaveBeenCalledTimes(1);
  });

  it("is off with no credentials", async () => {
    expect(await hostedCheckoutAvailable(null)).toBe(false);
  });
});

describe("startCheckout", () => {
  it("hosted: posts the session contract and returns its url", async () => {
    const f = vi.fn().mockResolvedValue(res(201, { id: "cs_1", url: "https://coinpayportal.com/checkout/cs_1" }));
    const r = await startCheckout("COINPAY", req, cfg, f as never);
    expect(r).toMatchObject({ provider: "coinpay_session", id: "cs_1", url: "https://coinpayportal.com/checkout/cs_1" });
    const [url, init] = f.mock.calls[0];
    expect(url).toBe("https://coinpayportal.com/api/checkout/sessions");
    const body = JSON.parse(init.body);
    expect(body).toMatchObject({
      amount: 400,
      currency: "USD",
      customer_email: "buyer@example.com",
      account_id: "user-1",
      property: "threatcrush.com",
      expires_in_minutes: 60,
    });
    expect(body.metadata.property).toBe("threatcrush.com");
    expect(init.headers.Authorization).toBe("Bearer cp_live_x");
  });

  it("hosted: a 404 says pick a coin or PayPal (409)", async () => {
    const f = vi.fn().mockResolvedValue(res(404, {}));
    await expect(startCheckout("COINPAY", req, cfg, f as never)).rejects.toMatchObject({ status: 409 });
  });

  it("coin: opens a payment on the chosen chain with the metadata", async () => {
    const f = vi.fn().mockResolvedValue(
      res(201, { success: true, payment: { id: "pay_1", payment_address: "addr", crypto_amount: "0.004" } }),
    );
    const r = await startCheckout("BTC", req, cfg, f as never);
    expect(r).toMatchObject({ provider: "coinpay", id: "pay_1", url: "https://coinpayportal.com/pay/pay_1", address: "addr" });
    const body = JSON.parse(f.mock.calls[0][1].body);
    expect(body).toMatchObject({ blockchain: "BTC", amount: 400, currency: "USD", business_id: "biz" });
    expect(body.metadata).toMatchObject({ property: "threatcrush.com", account_id: "user-1", email: "buyer@example.com" });
  });

  it("paypal: opens an order on CoinPay's PayPal rail", async () => {
    const f = vi.fn().mockResolvedValue(res(200, { transaction_id: "ppt_1" }));
    const r = await startCheckout("PAYPAL", req, cfg, f as never);
    expect(f.mock.calls[0][0]).toBe("https://coinpayportal.com/api/paypal/payments/create");
    expect(r).toMatchObject({ provider: "paypal", id: "ppt_1", url: "https://coinpayportal.com/pay/paypal/ppt_1" });
    const body = JSON.parse(f.mock.calls[0][1].body);
    expect(body).toMatchObject({ amount: 400, customer_email: "buyer@example.com", invoiceNumber: "tc-scan-1" });
  });

  it("refuses without credentials", async () => {
    await expect(startCheckout("BTC", req, null)).rejects.toMatchObject({ status: 503 });
  });
});

describe("webhookOrderIds", () => {
  it("names the payment and the hosted session", () => {
    expect(webhookOrderIds({ data: { payment_id: "pay_1", checkout_session_id: "cs_1" } })).toEqual(["pay_1", "cs_1"]);
    expect(webhookOrderIds({ data: { payment_id: "pay_1" } })).toEqual(["pay_1"]);
  });
});
