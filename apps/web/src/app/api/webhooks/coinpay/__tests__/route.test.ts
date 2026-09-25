import { describe, it, expect, vi, beforeEach } from "vitest";
import { createHmac } from "node:crypto";

// ─── Mock setup ───
// The coinpay route creates its own supabase client via createClient directly.
// Chain patterns used:
//   .from(<payment table>).select("id, …").eq("coinpay_payment_id", paymentId).maybeSingle()
//   .from(<payment table>).update({...}).eq("coinpay_payment_id", paymentId)
//       [.not("status", "in", '("confirmed","forwarded")')].select("id")  ← awaited
//   .from("waitlist").select("id, email, paid").eq("payment_id", paymentId).maybeSingle()
//   .from("waitlist").update({...}).eq("id", entry.id)       ← awaited directly
//   .from("waitlist").select("referred_by").eq("id", entry.id).single()
//   .from("waitlist").update({amount_usd:399}).eq("referral_code",...).eq("paid",false)  ← awaited

const mockFundingMaybeSingle = vi.fn();
const mockLicenseMaybeSingle = vi.fn();
const mockCreditMaybeSingle = vi.fn();
const mockWaitlistMaybeSingle = vi.fn();
const mockWaitlistSingle = vi.fn();
// Records every .update(patch) as (table, patch) so tests can assert on writes.
const mockUpdate = vi.fn();

const PAYMENT_TABLES = ["funding_payments", "credit_deposits", "license_purchases"];
// Status the payment row holds at the moment the UPDATE runs, per table. A test
// can make it differ from what the lookup returned to model another delivery
// for the same payment committing between this request's read and its write.
let storedStatus: Record<string, string | undefined> = {};

/**
 * An UPDATE on a payment table: applies only when the stored row passes every
 * `.not(column, "in", list)` filter, like PostgREST, and resolves with the rows
 * it touched when `.select()` asks for them.
 */
function paymentUpdateChain(table: string, patch: { status?: string }) {
  const excluded: string[][] = [];
  const run = () => {
    const current = storedStatus[table];
    const matches = current !== undefined && excluded.every((list) => !list.includes(current));
    if (matches && patch.status) storedStatus[table] = patch.status;
    return matches;
  };
  const chain = {
    eq: vi.fn().mockImplementation(() => chain),
    not: vi.fn().mockImplementation((column: string, op: string, list: string) => {
      expect([column, op]).toEqual(["status", "in"]);
      excluded.push(list.replace(/^\(|\)$/g, "").split(",").map((v) => v.replace(/^"|"$/g, "")));
      return chain;
    }),
    select: vi.fn().mockImplementation(() => ({
      then: (resolve: (v: unknown) => void) =>
        resolve({ data: run() ? [{ id: `${table}-row` }] : [], error: null }),
    })),
    then: (resolve: (v: unknown) => void) => {
      run();
      resolve({ error: null });
    },
  };
  return chain;
}

// Build a chainable mock for a specific table
function buildTableMock(table: string) {
  if (PAYMENT_TABLES.includes(table)) {
    const lookup =
      table === "funding_payments" ? mockFundingMaybeSingle
      : table === "credit_deposits" ? mockCreditMaybeSingle
      : mockLicenseMaybeSingle;
    const chainableEq = () => ({
      eq: vi.fn().mockImplementation(() => chainableEq()),
      maybeSingle: lookup,
    });
    return {
      select: vi.fn().mockImplementation(() => chainableEq()),
      update: vi.fn().mockImplementation((patch: { status?: string }) => paymentUpdateChain(table, patch)),
    };
  }
  // waitlist table
  const chainableEq = () => ({
    eq: vi.fn().mockImplementation(() => chainableEq()),
    maybeSingle: mockWaitlistMaybeSingle,
    single: mockWaitlistSingle,
    then: (resolve: (v: unknown) => void) => resolve({ error: null }),
  });
  return {
    select: vi.fn().mockImplementation(() => chainableEq()),
    update: vi.fn().mockImplementation(() => chainableEq()),
  };
}

function resetMocks(overrides: {
  findEntryResult?: { data: unknown; error: unknown };
  referralResult?: { data: unknown; error: unknown };
} = {}) {
  const findEntryResult = overrides.findEntryResult ?? {
    data: { id: "wl-001", email: "user@example.com", paid: false },
    error: null,
  };
  const referralResult = overrides.referralResult ?? {
    data: { referred_by: "REF123" },
    error: null,
  };

  mockFundingMaybeSingle.mockResolvedValue({ data: null, error: null });
  mockLicenseMaybeSingle.mockResolvedValue({ data: null, error: null });
  mockCreditMaybeSingle.mockResolvedValue({ data: null, error: null });
  mockWaitlistMaybeSingle.mockResolvedValue(findEntryResult);
  mockWaitlistSingle.mockResolvedValue(referralResult);
  storedStatus = {};
}

vi.mock("@supabase/supabase-js", () => ({
  createClient: () => ({
    from: (table: string) => {
      const tableMock = buildTableMock(table);
      const update = tableMock.update;
      tableMock.update = vi.fn().mockImplementation((patch: unknown) => {
        mockUpdate(table, patch);
        return update(patch);
      });
      return tableMock;
    },
  }),
}));

import { POST, logSafe } from "@/app/api/webhooks/coinpay/route";

const WEBHOOK_SECRET = "test-webhook-secret";

/**
 * Real signature, not a mocked verifier: TC-09 was specifically about a branch
 * that skipped this check, so the tests should exercise the genuine one.
 */
function signBody(rawBody: string): string {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const sig = createHmac("sha256", WEBHOOK_SECRET)
    .update(`${timestamp}.${rawBody}`)
    .digest("hex");
  return `t=${timestamp},v1=${sig}`;
}

function makeRequest(body: unknown, opts: { signed?: boolean } = {}) {
  const rawBody = JSON.stringify(body);
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.signed !== false) headers["x-coinpay-signature"] = signBody(rawBody);

  return new Request("http://localhost/api/webhooks/coinpay", {
    method: "POST",
    headers,
    body: rawBody,
  }) as unknown as import("next/server").NextRequest;
}

describe("POST /api/webhooks/coinpay", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.COINPAY_WEBHOOK_SECRET = WEBHOOK_SECRET;
    resetMocks();
  });

  it("handles payment.confirmed event", async () => {
    const req = makeRequest({
      type: "payment.confirmed",
      data: { payment_id: "pay-001", status: "confirmed" },
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.email).toBe("user@example.com");
  });

  // TC-09: the waitlist branch used to be reachable with no signature at all,
  // so anyone who knew a payment id could mark a waitlist row paid.
  it("rejects an unsigned waitlist callback", async () => {
    const req = makeRequest(
      { type: "payment.confirmed", data: { payment_id: "pay-001", status: "confirmed" } },
      { signed: false },
    );
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(401);
    expect(body.error).toContain("Invalid signature");
  });

  it("rejects a waitlist callback with a forged signature", async () => {
    const rawBody = JSON.stringify({
      type: "payment.confirmed",
      data: { payment_id: "pay-001", status: "confirmed" },
    });
    const req = new Request("http://localhost/api/webhooks/coinpay", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-coinpay-signature": `t=${Math.floor(Date.now() / 1000)},v1=${"00".repeat(32)}`,
      },
      body: rawBody,
    }) as unknown as import("next/server").NextRequest;

    const res = await POST(req);
    expect(res.status).toBe(401);
  });

  it("rejects missing payment_id", async () => {
    const req = makeRequest({ type: "payment.confirmed", data: {} });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(400);
    expect(body.error).toContain("Missing payment_id");
  });

  it("ignores non-confirmed events", async () => {
    const req = makeRequest({
      type: "payment.pending",
      data: { payment_id: "pay-001", status: "pending" },
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.email).toBeUndefined();
  });

  it("skips already-paid entries", async () => {
    resetMocks({
      findEntryResult: {
        data: { id: "wl-001", email: "user@example.com", paid: true },
        error: null,
      },
    });

    const req = makeRequest({
      type: "payment.confirmed",
      data: { payment_id: "pay-001", status: "confirmed" },
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
  });

  it("handles missing waitlist entry gracefully", async () => {
    resetMocks({
      findEntryResult: { data: null, error: null },
    });

    const req = makeRequest({
      type: "payment.confirmed",
      data: { payment_id: "pay-999", status: "confirmed" },
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
  });

  it("processes forwarded status", async () => {
    const req = makeRequest({
      type: "payment.forwarded",
      data: { payment_id: "pay-001", status: "forwarded" },
    });
    const res = await POST(req);
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body.ok).toBe(true);
    expect(body.email).toBe("user@example.com");
  });

  it("response shape matches contract", async () => {
    const req = makeRequest({
      type: "payment.confirmed",
      data: { payment_id: "pay-001", status: "confirmed" },
    });
    const res = await POST(req);
    const body = await res.json();

    expect(body).toEqual(
      expect.objectContaining({
        ok: true,
      })
    );
  });

  // TC-10: a late payment.expired / payment.failed after settlement used to
  // overwrite the settled funding and license rows.
  it("ignores a late expired event for a settled funding payment", async () => {
    mockFundingMaybeSingle.mockResolvedValue({ data: { id: "fund-001" }, error: null });
    storedStatus.funding_payments = "confirmed";

    const res = await POST(makeRequest({
      type: "payment.expired",
      data: { payment_id: "pay-001", status: "expired" },
    }));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body).toEqual({ received: true, ignored: "stale event" });
    expect(storedStatus.funding_payments).toBe("confirmed");
  });

  it("still applies a forwarded event to a confirmed funding payment", async () => {
    mockFundingMaybeSingle.mockResolvedValue({ data: { id: "fund-001" }, error: null });
    storedStatus.funding_payments = "confirmed";

    const res = await POST(makeRequest({
      type: "payment.forwarded",
      data: { payment_id: "pay-001", status: "forwarded", tx_hash: "0xabc" },
    }));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body).toEqual({ received: true });
    expect(storedStatus.funding_payments).toBe("forwarded");
    expect(mockUpdate).toHaveBeenCalledWith(
      "funding_payments",
      expect.objectContaining({ status: "forwarded", tx_hash: "0xabc" }),
    );
  });

  it("ignores a late expired event for a settled license purchase", async () => {
    mockLicenseMaybeSingle.mockResolvedValue({
      data: { id: "lic-001", user_id: "user-001", email: "user@example.com" },
      error: null,
    });
    storedStatus.license_purchases = "confirmed";

    const res = await POST(makeRequest({
      type: "payment.expired",
      data: { payment_id: "pay-001", status: "expired" },
    }));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body).toEqual({ received: true, ignored: "stale event" });
    expect(storedStatus.license_purchases).toBe("confirmed");
  });

  // The guard used to be read-then-write: two deliveries for the same payment
  // could both read "pending", and the expired one then overwrote the confirm
  // that committed in between. The lookup here returns that stale snapshot.
  it.each([
    ["funding_payments", mockFundingMaybeSingle, { id: "fund-001", status: "pending" }],
    ["credit_deposits", mockCreditMaybeSingle,
      { id: "dep-001", user_id: "user-001", email: "user@example.com", amount_usd: 25, status: "pending" }],
    ["license_purchases", mockLicenseMaybeSingle,
      { id: "lic-001", user_id: "user-001", email: "user@example.com", status: "pending" }],
  ])("does not regress a %s row settled by a concurrent delivery", async (table, lookup, row) => {
    lookup.mockResolvedValue({ data: row, error: null });
    storedStatus[table] = "confirmed";

    const res = await POST(makeRequest({
      type: "payment.failed",
      data: { payment_id: "pay-001", status: "failed" },
    }));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body).toEqual({ received: true, ignored: "stale event" });
    expect(storedStatus[table]).toBe("confirmed");
    expect(mockUpdate).not.toHaveBeenCalledWith("user_profiles", expect.anything());
  });

  it("still expires a deposit that never settled", async () => {
    mockCreditMaybeSingle.mockResolvedValue({
      data: { id: "dep-001", user_id: "user-001", email: "user@example.com", amount_usd: 25 },
      error: null,
    });
    storedStatus.credit_deposits = "pending";

    const res = await POST(makeRequest({
      type: "payment.expired",
      data: { payment_id: "pay-001", status: "expired" },
    }));
    const body = await res.json();

    expect(res.status).toBe(200);
    expect(body).toEqual({ received: true });
    expect(storedStatus.credit_deposits).toBe("expired");
  });
});

// TC-46: a CRLF in a webhook field could forge an extra log line and fake a
// settlement in an audit trail.
describe("logSafe", () => {
  it("collapses newlines so a value cannot forge a log line", () => {
    expect(logSafe("pay-001\n[coinpay webhook] credited 999999")).toBe(
      "pay-001 [coinpay webhook] credited 999999",
    );
    expect(logSafe("a\r\nb")).toBe("a  b");
  });

  it("strips other control characters", () => {
    expect(logSafe("a\u0000b\u001fc\u007fd")).toBe("a b c d");
  });

  it("caps length and handles nullish input", () => {
    expect(logSafe("x".repeat(500))).toHaveLength(200);
    expect(logSafe(null)).toBe("");
    expect(logSafe(undefined)).toBe("");
  });
});
