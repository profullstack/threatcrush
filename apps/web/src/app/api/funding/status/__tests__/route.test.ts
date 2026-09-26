import { describe, it, expect, vi, beforeEach } from "vitest";
import { NextRequest } from "next/server";
import type * as CoinpayClient from "@/lib/coinpay-client";

// vi.mock factories are hoisted above the imports, so anything they close over
// must be hoisted with them.
const { db, mockLiveStatus } = vi.hoisted(() => ({
  // The funding_payments row as the database holds it.
  db: { status: "pending" },
  mockLiveStatus: vi.fn(),
}));

/**
 * funding_payments with PostgREST filter semantics: the SELECT returns the
 * stored row; an UPDATE applies only when the row passes every
 * `.not(column, "in", list)` filter.
 */
vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: () => ({
      select: () => ({
        eq: () => ({
          maybeSingle: async () => ({ data: { ...db }, error: null }),
        }),
      }),
      update: (patch: { status: string }) => {
        const excluded: string[][] = [];
        const chain = {
          eq: () => chain,
          not: (column: string, op: string, list: string) => {
            expect([column, op]).toEqual(["status", "in"]);
            excluded.push(list.replace(/^\(|\)$/g, "").split(",").map((v) => v.replace(/^"|"$/g, "")));
            return chain;
          },
          then: (resolve: (v: unknown) => void) => {
            if (excluded.every((l) => !l.includes(db.status))) db.status = patch.status;
            resolve({ error: null });
          },
        };
        return chain;
      },
    }),
  }),
}));

vi.mock("@/lib/coinpay-client", async (importOriginal) => ({
  ...(await importOriginal<typeof CoinpayClient>()),
  getCoinpayPaymentStatus: mockLiveStatus,
}));

import { GET } from "@/app/api/funding/status/route";
import { CoinpayError, CoinpayNotConfiguredError } from "@/lib/coinpay-client";

function makeRequest() {
  return new NextRequest("http://localhost/api/funding/status?payment_id=pay-001");
}

describe("GET /api/funding/status", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  // TC-10: a confirmed row is re-polled against CoinPay, and the live lookup
  // falls back to "pending" when the response has no status. That used to be
  // written straight over the settled row.
  it("does not regress a settled payment to a lagging live status", async () => {
    db.status = "confirmed";
    mockLiveStatus.mockResolvedValue({ status: "pending", tx_hash: null });

    const res = await GET(makeRequest());

    expect(res.status).toBe(200);
    expect(db.status).toBe("confirmed");
  });

  it("still moves a confirmed payment on to forwarded", async () => {
    db.status = "confirmed";
    mockLiveStatus.mockResolvedValue({ status: "forwarded", tx_hash: "0xabc" });

    await GET(makeRequest());

    expect(db.status).toBe("forwarded");
  });

  it("still records an unsettled payment expiring", async () => {
    db.status = "pending";
    mockLiveStatus.mockResolvedValue({ status: "expired", tx_hash: null });

    await GET(makeRequest());

    expect(db.status).toBe("expired");
  });

  describe("when the live CoinPay lookup fails", () => {
    beforeEach(() => {
      db.status = "pending";
      vi.spyOn(console, "error").mockImplementation(() => {});
    });

    it("answers 404 JSON for a payment id CoinPay does not know", async () => {
      mockLiveStatus.mockRejectedValue(new CoinpayError("CoinPay status failed: 404", 404));

      const res = await GET(makeRequest());

      expect(res.status).toBe(404);
      expect(await res.json()).toEqual({ error: expect.any(String) });
      expect(db.status).toBe("pending");
    });

    it("answers 502 JSON when CoinPay errors or is unreachable", async () => {
      for (const err of [new CoinpayError("CoinPay status failed: 500", 500), new TypeError("fetch failed")]) {
        mockLiveStatus.mockRejectedValueOnce(err);

        const res = await GET(makeRequest());

        expect(res.status).toBe(502);
        expect(await res.json()).toEqual({ error: expect.any(String) });
      }
    });

    it("answers 503 JSON when CoinPay credentials are not configured", async () => {
      mockLiveStatus.mockRejectedValue(new CoinpayNotConfiguredError());

      const res = await GET(makeRequest());

      expect(res.status).toBe(503);
      expect(await res.json()).toEqual({ error: expect.any(String) });
    });
  });
});
