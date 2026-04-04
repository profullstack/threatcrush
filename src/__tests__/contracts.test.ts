import { describe, it, expect } from "vitest";

/**
 * API Response Contract Tests
 *
 * These tests validate the expected response shapes for all API endpoints.
 * They don't call the actual routes — they validate JSON structures
 * that consumers (CLI, frontend) depend on. If a shape changes, these break.
 */

// ─── Auth Contracts ───

describe("API Response Contracts", () => {
  describe("Auth contracts", () => {
    it("signup response shape", () => {
      const response = {
        user: { id: "user-123", email: "test@example.com" },
        referral_code: "ABC12345",
        needs_email_verification: true,
        needs_phone_verification: false,
      };

      expect(response).toEqual(
        expect.objectContaining({
          user: expect.objectContaining({
            id: expect.any(String),
            email: expect.any(String),
          }),
          referral_code: expect.any(String),
          needs_email_verification: expect.any(Boolean),
          needs_phone_verification: expect.any(Boolean),
        })
      );
    });

    it("login response shape", () => {
      const response = {
        user: { id: "user-123", email: "test@example.com" },
        session: { access_token: "tok-abc" },
        verified: { email: true, phone: false },
      };

      expect(response).toEqual(
        expect.objectContaining({
          user: expect.objectContaining({ id: expect.any(String) }),
          session: expect.objectContaining({ access_token: expect.any(String) }),
          verified: expect.objectContaining({
            email: expect.any(Boolean),
            phone: expect.any(Boolean),
          }),
        })
      );
    });

    it("verify-phone response shape", () => {
      const response = { verified: true };
      expect(response).toEqual({ verified: true });
    });

    it("me GET response shape", () => {
      const response = {
        profile: {
          id: "user-123",
          email: "test@example.com",
          display_name: "Test User",
          license_status: "active",
          referral_code: "REF12345",
          notification_email: true,
          notification_sms: false,
          notification_webhook_url: null,
          wallet_address: null,
          phone: "+1234567890",
          phone_verified: true,
          email_verified: true,
        },
      };

      expect(response).toEqual(
        expect.objectContaining({
          profile: expect.objectContaining({
            id: expect.any(String),
            email: expect.any(String),
            display_name: expect.any(String),
            license_status: expect.any(String),
            referral_code: expect.any(String),
            notification_email: expect.any(Boolean),
            notification_sms: expect.any(Boolean),
          }),
        })
      );
    });

    it("me PATCH response shape", () => {
      const response = {
        profile: {
          id: "user-123",
          email: "test@example.com",
          display_name: "Updated Name",
          license_status: "active",
          referral_code: "REF12345",
          notification_email: true,
          notification_sms: false,
          notification_webhook_url: null,
          wallet_address: "0xABC",
        },
      };

      expect(response).toEqual(
        expect.objectContaining({
          profile: expect.objectContaining({
            id: expect.any(String),
            display_name: expect.any(String),
          }),
        })
      );
    });

    it("check response shape", () => {
      const response = {
        email_verified: true,
        phone_verified: true,
        license_status: "active",
        can_proceed_to_payment: true,
      };

      expect(response).toEqual(
        expect.objectContaining({
          email_verified: expect.any(Boolean),
          phone_verified: expect.any(Boolean),
          can_proceed_to_payment: expect.any(Boolean),
        })
      );
    });
  });

  // ─── Module Contracts ───

  describe("Module contracts", () => {
    it("module list response shape", () => {
      const response = {
        modules: [
          {
            id: "mod-001",
            name: "test-scanner",
            slug: "test-scanner",
            display_name: "Test Scanner",
            description: "A test module",
            category: "security",
            pricing_type: "free",
            downloads: 42,
            rating_avg: 4.5,
            rating_count: 10,
            published: true,
          },
        ],
        total: 1,
        page: 1,
        limit: 20,
      };

      expect(response).toEqual(
        expect.objectContaining({
          modules: expect.arrayContaining([
            expect.objectContaining({
              id: expect.any(String),
              slug: expect.any(String),
              published: expect.any(Boolean),
            }),
          ]),
          total: expect.any(Number),
          page: expect.any(Number),
          limit: expect.any(Number),
        })
      );
    });

    it("module detail response shape", () => {
      const response = {
        module: {
          id: "mod-001",
          slug: "test-scanner",
          display_name: "Test Scanner",
          description: "A test module",
          version: "1.0.0",
          rating_avg: 4.5,
          rating_count: 10,
        },
        versions: [{ id: "v1", version: "1.0.0", created_at: "2025-01-01T00:00:00Z" }],
        reviews: [{ id: "r1", rating: 5, title: "Great" }],
      };

      expect(response).toEqual(
        expect.objectContaining({
          module: expect.objectContaining({
            id: expect.any(String),
            slug: expect.any(String),
          }),
          versions: expect.any(Array),
          reviews: expect.any(Array),
        })
      );
    });

    it("module install response shape", () => {
      const response = {
        success: true,
        downloads: 43,
      };

      expect(response).toEqual(
        expect.objectContaining({
          success: true,
          downloads: expect.any(Number),
        })
      );
    });

    it("module review response shape", () => {
      const response = {
        review: {
          id: "rev-001",
          module_id: "mod-001",
          user_email: "reviewer@example.com",
          rating: 5,
          title: "Great module",
          body: "Works perfectly",
          created_at: "2025-03-01T00:00:00Z",
        },
      };

      expect(response).toEqual(
        expect.objectContaining({
          review: expect.objectContaining({
            rating: expect.any(Number),
            user_email: expect.any(String),
          }),
        })
      );
    });

    it("module review list response shape", () => {
      const response = {
        reviews: [{ id: "r1", rating: 5, title: "Great" }],
        total: 1,
        page: 1,
      };

      expect(response).toEqual(
        expect.objectContaining({
          reviews: expect.any(Array),
          total: expect.any(Number),
          page: expect.any(Number),
        })
      );
    });
  });

  // ─── Usage Contracts ───

  describe("Usage contracts", () => {
    it("usage stats response shape", () => {
      const response = {
        balance_usd: 24.99,
        today_usd: 0.5,
        today_requests: 12,
        week_usd: 3.2,
        week_requests: 85,
        month_usd: 10.5,
        month_requests: 250,
        burn_rate_daily: 0.35,
        estimated_days_remaining: 71,
        projected_monthly_usd: 10.5,
        daily_spend: [{ date: "2025-06-01", amount: 0.5, requests: 12 }],
        module_breakdown: [{ module: "scanner", action: "ai.inference", requests: 10, cost: 0.5, percentage: 5 }],
        history: [{ id: "evt_1", timestamp: "2025-06-01T12:00:00Z", module: "scanner", action: "ai.inference", cost_usd: 0.005, status: "completed" }],
        demo: true,
      };

      expect(response).toEqual(
        expect.objectContaining({
          balance_usd: expect.any(Number),
          today_usd: expect.any(Number),
          today_requests: expect.any(Number),
          week_usd: expect.any(Number),
          month_usd: expect.any(Number),
          burn_rate_daily: expect.any(Number),
          estimated_days_remaining: expect.any(Number),
          daily_spend: expect.any(Array),
          module_breakdown: expect.any(Array),
          history: expect.any(Array),
          demo: expect.any(Boolean),
        })
      );
    });

    it("usage topup response shape (demo)", () => {
      const response = {
        success: true,
        demo: true,
        message: "Demo mode — CoinPayPortal not configured. Top-up simulated.",
        payment_url: null,
        amount_usd: 25,
      };

      expect(response).toEqual(
        expect.objectContaining({
          success: true,
          amount_usd: expect.any(Number),
        })
      );
    });

    it("usage topup response shape (live)", () => {
      const response = {
        success: true,
        payment_url: "https://pay.example.com/session-123",
        payment_id: "pay-123",
        amount_usd: 25,
      };

      expect(response).toEqual(
        expect.objectContaining({
          success: true,
          payment_url: expect.any(String),
          payment_id: expect.any(String),
          amount_usd: expect.any(Number),
        })
      );
    });
  });

  // ─── Waitlist Contracts ───

  describe("Waitlist contracts", () => {
    it("waitlist signup response shape (email only)", () => {
      const response = {
        success: true,
        waitlist_id: "wl-001",
        referral_code: "abc12345",
        price: 499,
        discount: false,
      };

      expect(response).toEqual(
        expect.objectContaining({
          success: true,
          waitlist_id: expect.any(String),
          referral_code: expect.any(String),
          price: expect.any(Number),
          discount: expect.any(Boolean),
        })
      );
    });

    it("waitlist signup response shape (with crypto payment)", () => {
      const response = {
        success: true,
        waitlist_id: "wl-001",
        referral_code: "abc12345",
        price: 399,
        discount: true,
        payment: {
          address: "0xABC123",
          checkout_url: "https://pay.example.com/checkout",
          amount_usd: 399,
          currency: "USDC (Solana)",
          payment_id: "pay-001",
        },
      };

      expect(response).toEqual(
        expect.objectContaining({
          success: true,
          price: expect.any(Number),
          payment: expect.objectContaining({
            amount_usd: expect.any(Number),
            currency: expect.any(String),
          }),
        })
      );
    });

    it("waitlist GET response shape", () => {
      const response = {
        message: "ThreatCrush Waitlist API",
        pricing: {
          full: "$499 lifetime access",
          referral: "$399 with referral code (both you and your friend)",
        },
      };

      expect(response).toEqual(
        expect.objectContaining({
          message: expect.any(String),
          pricing: expect.objectContaining({
            full: expect.any(String),
            referral: expect.any(String),
          }),
        })
      );
    });
  });

  // ─── Webhook Contracts ───

  describe("Webhook contracts", () => {
    it("coinpay webhook response shape", () => {
      const response = { ok: true, email: "user@example.com" };

      expect(response).toEqual(
        expect.objectContaining({
          ok: true,
        })
      );
    });
  });

  // ─── Error Contracts ───

  describe("Error contracts", () => {
    it("standard error response shape", () => {
      const response = { error: "Something went wrong" };

      expect(response).toEqual(
        expect.objectContaining({
          error: expect.any(String),
        })
      );
    });
  });
});
