import { describe, expect, it } from "vitest";
import { createHmac } from "node:crypto";
import {
  buildPurchaseRow,
  currentPurchaseFor,
  isMarketplaceAction,
  isStaleEvent,
  parseWebhookBody,
  verifyGithubSignature,
  type MarketplaceEventPayload,
} from "../github-marketplace";

const SECRET = "s3cret-webhook-token";

function sign(body: string, secret = SECRET): string {
  return `sha256=${createHmac("sha256", secret).update(body, "utf8").digest("hex")}`;
}

// Shaped after the example payload in GitHub's docs.
const PURCHASED: MarketplaceEventPayload = {
  action: "purchased",
  effective_date: "2026-08-21T00:00:00+00:00",
  sender: { login: "octocat" },
  marketplace_purchase: {
    account: {
      type: "Organization",
      id: 18404712,
      node_id: "MDEyOk9yZ2FuaXphdGlvbjE4NDA0NzEy",
      login: "acme-corp",
      organization_billing_email: "billing@acme.test",
    },
    billing_cycle: "monthly",
    unit_count: 3,
    on_free_trial: false,
    free_trial_ends_on: null,
    next_billing_date: "2026-09-21T00:00:00+00:00",
    plan: {
      id: 435,
      name: "Pro Plan",
      monthly_price_in_cents: 999,
      yearly_price_in_cents: 9999,
    },
  },
};

describe("verifyGithubSignature", () => {
  it("accepts a correctly signed body", () => {
    const body = JSON.stringify(PURCHASED);
    expect(verifyGithubSignature(body, sign(body), SECRET)).toBe(true);
  });

  it("rejects a body signed with a different secret", () => {
    const body = JSON.stringify(PURCHASED);
    expect(verifyGithubSignature(body, sign(body, "wrong"), SECRET)).toBe(false);
  });

  it("rejects a tampered body", () => {
    const body = JSON.stringify(PURCHASED);
    const signature = sign(body);
    expect(verifyGithubSignature(body + " ", signature, SECRET)).toBe(false);
  });

  it("rejects when the secret is missing, rather than passing", () => {
    const body = JSON.stringify(PURCHASED);
    expect(verifyGithubSignature(body, sign(body), undefined)).toBe(false);
    expect(verifyGithubSignature(body, sign(body), "")).toBe(false);
  });

  it("rejects a missing or malformed signature header without throwing", () => {
    const body = JSON.stringify(PURCHASED);
    expect(verifyGithubSignature(body, null, SECRET)).toBe(false);
    expect(verifyGithubSignature(body, "sha256=short", SECRET)).toBe(false);
    expect(verifyGithubSignature(body, "garbage", SECRET)).toBe(false);
  });
});

describe("parseWebhookBody", () => {
  it("parses application/json", () => {
    const body = JSON.stringify(PURCHASED);
    expect(parseWebhookBody(body, "application/json")?.action).toBe("purchased");
  });

  it("parses the urlencoded form, where the JSON arrives in a payload field", () => {
    const body = `payload=${encodeURIComponent(JSON.stringify(PURCHASED))}`;
    const parsed = parseWebhookBody(body, "application/x-www-form-urlencoded");
    expect(parsed?.action).toBe("purchased");
    expect(parsed?.marketplace_purchase?.account?.login).toBe("acme-corp");
  });

  it("returns null on malformed JSON instead of throwing", () => {
    expect(parseWebhookBody("{not json", "application/json")).toBeNull();
    expect(parseWebhookBody("", "application/json")).toBeNull();
  });
});

describe("isMarketplaceAction", () => {
  it("accepts the five documented actions and nothing else", () => {
    for (const a of [
      "purchased",
      "changed",
      "cancelled",
      "pending_change",
      "pending_change_cancelled",
    ]) {
      expect(isMarketplaceAction(a)).toBe(true);
    }
    expect(isMarketplaceAction("deleted")).toBe(false);
    expect(isMarketplaceAction(undefined)).toBe(false);
  });
});

describe("buildPurchaseRow", () => {
  const now = "2026-08-21T12:00:00.000Z";

  it("maps a purchase onto the stored row", () => {
    const row = buildPurchaseRow("purchased", PURCHASED, now);
    expect(row).not.toBeNull();
    expect(row!.github_account_id).toBe(18404712);
    expect(row!.github_account_login).toBe("acme-corp");
    expect(row!.github_account_type).toBe("Organization");
    expect(row!.plan_id).toBe(435);
    expect(row!.plan_name).toBe("Pro Plan");
    expect(row!.plan_monthly_price_cents).toBe(999);
    expect(row!.billing_cycle).toBe("monthly");
    expect(row!.unit_count).toBe(3);
    expect(row!.status).toBe("active");
    expect(row!.sender_login).toBe("octocat");
    expect(row!.effective_date).toBe("2026-08-21T00:00:00.000Z");
  });

  it("returns null when the payload carries no account id", () => {
    expect(buildPurchaseRow("purchased", { action: "purchased" }, now)).toBeNull();
  });

  it("marks a cancellation cancelled", () => {
    const row = buildPurchaseRow("cancelled", { ...PURCHASED, action: "cancelled" }, now);
    expect(row!.status).toBe("cancelled");
  });

  it("keeps the CURRENT plan on a pending downgrade and records the future one", () => {
    // The regression this guards: reading marketplace_purchase on a
    // pending_change downgrades the customer immediately instead of at the
    // end of their billing cycle.
    const pending: MarketplaceEventPayload = {
      action: "pending_change",
      effective_date: "2026-09-21T00:00:00+00:00",
      sender: { login: "octocat" },
      marketplace_purchase: {
        account: PURCHASED.marketplace_purchase!.account,
        billing_cycle: "monthly",
        unit_count: 1,
        plan: { id: 1, name: "Free Plan", monthly_price_in_cents: 0 },
      },
      previous_marketplace_purchase: PURCHASED.marketplace_purchase,
    };

    const row = buildPurchaseRow("pending_change", pending, now);
    expect(row!.plan_name).toBe("Pro Plan");
    expect(row!.plan_id).toBe(435);
    expect(row!.status).toBe("active");
    expect(row!.pending_plan_name).toBe("Free Plan");
    expect(row!.pending_plan_id).toBe(1);
    expect(row!.pending_effective_date).toBe("2026-09-21T00:00:00.000Z");
  });

  it("clears a pending change on any non-pending action", () => {
    const row = buildPurchaseRow("changed", { ...PURCHASED, action: "changed" }, now);
    expect(row!.pending_plan_id).toBeNull();
    expect(row!.pending_plan_name).toBeNull();
    expect(row!.pending_effective_date).toBeNull();
  });

  it("treats a free trial as active and keeps the trial end date", () => {
    const trial: MarketplaceEventPayload = {
      ...PURCHASED,
      marketplace_purchase: {
        ...PURCHASED.marketplace_purchase!,
        on_free_trial: true,
        free_trial_ends_on: "2026-09-04T00:00:00+00:00",
      },
    };
    const row = buildPurchaseRow("purchased", trial, now);
    expect(row!.on_free_trial).toBe(true);
    expect(row!.free_trial_ends_on).toBe("2026-09-04T00:00:00.000Z");
    expect(row!.status).toBe("active");
  });

  it("survives a payload with no plan or dates", () => {
    const bare: MarketplaceEventPayload = {
      action: "purchased",
      marketplace_purchase: { account: { id: 7, login: "solo" } },
    };
    const row = buildPurchaseRow("purchased", bare, now);
    expect(row!.plan_id).toBeNull();
    expect(row!.effective_date).toBeNull();
    expect(row!.next_billing_date).toBeNull();
    expect(row!.on_free_trial).toBe(false);
  });
});

describe("currentPurchaseFor", () => {
  it("falls back to marketplace_purchase when there is no previous one", () => {
    const p = currentPurchaseFor("pending_change", PURCHASED);
    expect(p.plan?.name).toBe("Pro Plan");
  });
});

describe("isStaleEvent", () => {
  it("rejects an event older than what was applied", () => {
    expect(isStaleEvent("2026-08-21T00:00:00Z", "2026-08-20T00:00:00Z")).toBe(true);
  });

  it("allows a newer or equal event", () => {
    expect(isStaleEvent("2026-08-21T00:00:00Z", "2026-08-22T00:00:00Z")).toBe(false);
    // purchased and changed can share a timestamp; the later arrival wins.
    expect(isStaleEvent("2026-08-21T00:00:00Z", "2026-08-21T00:00:00Z")).toBe(false);
  });

  it("does not block when either side is missing or unparseable", () => {
    expect(isStaleEvent(null, "2026-08-21T00:00:00Z")).toBe(false);
    expect(isStaleEvent("2026-08-21T00:00:00Z", null)).toBe(false);
    expect(isStaleEvent("nonsense", "2026-08-21T00:00:00Z")).toBe(false);
  });
});
