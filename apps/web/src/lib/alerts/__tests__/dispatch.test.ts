import { beforeEach, describe, expect, it, vi } from "vitest";
import { recordQuery, type QueryCall } from "@/__tests__/helpers/query-recorder";

const safeFetch = vi.fn();
vi.mock("@/lib/ssrf-guard", () => ({ safeFetch: (...args: unknown[]) => safeFetch(...args) }));

const db = {
  rules: [] as unknown[],
  destinations: [] as unknown[],
  rulesError: null as unknown,
  priorAttempts: 0,
  deliveryCalls: [] as QueryCall[],
};

vi.mock("@/lib/supabase", () => ({
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      switch (table) {
        case "alert_rules":
          return recordQuery({ data: db.rules, error: db.rulesError });
        case "alert_destinations":
          return recordQuery({ data: db.destinations, error: null });
        case "organizations":
          return recordQuery({ data: { slug: "acme" }, error: null });
        case "servers":
          return recordQuery({ data: [{ id: "srv-1", name: "web-1", hostname: "web-1.local" }], error: null });
        case "alert_deliveries":
          return recordQuery({ data: null, error: null, count: db.priorAttempts }, db.deliveryCalls);
        default:
          throw new Error(`Unexpected table ${table}`);
      }
    },
  }),
}));

import { dispatchDetectionAlerts } from "../dispatch";
import type { AlertableDetection } from "../types";

const detection = (id: string, overrides: Partial<AlertableDetection> = {}): AlertableDetection => ({
  id,
  organization_id: "org-1",
  server_id: "srv-1",
  severity: "high",
  title: `Detection ${id}`,
  description: null,
  source_ip: "203.0.113.5",
  rule_id: "ssh-bruteforce",
  detected_at: "2026-09-25T10:00:00.000Z",
  ...overrides,
});

const slack = (id = "dest-slack") => ({
  id,
  organization_id: "org-1",
  name: "Slack",
  type: "slack",
  config: { webhook_url: "https://hooks.slack.com/services/T/B/x" },
  enabled: true,
});

const rule = (overrides: Record<string, unknown> = {}) => ({
  id: "rule-1",
  organization_id: "org-1",
  name: "High and up",
  min_severity: "high",
  server_scope: [],
  destination_id: "dest-slack",
  rate_limit_per_hour: 60,
  enabled: true,
  ...overrides,
});

/** Every row written to alert_deliveries, in insert order. */
function recorded() {
  return db.deliveryCalls
    .filter(([method]) => method === "insert")
    .flatMap(([, rows]) => rows as Record<string, unknown>[]);
}

beforeEach(() => {
  safeFetch.mockReset().mockResolvedValue(new Response("ok", { status: 200 }));
  db.rules = [rule()];
  db.destinations = [slack()];
  db.rulesError = null;
  db.priorAttempts = 0;
  db.deliveryCalls = [];
  delete process.env.RESEND_API_KEY;
});

describe("dispatchDetectionAlerts", () => {
  it("delivers only detections at or above the rule's severity and records them as sent", async () => {
    await dispatchDetectionAlerts([detection("det-high"), detection("det-low", { severity: "low" })]);

    expect(safeFetch).toHaveBeenCalledTimes(1);
    expect(recorded()).toEqual([
      {
        organization_id: "org-1",
        rule_id: "rule-1",
        destination_id: "dest-slack",
        detection_id: "det-high",
        status: "sent",
        error: null,
      },
    ]);
  });

  it("counts only sent and failed attempts from the last hour against the limit", async () => {
    await dispatchDetectionAlerts([detection("det-1")]);

    expect(db.deliveryCalls).toContainEqual(["eq", "rule_id", "rule-1"]);
    expect(db.deliveryCalls).toContainEqual(["in", "status", ["sent", "failed"]]);
    const since = db.deliveryCalls.find(([method, column]) => method === "gte" && column === "created_at");
    const ageMs = Date.now() - Date.parse(since![2] as string);
    expect(ageMs).toBeGreaterThanOrEqual(60 * 60 * 1000);
    expect(ageMs).toBeLessThan(60 * 60 * 1000 + 5000);
  });

  it("allows exactly rate_limit_per_hour attempts, then records rate_limited", async () => {
    db.rules = [rule({ rate_limit_per_hour: 3 })];
    db.priorAttempts = 2;

    await dispatchDetectionAlerts([detection("det-1"), detection("det-2"), detection("det-3")]);

    expect(safeFetch).toHaveBeenCalledTimes(1);
    expect(recorded().map((row) => [row.detection_id, row.status])).toEqual([
      ["det-1", "sent"],
      ["det-2", "rate_limited"],
      ["det-3", "rate_limited"],
    ]);
    expect(recorded()[1].error).toBe("Rule limit of 3 alerts per hour reached");
  });

  it("records a failed delivery with its error instead of throwing", async () => {
    safeFetch.mockRejectedValue(new Error("Requests to internal addresses are not allowed"));

    await expect(dispatchDetectionAlerts([detection("det-1")])).resolves.toBeUndefined();

    expect(recorded()).toMatchObject([
      { detection_id: "det-1", status: "failed", error: "Requests to internal addresses are not allowed" },
    ]);
  });

  it("counts failed attempts toward the limit too", async () => {
    db.rules = [rule({ rate_limit_per_hour: 1 })];
    safeFetch.mockResolvedValue(new Response("nope", { status: 500 }));

    await dispatchDetectionAlerts([detection("det-1"), detection("det-2")]);

    expect(recorded().map((row) => row.status)).toEqual(["failed", "rate_limited"]);
  });

  it("records a missing provider key as failed", async () => {
    db.destinations = [{ ...slack("dest-email"), type: "email", config: { to: "soc@example.com" } }];
    db.rules = [rule({ destination_id: "dest-email" })];

    await dispatchDetectionAlerts([detection("det-1")]);

    expect(recorded()).toMatchObject([
      { destination_id: "dest-email", status: "failed", error: "Email delivery is not configured (RESEND_API_KEY not set)" },
    ]);
  });

  it("sends one alert per destination when several rules route to it", async () => {
    db.rules = [rule({ id: "rule-a" }), rule({ id: "rule-b", min_severity: "info" })];

    await dispatchDetectionAlerts([detection("det-1")]);

    expect(safeFetch).toHaveBeenCalledTimes(1);
    expect(recorded()).toHaveLength(1);
  });

  it("skips rules scoped to other servers and disabled destinations", async () => {
    db.rules = [
      rule({ id: "rule-scoped", server_scope: ["srv-other"] }),
      rule({ id: "rule-disabled-dest", destination_id: "dest-off" }),
    ];
    db.destinations = [slack(), { ...slack("dest-off"), enabled: false }];

    await dispatchDetectionAlerts([detection("det-1")]);

    expect(safeFetch).not.toHaveBeenCalled();
    expect(recorded()).toEqual([]);
  });

  it("gives up quietly when rules cannot be loaded", async () => {
    db.rulesError = { message: "connection refused" };
    const error = vi.spyOn(console, "error").mockImplementation(() => {});

    await expect(dispatchDetectionAlerts([detection("det-1")])).resolves.toBeUndefined();

    expect(safeFetch).not.toHaveBeenCalled();
    error.mockRestore();
  });
});
