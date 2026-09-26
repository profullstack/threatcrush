import type { NextRequest } from "next/server";
import type * as NextServer from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { recordQuery, type QueryCall } from "@/__tests__/helpers/query-recorder";

const OWN_SERVER = "11111111-1111-4111-8111-111111111111";
const OTHER_OWN_SERVER = "22222222-2222-4222-8222-222222222222";
const FOREIGN_SERVER = "33333333-3333-4333-8333-333333333333";
const MISSING_SERVER = "44444444-4444-4444-8444-444444444444";

type RpcRow = Record<string, unknown>;

const state = {
  servers: [] as Array<{ id: string; org_id: string }>,
  memberOrgs: [] as string[],
  serverCalls: [] as QueryCall[],
  rpc: vi.fn(),
  rpcResult: {} as Record<string, { data: unknown; error: unknown }>,
};

vi.mock("@/lib/supabase", () => ({
  getSupabaseClient: () => ({
    auth: {
      getUser: async (token: string) =>
        token === "good-token"
          ? { data: { user: { id: "user-1", email: "a@example.com", user_metadata: {} } }, error: null }
          : { data: { user: null }, error: { message: "bad jwt" } },
    },
  }),
  getSupabaseAdmin: () => ({
    from: (table: string) => {
      if (table === "servers") {
        return recordQuery({ data: state.servers, error: null }, state.serverCalls);
      }
      if (table === "organization_members") {
        return recordQuery({ data: state.memberOrgs.map((org_id) => ({ org_id })), error: null });
      }
      throw new Error(`Unexpected table ${table}`);
    },
    rpc: (name: string, args: { p_rows: unknown[] }) => {
      state.rpc(name, args);
      // By default every remediation row is new.
      const fallback = name === "ingest_remediations" ? args.p_rows.length : [];
      return Promise.resolve(state.rpcResult[name] ?? { data: fallback, error: null });
    },
  }),
}));

// after() needs a live request scope; run the callback inline so the test can
// see what the route hands to alert delivery.
const { dispatchDetectionAlerts } = vi.hoisted(() => ({
  dispatchDetectionAlerts: vi.fn(async (_detections: unknown[]) => {}),
}));
vi.mock("@/lib/alerts/dispatch", () => ({ dispatchDetectionAlerts }));
vi.mock("next/server", async (importOriginal) => ({
  ...(await importOriginal<typeof NextServer>()),
  after: (task: () => unknown) => {
    void task();
  },
}));

import { POST } from "@/app/api/ingest/route";

function post(body: unknown, { token = "good-token" as string | null, raw = false } = {}) {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (token) headers.authorization = `Bearer ${token}`;
  const req = new Request("http://localhost/api/ingest", {
    method: "POST",
    headers,
    body: raw ? (body as string) : JSON.stringify(body),
  });
  return POST(req as unknown as NextRequest);
}

function rpcArgs(name: string): Array<Record<string, unknown>> {
  const call = state.rpc.mock.calls.find(([n]) => n === name);
  return call ? (call[1] as { p_rows: Array<Record<string, unknown>> }).p_rows : [];
}

function insertedRemediations(): Array<Record<string, unknown>> {
  return rpcArgs("ingest_remediations");
}

const detection = (overrides: Record<string, unknown> = {}) => ({
  type: "detection",
  server_id: OWN_SERVER,
  severity: "high",
  title: "SSH brute force",
  rule_id: "ssh-bruteforce",
  source_ip: "203.0.113.9",
  detected_at: "2026-09-25T10:00:05Z",
  ...overrides,
});

describe("POST /api/ingest", () => {
  beforeEach(() => {
    state.servers = [
      { id: OWN_SERVER, org_id: "org-a" },
      { id: OTHER_OWN_SERVER, org_id: "org-b" },
      { id: FOREIGN_SERVER, org_id: "org-foreign" },
    ];
    state.memberOrgs = ["org-a", "org-b"];
    state.serverCalls = [];
    state.rpc = vi.fn();
    state.rpcResult = {};
    dispatchDetectionAlerts.mockClear();
  });

  it("rejects a missing or invalid bearer token", async () => {
    expect((await post({ events: [detection()] }, { token: null })).status).toBe(401);
    expect((await post({ events: [detection()] }, { token: "expired" })).status).toBe(401);
    expect(state.rpc).not.toHaveBeenCalled();
  });

  it("rejects malformed batches as a whole with 400", async () => {
    expect((await post("{not json", { raw: true })).status).toBe(400);
    expect((await post({})).status).toBe(400);
    expect((await post({ events: [] })).status).toBe(400);
    expect((await post({ events: "nope" })).status).toBe(400);
    expect((await post({ events: Array.from({ length: 501 }, () => detection()) })).status).toBe(400);
  });

  it("accepts exactly 500 events", async () => {
    const res = await post({ events: Array.from({ length: 500 }, () => ({ type: "heartbeat", server_id: OWN_SERVER })) });
    expect(res.status).toBe(200);
    expect((await res.json()).accepted.heartbeats).toBe(500);
  });

  it("rejects a body over 1 MB before parsing it", async () => {
    const huge = JSON.stringify({ events: [detection({ description: "x".repeat(1_000_001) })] });
    expect((await post(huge, { raw: true })).status).toBe(400);
    expect(state.rpc).not.toHaveBeenCalled();
  });

  it("rejects events for servers the caller can't access individually and accepts the rest", async () => {
    const res = await post({
      events: [
        detection(),
        detection({ server_id: FOREIGN_SERVER }),
        { type: "heartbeat", server_id: MISSING_SERVER },
        detection({ server_id: OTHER_OWN_SERVER }),
        { type: "heartbeat", server_id: "not-a-uuid" },
      ],
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.rejected).toEqual([
      { index: 1, error: `no access to server ${FOREIGN_SERVER}` },
      { index: 2, error: `no access to server ${MISSING_SERVER}` },
      { index: 4, error: expect.stringContaining("server_id") },
    ]);

    const rows = rpcArgs("ingest_detections");
    expect(rows.map((r) => [r.server_id, r.organization_id])).toEqual([
      [OWN_SERVER, "org-a"],
      [OTHER_OWN_SERVER, "org-b"],
    ]);
  });

  it("resolves server access with one lookup per batch, not per event", async () => {
    await post({ events: Array.from({ length: 50 }, () => detection()) });
    expect(state.serverCalls.filter(([m]) => m === "select")).toHaveLength(1);
    expect(state.serverCalls).toContainEqual(["in", "id", [OWN_SERVER]]);
  });

  it("reports schema failures per event without failing the batch", async () => {
    const res = await post({
      events: [
        detection({ title: "t".repeat(301) }),
        detection({ severity: "catastrophic" }),
        detection({ raw_metadata: { blob: "x".repeat(16 * 1024) } }),
        detection({ detected_at: "yesterday-ish" }),
        { type: "telemetry", server_id: OWN_SERVER },
        detection({ title: "t".repeat(300) }),
      ],
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.rejected.map((r: { index: number }) => r.index)).toEqual([0, 1, 2, 3, 4]);
    expect(rpcArgs("ingest_detections")).toHaveLength(1);
  });

  it("counts detections the database merged into existing rows as deduplicated", async () => {
    state.rpcResult.ingest_detections = {
      data: [
        { id: "d-1", inserted: true, occurrences: 2 },
        { id: "d-2", inserted: false, occurrences: 7 },
      ],
      error: null,
    };
    const res = await post({
      events: [
        detection(),
        detection({ detected_at: "2026-09-25T10:00:40Z" }),
        detection({ rule_id: "port-scan" }),
      ],
    });
    const body = await res.json();
    expect(body).toEqual({
      success: true,
      accepted: { detections: 1, deduplicated: 2, heartbeats: 0, findings: 0, remediations: 0 },
      rejected: [],
    });
    // Only the newly inserted row alerts; merged repeats must not page anyone again.
    expect(dispatchDetectionAlerts).toHaveBeenCalledTimes(1);
    expect(dispatchDetectionAlerts).toHaveBeenCalledWith([expect.objectContaining({ id: "d-1" })]);
  });

  it("does not alert when every detection in the batch was a repeat", async () => {
    state.rpcResult.ingest_detections = {
      data: [{ id: "d-2", inserted: false, occurrences: 8 }],
      error: null,
    };
    const res = await post({ events: [detection()] });
    expect(res.status).toBe(200);
    expect(dispatchDetectionAlerts).not.toHaveBeenCalled();
  });

  it("still accepts v1 heartbeat and detection bodies", async () => {
    const before = Date.now();
    const res = await post({
      events: [
        { type: "heartbeat", server_id: OWN_SERVER, version: "0.13.7" },
        { type: "detection", server_id: OWN_SERVER, severity: "medium", title: "Port scan", raw_metadata: { ports: 40 } },
      ],
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.accepted.heartbeats).toBe(1);
    expect(body.rejected).toEqual([]);

    const update = state.serverCalls.find(([m]) => m === "update");
    expect(update?.[1]).toMatchObject({ status: "online", threatcrushd_version: "0.13.7" });
    expect(update?.[1]).not.toHaveProperty("hostname");

    const [row] = rpcArgs("ingest_detections");
    expect(row).toMatchObject({ rule_id: null, source_ip: null, raw_metadata: { ports: 40 } });
    expect(Date.parse(row.detected_at as string)).toBeGreaterThanOrEqual(before - 1000);
  });

  it("updates hostname and version from the latest heartbeat for each server", async () => {
    await post({
      events: [
        { type: "heartbeat", server_id: OWN_SERVER, version: "0.13.9", hostname: "old-name" },
        { type: "heartbeat", server_id: OWN_SERVER, hostname: "web-1" },
      ],
    });
    const updates = state.serverCalls.filter(([m]) => m === "update");
    expect(updates).toHaveLength(1);
    expect(updates[0][1]).toMatchObject({ status: "online", threatcrushd_version: "0.13.9", hostname: "web-1" });
  });

  it("records daemon remediations with their outcome and source", async () => {
    const res = await post({
      events: [
        {
          type: "remediation",
          server_id: OWN_SERVER,
          action_type: "block",
          target_value: "198.51.100.7",
          status: "executed",
          rule_id: "ssh-bruteforce",
          reason: "12 failed logins",
          executed_at: "2026-09-25T10:01:00Z",
          expires_at: "2026-09-25T11:01:00Z",
        },
        {
          type: "remediation",
          server_id: OWN_SERVER,
          action_type: "block",
          target_value: "10.0.0.1",
          status: "failed",
          error: "target is protected",
          dry_run: true,
        },
      ],
    });
    expect((await res.json()).accepted.remediations).toBe(2);
    const rows = insertedRemediations();
    expect(rows[0]).toMatchObject({
      organization_id: "org-a",
      server_id: OWN_SERVER,
      action_type: "block",
      status: "executed",
      executed_at: "2026-09-25T10:01:00.000Z",
      expires_at: "2026-09-25T11:01:00.000Z",
      metadata: { source: "daemon", rule_id: "ssh-bruteforce", reason: "12 failed logins", error: null, dry_run: false },
    });
    expect(rows[1]).toMatchObject({
      status: "failed",
      expires_at: null,
      metadata: { source: "daemon", error: "target is protected", dry_run: true },
    });
  });

  it("counts remediations the database skipped as already recorded as deduplicated", async () => {
    const eventId = "5d9f3a2e-8c1b-4f6a-9e7d-2b3c4d5e6f70";
    const ban = { type: "remediation", server_id: OWN_SERVER, action_type: "block", target_value: "203.0.113.9", status: "executed" };
    state.rpcResult.ingest_remediations = { data: 1, error: null };

    const res = await post({ events: [{ ...ban, event_id: eventId }, { ...ban, event_id: eventId.toUpperCase() }] });
    const body = await res.json();
    expect(body.accepted).toMatchObject({ remediations: 1, deduplicated: 1 });
    expect(insertedRemediations().map((r) => (r.metadata as { event_id: string }).event_id)).toEqual([eventId, eventId]);
  });

  it("records remediations without event_id as separate rows", async () => {
    const ban = { type: "remediation", server_id: OWN_SERVER, action_type: "block", target_value: "203.0.113.9", status: "executed" };
    const res = await post({ events: [ban, ban] });
    const body = await res.json();
    expect(body.accepted).toMatchObject({ remediations: 2, deduplicated: 0 });
    expect(insertedRemediations().map((r) => (r.metadata as { event_id: unknown }).event_id)).toEqual([null, null]);
  });

  it("rejects a remediation whose event_id isn't a UUID", async () => {
    const res = await post({
      events: [{ type: "remediation", server_id: OWN_SERVER, action_type: "block", target_value: "1.2.3.4", status: "executed", event_id: "replay-1" }],
    });
    expect((await res.json()).rejected).toEqual([{ index: 0, error: "event_id must be a UUID" }]);
  });

  it("never lets the daemon queue pending remediations", async () => {
    const res = await post({
      events: [{ type: "remediation", server_id: OWN_SERVER, action_type: "block", target_value: "1.2.3.4", status: "pending" }],
    });
    const body = await res.json();
    expect(body.rejected).toEqual([{ index: 0, error: expect.stringContaining("status") }]);
    expect(insertedRemediations()).toEqual([]);
  });

  it("passes hardening findings to the upsert and counts them", async () => {
    const res = await post({
      events: [
        { type: "hardening_finding", server_id: OWN_SERVER, finding_key: "ssh.root_login", status: "fail", severity: "high", title: "Root login enabled" },
        { type: "hardening_finding", server_id: OWN_SERVER, finding_key: "ssh.root_login", status: "acknowledged", severity: "high", title: "x" },
      ],
    });
    const body = await res.json();
    expect(body.accepted.findings).toBe(1);
    expect(body.rejected).toEqual([{ index: 1, error: expect.stringContaining("status") }]);
    expect(rpcArgs("ingest_hardening_findings")).toEqual([
      expect.objectContaining({ organization_id: "org-a", finding_key: "ssh.root_login", status: "fail" }),
    ]);
  });

  it("returns 500 so the daemon spools the batch when the database fails", async () => {
    state.rpcResult.ingest_detections = { data: null, error: { message: "connection reset" } };
    const res = await post({ events: [detection(), { type: "remediation", server_id: OWN_SERVER, action_type: "block", target_value: "1.2.3.4", status: "executed" }] });
    expect(res.status).toBe(500);
    // Remediations without event_id aren't idempotent, so they must not be written before
    // a failure that makes the daemon resend the whole batch.
    expect(insertedRemediations()).toEqual([]);
  });
});
