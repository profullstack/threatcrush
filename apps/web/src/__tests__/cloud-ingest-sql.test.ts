/**
 * Exercises the SQL behind the daemon ↔ cloud pipeline
 * (supabase/migrations/20260925100000_cloud_ingest.sql) against a real
 * Supabase: detection dedupe, the hardening-finding state rules and the
 * remediation claim lease. The route tests mock the database, so this is the
 * only place those rules are checked.
 *
 * Runs only when pointed at a database with the migration applied:
 *   CLOUD_INGEST_TEST_SUPABASE_URL=http://127.0.0.1:54321 \
 *   CLOUD_INGEST_TEST_SERVICE_ROLE_KEY=... pnpm --filter @profullstack/threatcrush-web test
 * Everything it creates hangs off a throwaway user and is deleted afterwards.
 */
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const url = process.env.CLOUD_INGEST_TEST_SUPABASE_URL;
const key = process.env.CLOUD_INGEST_TEST_SERVICE_ROLE_KEY;

describe.skipIf(!url || !key)("cloud ingest SQL", () => {
  let db: SupabaseClient;
  let userId: string;
  let orgId: string;
  let serverId: string;
  let otherServerId: string;

  beforeAll(async () => {
    // setup.ts stubs fetch for the mocked suites; this one talks to a real API.
    vi.unstubAllGlobals();
    db = createClient(url!, key!, { auth: { persistSession: false } });
    const suffix = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const { data: created, error: userError } = await db.auth.admin.createUser({
      email: `ingest-sql-${suffix}@example.test`,
      password: `pw-${suffix}-Aa1!`,
      email_confirm: true,
    });
    if (userError) throw userError;
    userId = created.user.id;
    const { error: profileError } = await db.from("user_profiles").insert({
      id: userId,
      email: created.user.email,
      referral_code: `T${suffix}`.slice(0, 16),
    });
    if (profileError) throw profileError;

    const { data: org, error: orgError } = await db
      .from("organizations")
      .insert({ name: "ingest sql", slug: `ingest-sql-${suffix}`, created_by: userId })
      .select("id")
      .single();
    if (orgError) throw orgError;
    orgId = org.id;

    const { data: servers, error: serverError } = await db
      .from("servers")
      .insert([
        { org_id: orgId, name: "a", hostname: "a", created_by: userId },
        { org_id: orgId, name: "b", hostname: "b", created_by: userId },
      ])
      .select("id, name")
      .order("name");
    if (serverError) throw serverError;
    [serverId, otherServerId] = servers.map((s) => s.id);
  });

  afterAll(async () => {
    if (!db || !userId) return;
    if (orgId) await db.from("organizations").delete().eq("id", orgId);
    await db.from("user_profiles").delete().eq("id", userId);
    await db.auth.admin.deleteUser(userId);
  });

  const detectionRow = (overrides: Record<string, unknown> = {}) => ({
    organization_id: orgId,
    server_id: serverId,
    rule_id: "ssh-bruteforce",
    severity: "high",
    title: "SSH brute force",
    description: null,
    source_ip: "203.0.113.9",
    username: null,
    raw_metadata: {},
    detected_at: "2026-09-25T10:00:05.000Z",
    ord: 0,
    ...overrides,
  });

  async function ingestDetections(rows: Array<Record<string, unknown>>) {
    const { data, error } = await db.rpc("ingest_detections", { p_rows: rows });
    if (error) throw error;
    return data as Array<{ id: string; inserted: boolean; occurrences: number }>;
  }

  describe("detections", () => {
    it("merges a resend within the same minute into one row and counts it", async () => {
      const ip = "198.51.100.1";
      const first = await ingestDetections([
        detectionRow({ source_ip: ip }),
        detectionRow({ source_ip: ip, detected_at: "2026-09-25T10:00:30.000Z", ord: 1 }),
      ]);
      expect(first).toEqual([expect.objectContaining({ inserted: true, occurrences: 2 })]);

      const resend = await ingestDetections([
        detectionRow({ source_ip: ip, detected_at: "2026-09-25T10:00:59.000Z" }),
      ]);
      expect(resend).toEqual([expect.objectContaining({ id: first[0].id, inserted: false, occurrences: 3 })]);

      const { data: row } = await db
        .from("detections")
        .select("occurrences, detected_at, last_detected_at")
        .eq("id", first[0].id)
        .single();
      expect(row!.occurrences).toBe(3);
      expect(Date.parse(row!.detected_at)).toBe(Date.parse("2026-09-25T10:00:05Z"));
      expect(Date.parse(row!.last_detected_at)).toBe(Date.parse("2026-09-25T10:00:59Z"));
    });

    it("keeps separate rows across minutes, rules, source IPs and servers", async () => {
      const ip = "198.51.100.2";
      const rows = await ingestDetections([
        detectionRow({ source_ip: ip }),
        detectionRow({ source_ip: ip, detected_at: "2026-09-25T10:01:00.000Z" }),
        detectionRow({ source_ip: ip, rule_id: "port-scan" }),
        detectionRow({ source_ip: "198.51.100.3" }),
        detectionRow({ source_ip: ip, server_id: otherServerId }),
      ]);
      expect(rows).toHaveLength(5);
      expect(rows.every((r) => r.inserted && r.occurrences === 1)).toBe(true);
    });

    it("dedupes events without a rule or source IP on the minute alone", async () => {
      const at = "2026-09-25T12:34:10.000Z";
      const rows = await ingestDetections([
        detectionRow({ rule_id: null, source_ip: null, detected_at: at }),
        detectionRow({ rule_id: null, source_ip: null, detected_at: at, title: "other", ord: 1 }),
      ]);
      expect(rows).toEqual([expect.objectContaining({ inserted: true, occurrences: 2 })]);
    });
  });

  describe("hardening findings", () => {
    async function report(findingKey: string, status: string) {
      const { error } = await db.rpc("ingest_hardening_findings", {
        p_rows: [{
          organization_id: orgId, server_id: serverId, finding_key: findingKey, status,
          severity: "high", title: findingKey, recommendation: null,
          observed_at: new Date().toISOString(), ord: 0,
        }],
      });
      if (error) throw error;
      const { data } = await db
        .from("hardening_findings")
        .select("status, resolved_at")
        .eq("server_id", serverId)
        .eq("finding_key", findingKey)
        .single();
      return data as { status: string; resolved_at: string | null };
    }

    async function markByHuman(findingKey: string, status: string) {
      await db
        .from("hardening_findings")
        .update({ status, resolved_at: status === "resolved" ? new Date().toISOString() : null })
        .eq("server_id", serverId)
        .eq("finding_key", findingKey);
    }

    it("keeps an acknowledgement while the check still warns or fails, until it passes", async () => {
      await report("ack", "fail");
      await markByHuman("ack", "acknowledged");
      expect((await report("ack", "fail")).status).toBe("acknowledged");
      expect((await report("ack", "warn")).status).toBe("acknowledged");
      expect((await report("ack", "pass")).status).toBe("pass");
      expect((await report("ack", "fail")).status).toBe("fail");
    });

    it("reopens a resolved finding on fail but not on warn", async () => {
      await report("res", "fail");
      await markByHuman("res", "resolved");
      const warned = await report("res", "warn");
      expect(warned.status).toBe("resolved");
      expect(warned.resolved_at).not.toBeNull();

      const failed = await report("res", "fail");
      expect(failed).toEqual({ status: "fail", resolved_at: null });
    });

    it("applies the last report for a key within one batch", async () => {
      const { error } = await db.rpc("ingest_hardening_findings", {
        p_rows: ["fail", "pass"].map((status, ord) => ({
          organization_id: orgId, server_id: serverId, finding_key: "batch", status,
          severity: "low", title: "batch", recommendation: null,
          observed_at: new Date().toISOString(), ord,
        })),
      });
      expect(error).toBeNull();
      const { data } = await db.from("hardening_findings").select("status")
        .eq("server_id", serverId).eq("finding_key", "batch").single();
      expect(data!.status).toBe("pass");
    });
  });

  describe("remediation claim", () => {
    async function queue(rows: Array<Record<string, unknown>>) {
      const { data, error } = await db
        .from("remediation_actions")
        .insert(rows.map((r) => ({
          organization_id: orgId, server_id: serverId, action_type: "block",
          target_value: "203.0.113.50", status: "pending", ...r,
        })))
        .select("id");
      if (error) throw error;
      return data.map((d) => d.id as string);
    }

    async function claim(server = serverId) {
      const { data, error } = await db.rpc("claim_server_remediations", {
        p_org_id: orgId, p_server_id: server, p_limit: 50,
      });
      if (error) throw error;
      return data as Array<{ id: string; status: string; metadata: Record<string, unknown> }>;
    }

    it("hands out only this server's pending actions, once", async () => {
      const [mine] = await queue([{}]);
      const [theirs] = await queue([{ server_id: otherServerId }]);
      const [daemonBan] = await queue([{ status: "executed", metadata: { source: "daemon" } }]);

      const claimed = await claim();
      const ids = claimed.map((a) => a.id);
      expect(ids).toContain(mine);
      expect(ids).not.toContain(theirs);
      expect(ids).not.toContain(daemonBan);
      const row = claimed.find((a) => a.id === mine)!;
      expect(row.status).toBe("executing");
      expect(typeof row.metadata.claimed_at).toBe("string");

      expect((await claim()).map((a) => a.id)).not.toContain(mine);
    });

    it("re-queues a claim older than five minutes but not a fresh one", async () => {
      const stale = new Date(Date.now() - 6 * 60_000).toISOString();
      const fresh = new Date(Date.now() - 60_000).toISOString();
      const [staleId, freshId] = await queue([
        { status: "executing", metadata: { claimed_at: stale } },
        { status: "executing", metadata: { claimed_at: fresh } },
      ]);

      const ids = (await claim()).map((a) => a.id);
      expect(ids).toContain(staleId);
      expect(ids).not.toContain(freshId);
    });

    it("expires pending actions whose window already passed instead of handing them out", async () => {
      const [expiredId] = await queue([{ expires_at: new Date(Date.now() - 1000).toISOString() }]);
      expect((await claim()).map((a) => a.id)).not.toContain(expiredId);
      const { data } = await db.from("remediation_actions").select("status").eq("id", expiredId).single();
      expect(data!.status).toBe("expired");
    });
  });
});
