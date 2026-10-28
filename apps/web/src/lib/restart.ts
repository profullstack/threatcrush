import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { compareVersions } from "@/lib/fleet";

/**
 * Queue a daemon restart for one or more servers. It rides the same
 * remediation-claim channel the daemon already polls; the daemon executes
 * action_type "restart" (see apps/cli … remediation-consumer.ts). A short
 * expiry means a server that is offline now does not restart days later when it
 * finally reconnects.
 */

export const RESTART_TARGET = "daemon";

/** One queued row, returned so the dashboard can follow it live. */
export interface QueuedAction {
  id: string;
  server_id: string;
  action_type: "restart" | "update";
}
const RESTART_TTL_MS = 10 * 60 * 1000;

export async function queueRestart(
  admin: SupabaseClient,
  orgId: string,
  serverIds: string[],
): Promise<QueuedAction[]> {
  if (serverIds.length === 0) return [];
  const expires_at = new Date(Date.now() + RESTART_TTL_MS).toISOString();
  const rows = serverIds.map((server_id) => ({
    organization_id: orgId,
    server_id,
    action_type: "restart",
    target_value: RESTART_TARGET,
    status: "pending",
    expires_at,
  }));
  const { data, error } = await admin.from("remediation_actions").insert(rows).select("id, server_id, action_type");
  if (error) {
    console.error("Failed to queue restart:", error);
    throw new Error("Could not queue the restart");
  }
  return (data ?? []) as QueuedAction[];
}

/** The first daemon release that understands action_type "update". */
export const UPDATE_ACTION_SINCE = "0.13.59";

const older = (a: string | null, b: string) => !a || compareVersions(a, b) < 0;

/**
 * "Update now" for servers behind the newest release. Daemons that know the
 * `update` action install it at once and restart onto it. Older ones get a
 * `restart`: their auto-updater checks 10-40 minutes after start and takes the
 * newest release at least `min_age` (2h) old.
 */
export async function queueUpdate(
  admin: SupabaseClient,
  orgId: string,
  servers: Array<{ id: string; version: string | null }>,
): Promise<{ updates: number; restarts: number; actions: QueuedAction[] }> {
  if (servers.length === 0) return { updates: 0, restarts: 0, actions: [] };
  const expires_at = new Date(Date.now() + RESTART_TTL_MS).toISOString();
  const rows = servers.map((s) => ({
    organization_id: orgId,
    server_id: s.id,
    action_type: older(s.version, UPDATE_ACTION_SINCE) ? "restart" : "update",
    target_value: RESTART_TARGET,
    status: "pending",
    expires_at,
  }));
  const { data, error } = await admin.from("remediation_actions").insert(rows).select("id, server_id, action_type");
  if (error) {
    console.error("Failed to queue update:", error);
    throw new Error("Could not queue the update");
  }
  const updates = rows.filter((r) => r.action_type === "update").length;
  return { updates, restarts: rows.length - updates, actions: (data ?? []) as QueuedAction[] };
}
