import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * Queue a daemon restart for one or more servers. It rides the same
 * remediation-claim channel the daemon already polls; the daemon executes
 * action_type "restart" (see apps/cli … remediation-consumer.ts). A short
 * expiry means a server that is offline now does not restart days later when it
 * finally reconnects.
 */

export const RESTART_TARGET = "daemon";
const RESTART_TTL_MS = 10 * 60 * 1000;

export async function queueRestart(
  admin: SupabaseClient,
  orgId: string,
  serverIds: string[],
): Promise<number> {
  if (serverIds.length === 0) return 0;
  const expires_at = new Date(Date.now() + RESTART_TTL_MS).toISOString();
  const rows = serverIds.map((server_id) => ({
    organization_id: orgId,
    server_id,
    action_type: "restart",
    target_value: RESTART_TARGET,
    status: "pending",
    expires_at,
  }));
  const { error } = await admin.from("remediation_actions").insert(rows);
  if (error) {
    console.error("Failed to queue restart:", error);
    throw new Error("Could not queue the restart");
  }
  return rows.length;
}
