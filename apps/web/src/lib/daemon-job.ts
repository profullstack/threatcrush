/**
 * Live progress for the fleet panel's "Update all" / "Restart all": one queued
 * remediation action per server, followed from the queue to the daemon's first
 * heartbeat after it restarts. Pure so it can be tested without a browser.
 *
 * Both actions report `executed` and then restart the daemon 3s later (see
 * apps/cli remediation-consumer.ts and auto-update.ts), so a heartbeat only
 * counts as "back" when it lands clearly after that.
 */

export type JobPhase = "queued" | "running" | "restarting" | "online" | "failed" | "expired" | "stalled";

export interface JobItem {
  action_id: string;
  org_id: string;
  server_id: string;
  server_name: string;
  /** "restart" also covers updates sent to daemons too old for `update`. */
  action_type: "restart" | "update";
  /** What the user pressed, so a restart-for-update can say why. */
  intent: "restart" | "update";
  from_version: string | null;
}

export interface JobAction {
  id: string;
  status: string;
  executed_at: string | null;
  expires_at: string | null;
  metadata?: { error?: string } | null;
}

export interface JobServer {
  last_seen: string | null;
  threatcrushd_version: string | null;
}

export interface JobStatus {
  phase: JobPhase;
  detail: string;
}

/** The daemon restarts this long after reporting `executed`; plus slack for clock skew. */
const RESTART_SLACK_MS = 4_000;
/** No heartbeat this long after the restart: stop waiting and say so. */
export const STALL_MS = 5 * 60_000;

export const TERMINAL: ReadonlySet<JobPhase> = new Set(["online", "failed", "expired", "stalled"]);

export function jobStatus(item: JobItem, action: JobAction | undefined, server: JobServer | undefined, now = Date.now()): JobStatus {
  if (!action) return { phase: "queued", detail: "Queued" };
  if (action.status === "failed") return { phase: "failed", detail: action.metadata?.error || "The daemon reported a failure" };
  const expired = action.status === "expired"
    || (action.status === "pending" && action.expires_at != null && Date.parse(action.expires_at) < now);
  if (expired) return { phase: "expired", detail: "Never picked up: the daemon is offline, so nothing was changed" };
  if (action.status === "pending") return { phase: "queued", detail: "Waiting for the daemon to pick it up (it checks every 15s)" };
  if (action.status === "executing") {
    return { phase: "running", detail: item.action_type === "update" ? "Installing the new release" : "Restarting the daemon" };
  }

  const executedAt = action.executed_at ? Date.parse(action.executed_at) : NaN;
  const versionChanged = !!server?.threatcrushd_version && server.threatcrushd_version !== item.from_version;
  const seen = server?.last_seen ? Date.parse(server.last_seen) : NaN;
  const back = versionChanged || (!Number.isNaN(executedAt) && !Number.isNaN(seen) && seen > executedAt + RESTART_SLACK_MS);
  const version = server?.threatcrushd_version ? `v${server.threatcrushd_version}` : "unknown version";

  if (back) {
    if (item.intent === "update" && item.action_type === "restart") {
      return { phase: "online", detail: `Back on ${version}. This daemon is too old for "update now": its auto-updater installs the release within 40 minutes` };
    }
    if (item.intent === "update" && !versionChanged) return { phase: "online", detail: `Back on ${version} (already current)` };
    if (item.intent === "update") return { phase: "online", detail: `Updated ${item.from_version ? `v${item.from_version} → ` : ""}${version}` };
    return { phase: "online", detail: `Back online on ${version}` };
  }
  if (!Number.isNaN(executedAt) && now - executedAt > STALL_MS) {
    return { phase: "stalled", detail: "No heartbeat 5 minutes after the restart: check the daemon on the box (systemctl status threatcrushd)" };
  }
  return { phase: "restarting", detail: "Restarting, waiting for its first heartbeat" };
}
