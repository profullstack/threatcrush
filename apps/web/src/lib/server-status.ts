// A linked daemon heartbeats every minute or so. The stored `servers.status`
// is only ever set to online (by a heartbeat), so it is never trusted for
// display: connection state is derived from how recently the server was seen.

export const SERVER_OFFLINE_AFTER_MS = 3 * 60 * 1000;

export type ServerConnectionState = "online" | "offline";

export function serverConnectionState(
  lastSeen: string | null | undefined,
  now: number = Date.now(),
): ServerConnectionState {
  if (!lastSeen) return "offline";
  const seen = Date.parse(lastSeen);
  if (!Number.isFinite(seen)) return "offline";
  return now - seen <= SERVER_OFFLINE_AFTER_MS ? "online" : "offline";
}

/**
 * A server row as the API returns it: `status` replaced by the derived state,
 * so the CLI, MCP and any other client cannot show a server that stopped
 * reporting weeks ago as "online" (the stored column never goes offline).
 * A stored "unreachable" (set by a failed probe) still wins while seen.
 */
export function withConnectionState<T extends object>(server: T, now: number = Date.now()): T & { status: string } {
  const { status, last_seen } = server as { status?: string | null; last_seen?: string | null };
  const derived = serverConnectionState(last_seen, now);
  return { ...server, status: derived === "online" && status === "unreachable" ? "unreachable" : derived };
}
