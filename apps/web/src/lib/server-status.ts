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
