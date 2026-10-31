export interface ActionCenterDetection {
  server_id: string;
  severity: string;
  source_ip: string | null;
}

export interface ActionCenterServer {
  id: string;
  fleet_id?: string | null;
}

export interface ActionCenterFilters {
  severity: string;
  fleetId: string;
  serverId: string;
  ipQuery: string;
}

export function filterActionCenterDetections<T extends ActionCenterDetection>(
  detections: T[],
  servers: ActionCenterServer[],
  filters: ActionCenterFilters,
): T[] {
  const serverById = new Map(servers.map((server) => [server.id, server]));
  const ipQuery = filters.ipQuery.trim().toLowerCase();
  return detections.filter((detection) => {
    const server = serverById.get(detection.server_id);
    if (filters.severity !== "all" && detection.severity !== filters.severity) return false;
    if (filters.fleetId !== "all" && server?.fleet_id !== filters.fleetId) return false;
    if (filters.serverId !== "all" && detection.server_id !== filters.serverId) return false;
    if (ipQuery && !detection.source_ip?.toLowerCase().includes(ipQuery)) return false;
    return true;
  });
}

export function actionCenterNextStep(severity: string): string {
  if (severity === "critical") return "Investigate the host now and verify the source before containing it.";
  if (severity === "high") return "Review the host and source IP; block it if the activity is unauthorized.";
  if (severity === "medium") return "Check whether this activity is expected, then acknowledge or resolve it.";
  return "Review and resolve if expected.";
}
