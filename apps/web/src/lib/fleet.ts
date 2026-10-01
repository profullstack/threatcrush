import { serverConnectionState, type ServerConnectionState } from "@/lib/server-status";

/**
 * Every ThreatCrush install a user can see, across all of their organizations,
 * for the dashboard's fleet view.
 */

export interface FleetServer {
  id: string;
  name: string;
  hostname: string | null;
  ip_address: string | null;
  org_id: string;
  org_name: string;
  org_slug: string;
  fleet_id: string | null;
  fleet_name: string | null;
  last_seen: string | null;
  threatcrushd_version: string | null;
  connection: ServerConnectionState;
  /** Behind the newest version anywhere in this fleet. */
  outdated: boolean;
  /** `[remediation]` as last saved with `threatcrush save`, secrets redacted. */
  remediation: Record<string, unknown> | null;
  config_saved_at: string | null;
  created_at: string;
}

export interface FleetSummary {
  total: number;
  online: number;
  offline: number;
  latest_version: string | null;
  outdated: number;
  organizations: number;
}

/** Numeric dotted-version compare; anything unparsable sorts lowest. */
export function compareVersions(a: string | null, b: string | null): number {
  const parse = (v: string | null) =>
    (v ?? "").replace(/^v/, "").split(/[.+-]/).slice(0, 3).map((n) => Number.parseInt(n, 10) || 0);
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < 3; i++) {
    if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
  }
  return 0;
}

interface ServerRow {
  id: string;
  name: string;
  hostname: string | null;
  ip_address: string | null;
  org_id: string;
  fleet_id?: string | null;
  last_seen: string | null;
  threatcrushd_version: string | null;
  config: Record<string, unknown> | null;
  config_saved_at: string | null;
  created_at: string;
}

export function buildFleet(
  rows: ServerRow[],
  orgs: Map<string, { name: string; slug: string }>,
  now: number = Date.now(),
  fleetNames: Map<string, string> = new Map(),
): { servers: FleetServer[]; summary: FleetSummary } {
  const latest = rows
    .map((r) => r.threatcrushd_version)
    .filter((v): v is string => Boolean(v))
    .reduce<string | null>((best, v) => (compareVersions(v, best) > 0 ? v : best), null);

  const servers: FleetServer[] = rows.map((r) => {
    const org = orgs.get(r.org_id);
    const remediation = r.config && typeof r.config.remediation === "object" && r.config.remediation
      ? (r.config.remediation as Record<string, unknown>)
      : null;
    return {
      id: r.id,
      name: r.name,
      hostname: r.hostname,
      ip_address: r.ip_address,
      org_id: r.org_id,
      org_name: org?.name ?? "—",
      org_slug: org?.slug ?? "",
      fleet_id: r.fleet_id ?? null,
      fleet_name: r.fleet_id ? fleetNames.get(r.fleet_id) ?? null : null,
      last_seen: r.last_seen,
      threatcrushd_version: r.threatcrushd_version,
      connection: serverConnectionState(r.last_seen, now),
      outdated: Boolean(latest && r.threatcrushd_version && compareVersions(r.threatcrushd_version, latest) < 0),
      remediation,
      config_saved_at: r.config_saved_at,
      created_at: r.created_at,
    };
  });

  // Offline first, then behind, then by org and name: what needs attention on top.
  servers.sort((a, b) =>
    (a.connection === "offline" ? 0 : 1) - (b.connection === "offline" ? 0 : 1)
    || Number(b.outdated) - Number(a.outdated)
    || a.org_name.localeCompare(b.org_name)
    || a.name.localeCompare(b.name));

  const online = servers.filter((s) => s.connection === "online").length;
  return {
    servers,
    summary: {
      total: servers.length,
      online,
      offline: servers.length - online,
      latest_version: latest,
      outdated: servers.filter((s) => s.outdated).length,
      organizations: new Set(servers.map((s) => s.org_id)).size,
    },
  };
}
