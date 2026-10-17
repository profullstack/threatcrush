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
  /** Last `os-patches` report, or null when the daemon has never sent one. */
  patches: FleetPatches | null;
}

/** A server's pending security updates, from its `os-patches` finding. */
export interface FleetPatches {
  status: string;
  /** Source packages with a security update waiting. */
  packages: number;
  cves: number;
  critical: number;
  high: number;
  lists_stale: boolean;
  /** The check could not run here (not Debian/Ubuntu). */
  unsupported: boolean;
  observed_at: string;
}

/** The `hardening_findings` row for `os-patches`, as the fleet route reads it. */
export interface PatchFindingRow {
  server_id: string;
  status: string;
  observed_at: string;
  details: Record<string, unknown> | null;
}

export interface FleetSummary {
  total: number;
  online: number;
  offline: number;
  latest_version: string | null;
  outdated: number;
  organizations: number;
  /** Servers that have reported patch status on a supported OS. */
  patch_reported: number;
  /** Servers with at least one security update waiting. */
  patch_hosts_with_fixes: number;
  /** CVEs fixed by pending updates, summed across servers. */
  patch_cves: number;
  patch_critical_high: number;
}

function num(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

/** Summarize an `os-patches` row; tolerant of a missing or older `details`. */
export function fleetPatches(row: PatchFindingRow): FleetPatches {
  const d = row.details ?? {};
  const counts = (d.counts && typeof d.counts === "object" ? d.counts : {}) as Record<string, unknown>;
  return {
    status: row.status,
    packages: num(counts.packages),
    cves: num(counts.cves),
    critical: num(counts.critical),
    high: num(counts.high),
    lists_stale: d.lists_stale === true,
    unsupported: d.supported === false,
    observed_at: row.observed_at,
  };
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
  patchRows: PatchFindingRow[] = [],
): { servers: FleetServer[]; summary: FleetSummary } {
  const patchesByServer = new Map(patchRows.map((row) => [row.server_id, fleetPatches(row)]));
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
      patches: patchesByServer.get(r.id) ?? null,
    };
  });

  // Offline first, then behind, then by org and name: what needs attention on top.
  servers.sort((a, b) =>
    (a.connection === "offline" ? 0 : 1) - (b.connection === "offline" ? 0 : 1)
    || Number(b.outdated) - Number(a.outdated)
    || a.org_name.localeCompare(b.org_name)
    || a.name.localeCompare(b.name));

  const online = servers.filter((s) => s.connection === "online").length;
  const reported = servers.flatMap((s) => (s.patches && !s.patches.unsupported ? [s.patches] : []));
  return {
    servers,
    summary: {
      total: servers.length,
      online,
      offline: servers.length - online,
      latest_version: latest,
      outdated: servers.filter((s) => s.outdated).length,
      organizations: new Set(servers.map((s) => s.org_id)).size,
      patch_reported: reported.length,
      patch_hosts_with_fixes: reported.filter((p) => p.packages > 0).length,
      patch_cves: reported.reduce((n, p) => n + p.cves, 0),
      patch_critical_high: reported.reduce((n, p) => n + p.critical + p.high, 0),
    },
  };
}
