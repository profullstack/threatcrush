import { fleetCost, formatMonthly, matchAgents, monthlyCost, parseInventory, type Device, type Monthly } from "@profullstack/fleet";
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
  /** "no-agent": a device from the org's OpenDevice inventory with no daemon linked. */
  connection: ServerConnectionState | "no-agent";
  /** False for an inventory device that never linked a ThreatCrush daemon. */
  agent: boolean;
  /** The inventory device this row is, or matched to; null when the org has no inventory entry for it. */
  device: FleetDevice | null;
  /** Behind the newest version anywhere in this fleet. */
  outdated: boolean;
  /** `[remediation]` as last saved with `threatcrush save`, secrets redacted. */
  remediation: Record<string, unknown> | null;
  config_saved_at: string | null;
  created_at: string;
  /** Last `os-patches` report, or null when the daemon has never sent one. */
  patches: FleetPatches | null;
}

/** An OpenDevice inventory entry as the fleet view shows it. */
export interface FleetDevice {
  id: string;
  name: string;
  profile: Device["profile"];
  status: Device["status"];
  role: string | null;
  provider: string | null;
  hostnames: string[];
  ipv4: string[];
  monthly: Monthly;
  /** "$149.00", or "unstated" when the inventory gives no amount. Never guessed. */
  monthly_label: string;
}

/** A `fleet_inventories` row as the fleet route reads it. */
export interface InventoryRow {
  org_id: string;
  document: unknown;
  updated_at: string;
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
  /** Every row: linked daemons plus inventory devices without one. */
  total: number;
  /** Rows with a linked ThreatCrush daemon. */
  installs: number;
  online: number;
  /** Linked daemons that stopped reporting (agentless devices are not counted here). */
  offline: number;
  /** Inventory devices with no daemon linked. */
  no_agent: number;
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
  /** Stated monthly cost per currency across every inventory, never converted. */
  monthly_total: Record<string, number>;
  /** formatMonthly(monthly_total), "—" with no stated cost. */
  monthly_total_label: string;
  /** Devices whose cost is counted in the total. */
  cost_counted: number;
  /** Devices whose cost the inventory does not state (shown as "unstated"). */
  cost_unstated: number;
  /** Organizations with an inventory loaded. */
  inventories: number;
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
  /** The address the daemon reported from; matched against inventory addresses. */
  public_ip?: string | null;
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
  inventories: InventoryRow[] = [],
  /** Servers in the inventories' orgs the caller cannot see: they still claim their device. */
  hiddenRows: Array<Pick<ServerRow, "id" | "name" | "hostname" | "ip_address" | "public_ip" | "org_id">> = [],
  /** The newest published release (npm), when known: "outdated" is measured against it too. */
  published: string | null = null,
): { servers: FleetServer[]; summary: FleetSummary } {
  const at = new Date(now);
  const deviceOf = new Map<string, FleetDevice>();
  const agentless: Array<{ orgId: string; device: FleetDevice; updatedAt: string }> = [];
  const monthlyTotal: Record<string, number> = {};
  let costCounted = 0;
  let costUnstated = 0;
  let inventoriesLoaded = 0;
  for (const inv of inventories) {
    let doc;
    try {
      doc = parseInventory(inv.document as object);
    } catch {
      continue; // stored documents are validated on write; a bad one costs its rows, not the page
    }
    inventoriesLoaded++;
    const cost = fleetCost(doc, { now: at });
    for (const [cur, n] of Object.entries(cost.monthly)) monthlyTotal[cur] = round2((monthlyTotal[cur] ?? 0) + n);
    costCounted += cost.counted;
    costUnstated += cost.unstated.length;

    const orgServers = [...rows, ...hiddenRows].filter((r) => r.org_id === inv.org_id);
    const { devices } = matchAgents(doc, orgServers, {
      hostname: (s) => s.hostname,
      name: (s) => s.name,
      ip: (s) => s.public_ip ?? s.ip_address,
    });
    for (const { device, agents } of devices) {
      const view = fleetDevice(device, at);
      if (agents.length === 0) {
        if (device.status !== "retired") agentless.push({ orgId: inv.org_id, device: view, updatedAt: inv.updated_at });
        continue;
      }
      for (const a of agents) deviceOf.set(a.id, view);
    }
  }

  const patchesByServer = new Map(patchRows.map((row) => [row.server_id, fleetPatches(row)]));
  const latest = rows
    .map((r) => r.threatcrushd_version)
    .filter((v): v is string => Boolean(v))
    .reduce<string | null>((best, v) => (compareVersions(v, best) > 0 ? v : best), published);

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
      agent: true,
      device: deviceOf.get(r.id) ?? null,
      outdated: Boolean(latest && r.threatcrushd_version && compareVersions(r.threatcrushd_version, latest) < 0),
      remediation,
      config_saved_at: r.config_saved_at,
      created_at: r.created_at,
      patches: patchesByServer.get(r.id) ?? null,
    };
  });

  for (const { orgId, device, updatedAt } of agentless) {
    const org = orgs.get(orgId);
    servers.push({
      id: `device:${orgId}:${device.id}`,
      name: device.name,
      hostname: device.hostnames[0] ?? null,
      ip_address: device.ipv4[0] ?? null,
      org_id: orgId,
      org_name: org?.name ?? "—",
      org_slug: org?.slug ?? "",
      fleet_id: null,
      fleet_name: null,
      last_seen: null,
      threatcrushd_version: null,
      connection: "no-agent",
      agent: false,
      device,
      outdated: false,
      remediation: null,
      config_saved_at: null,
      created_at: updatedAt,
      patches: null,
    });
  }

  // Offline first, then behind, then by org and name: what needs attention on top.
  const rank = (c: FleetServer["connection"]) => (c === "offline" ? 0 : c === "online" ? 1 : 2);
  servers.sort((a, b) =>
    rank(a.connection) - rank(b.connection)
    || Number(b.outdated) - Number(a.outdated)
    || a.org_name.localeCompare(b.org_name)
    || a.name.localeCompare(b.name));

  const online = servers.filter((s) => s.connection === "online").length;
  const installs = servers.filter((s) => s.agent).length;
  const reported = servers.flatMap((s) => (s.patches && !s.patches.unsupported ? [s.patches] : []));
  return {
    servers,
    summary: {
      total: servers.length,
      installs,
      online,
      offline: installs - online,
      no_agent: servers.length - installs,
      latest_version: latest,
      outdated: servers.filter((s) => s.outdated).length,
      organizations: new Set(servers.map((s) => s.org_id)).size,
      patch_reported: reported.length,
      patch_hosts_with_fixes: reported.filter((p) => p.packages > 0).length,
      patch_cves: reported.reduce((n, p) => n + p.cves, 0),
      patch_critical_high: reported.reduce((n, p) => n + p.critical + p.high, 0),
      monthly_total: monthlyTotal,
      monthly_total_label: formatMonthly(monthlyTotal),
      cost_counted: costCounted,
      cost_unstated: costUnstated,
      inventories: inventoriesLoaded,
    },
  };
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}

/** One inventory device for the fleet view, with its monthly run rate. */
export function fleetDevice(d: Device, now: Date = new Date()): FleetDevice {
  const monthly = monthlyCost(d, { now });
  return {
    id: d.id,
    name: d.name,
    profile: d.profile,
    status: d.status,
    role: d.role ?? null,
    provider: d.provider?.name ?? null,
    hostnames: d.hostnames,
    ipv4: d.addresses.ipv4,
    monthly,
    monthly_label: monthlyLabel(monthly),
  };
}

/** "$149.00" for a stated cost, "unstated" when there is no amount; never a guess. */
export function monthlyLabel(m: Monthly): string {
  if (m.amount == null) return m.state === "grouped" ? "grouped" : "unstated";
  if (m.state === "retired") return "retired";
  if (m.state === "ended") return "ended";
  return m.currency ? formatMonthly({ [m.currency]: m.amount }) : String(m.amount);
}
