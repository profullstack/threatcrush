import chalk from "chalk";
import { homedir } from "node:os";
import { readFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const API_URL = process.env.THREATCRUSH_API_URL || "https://threatcrush.com";
const CONFIG_PATH = join(homedir(), ".threatcrush", "config.json");

interface CliConfig {
  email?: string;
  token?: string;
  current_org_id?: string;
  current_org_slug?: string;
}

function readConfig(): CliConfig {
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, "utf-8"));
  } catch {
    return {};
  }
}

function getAuthHeaders(): Record<string, string> {
  const config = readConfig();
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (config.token) headers["Authorization"] = `Bearer ${config.token}`;
  return headers;
}

interface Server {
  id: string;
  name: string;
  hostname: string | null;
  ip_address: string | null;
  port: number;
  ssh_username: string | null;
  status: string;
  last_seen: string | null;
  threatcrushd_version: string | null;
}

// ─── Servers ───

export async function serversCommand(options: { action?: string; name?: string; org?: string }): Promise<void> {
  const { action, name, org } = options;

  if (action === "list" || !action) {
    await listServers(org);
    return;
  }

  if (action === "add") {
    console.log(chalk.red("  Interactive server add is not yet implemented."));
    console.log(chalk.dim("  Use the web dashboard to add servers: https://threatcrush.com/dashboard\n"));
    return;
  }

  console.log(chalk.red(`  Unknown action: ${action}`));
  console.log(chalk.dim("  Available: list\n"));
}

async function listServers(orgSlug?: string): Promise<void> {
  const config = readConfig();

  if (!config.current_org_id && !orgSlug) {
    console.log(chalk.yellow("  No current organization set."));
    console.log(chalk.dim("  Set one with: threatcrush orgs use <slug>\n"));
    return;
  }

  console.log(chalk.green("  Servers\n"));

  try {
    // First get orgs to resolve the ID if only slug is given
    let orgId = config.current_org_id;

    if (orgSlug) {
      const orgsRes = await fetch(`${API_URL}/api/orgs`, { headers: getAuthHeaders() });
      if (!orgsRes.ok) {
        console.log(chalk.red(`  Failed to fetch organizations: ${orgsRes.statusText}\n`));
        return;
      }
      const orgsData = await orgsRes.json() as { organizations?: Array<Record<string, unknown>> };
      const org = (orgsData.organizations || []).find((o) => o.slug === orgSlug);
      if (!org) {
        console.log(chalk.red(`  Organization "/${orgSlug}" not found.\n`));
        return;
      }
      orgId = org.id as string;
    }

    if (!orgId) {
      console.log(chalk.red("  Could not resolve organization.\n"));
      return;
    }

    const res = await fetch(`${API_URL}/api/orgs/${orgId}/servers`, { headers: getAuthHeaders() });
    if (!res.ok) {
      console.log(chalk.red(`  Failed to list servers: ${res.statusText}\n`));
      return;
    }

    const data = await res.json() as { servers?: Server[] };
    const servers = data.servers || [];

    if (servers.length === 0) {
      console.log(chalk.yellow("  No servers registered."));
      console.log(chalk.dim("  Add servers via the web dashboard.\n"));
      return;
    }

    for (const server of servers) {
      const statusColor = server.status === "online" ? chalk.green : server.status === "unreachable" ? chalk.red : chalk.gray;
      const statusDot = server.status === "online" ? "●" : "○";

      console.log(`  ${statusColor(statusDot)} ${chalk.bold(server.name)}`);
      console.log(`    ${chalk.dim(`${server.hostname || server.ip_address}:${server.port}`)}`);
      console.log(`    Status: ${statusColor(server.status)}`);
      if (server.last_seen) {
        console.log(`    Last seen: ${chalk.dim(timeAgo(server.last_seen))}`);
      }
      if (server.threatcrushd_version) {
        console.log(`    Version: ${chalk.dim(server.threatcrushd_version)}`);
      }
      if (server.ssh_username) {
        console.log(`    SSH user: ${chalk.dim(server.ssh_username)}`);
      }
      console.log();
    }

    console.log(chalk.dim("  Connect: threatcrush connect <server-name>\n"));
  } catch (err) {
    console.log(chalk.red(`  Failed: ${err instanceof Error ? err.message : err}\n`));
  }
}

function timeAgo(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
