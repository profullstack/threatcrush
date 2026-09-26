import chalk from "chalk";
import readline from "node:readline";
import { hostname as osHostname } from "node:os";
import {
  clearCliConfig,
  cloudFetch,
  hasSession,
  readCliConfig,
  updateCliConfig,
} from "../core/cli-config.js";

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

interface Org {
  id: string;
  slug: string;
  name: string;
}

// ─── Servers ───

export async function serversCommand(options: { action?: string; name?: string; org?: string }): Promise<void> {
  const { action, name, org } = options;

  if (action === "list" || !action) {
    await listServers(org);
    return;
  }

  if (action === "link") {
    await linkCommand({ org, name });
    return;
  }

  if (action === "unlink") {
    unlinkCommand();
    return;
  }

  if (action === "add") {
    console.log(chalk.red("  Interactive server add is not yet implemented."));
    console.log(chalk.dim("  Use the web dashboard to add servers: https://threatcrush.com/dashboard\n"));
    return;
  }

  console.log(chalk.red(`  Unknown action: ${action}`));
  console.log(chalk.dim("  Available: list, link, unlink\n"));
}

async function fetchOrgs(): Promise<Org[]> {
  const res = await cloudFetch("/api/orgs");
  if (res.status === 401) throw new Error("Not authenticated. Run: threatcrush login");
  if (!res.ok) throw new Error(`Failed to fetch organizations (${res.status})`);
  const data = await res.json() as { organizations?: Org[] };
  return data.organizations || [];
}

function askChoice(question: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(question, (answer) => {
    rl.close();
    resolve(answer.trim());
  }));
}

/**
 * The org to link into: `--org` (id or slug), else the current org, else the
 * only org, else ask.
 */
async function chooseOrg(
  orgs: Org[],
  flag: string | undefined,
  ask: (question: string) => Promise<string>,
): Promise<Org> {
  if (flag) {
    const org = orgs.find((o) => o.id === flag || o.slug === flag);
    if (!org) throw new Error(`Organization "${flag}" not found among yours.`);
    return org;
  }
  const current = orgs.find((o) => o.id === readCliConfig().current_org_id);
  if (current) return current;
  if (orgs.length === 1) return orgs[0];
  if (orgs.length === 0) throw new Error("You are not in any organization. Create one: threatcrush orgs create <name>");
  if (!process.stdin.isTTY) {
    throw new Error(`You are in ${orgs.length} organizations; pick one with --org <${orgs.map((o) => o.slug).join("|")}>`);
  }
  orgs.forEach((o, i) => console.log(`  ${i + 1}) ${o.name} ${chalk.gray(`(/${o.slug})`)}`));
  const answer = await ask(chalk.green(`  Link to which organization? [1-${orgs.length}]: `));
  const org = orgs[Number(answer) - 1];
  if (!org) throw new Error("No organization chosen.");
  return org;
}

export interface LinkResult {
  org: Org;
  server: Pick<Server, "id" | "name" | "hostname">;
  created: boolean;
}

/**
 * Link this machine to a `servers` row: reuse the one whose hostname matches
 * this host (so relinking or reinstalling does not pile up duplicates),
 * otherwise register a new one. Stores the ids in ~/.threatcrush/config.json,
 * where the daemon picks them up on its next tick.
 */
export async function linkServer(
  opts: { org?: string; name?: string; hostname?: string } = {},
  ask: (question: string) => Promise<string> = askChoice,
): Promise<LinkResult> {
  if (!hasSession()) throw new Error("Not logged in. Run: threatcrush login");

  const org = await chooseOrg(await fetchOrgs(), opts.org, ask);
  const host = opts.hostname ?? osHostname();

  const listRes = await cloudFetch(`/api/orgs/${org.id}/servers`);
  if (!listRes.ok) throw new Error(`Failed to list servers in /${org.slug} (${listRes.status})`);
  const { servers = [] } = await listRes.json() as { servers?: Server[] };

  // Hostnames are case-insensitive; `--name` breaks a tie between several rows.
  const matches = servers.filter((s) => s.hostname?.toLowerCase() === host.toLowerCase());
  let server: Pick<Server, "id" | "name" | "hostname"> | undefined =
    matches.find((s) => opts.name && s.name === opts.name) ?? matches[0];
  let created = false;

  if (!server) {
    const res = await cloudFetch(`/api/orgs/${org.id}/servers`, {
      method: "POST",
      body: JSON.stringify({ name: opts.name || host, hostname: host }),
    });
    const data = await res.json().catch(() => ({})) as { server?: Server; error?: string };
    if (!res.ok || !data.server) {
      throw new Error(`Could not register this server in /${org.slug}: ${data.error || res.status}`);
    }
    server = data.server;
    created = true;
  }

  updateCliConfig({ server_id: server.id, server_org_id: org.id });
  return { org, server, created };
}

async function linkCommand(opts: { org?: string; name?: string }): Promise<void> {
  try {
    const { org, server, created } = await linkServer(opts);
    console.log(chalk.green(`  ✓ ${created ? "Registered and linked" : "Linked"} ${chalk.bold(server.name)} in /${org.slug}`));
    console.log(chalk.dim(`    server id: ${server.id}  hostname: ${server.hostname ?? "-"}`));
    console.log(chalk.dim("    A running daemon starts reporting within a minute; no restart needed."));
    console.log(chalk.dim("    Opt out in threatcrushd.conf: [cloud] enabled = false\n"));
  } catch (err) {
    console.log(chalk.red(`  ✗ ${(err as Error).message}\n`));
    process.exitCode = 1;
  }
}

function unlinkCommand(): void {
  const cfg = readCliConfig();
  if (!cfg.server_id) {
    console.log(chalk.gray("  This machine is not linked to a dashboard server.\n"));
    return;
  }
  clearCliConfig(["server_id", "server_org_id"]);
  console.log(chalk.green(`  ✓ Unlinked from server ${cfg.server_id}.`));
  console.log(chalk.dim("    The daemon stops reporting within a minute. The server stays on the dashboard until you delete it there.\n"));
}

async function listServers(orgSlug?: string): Promise<void> {
  const config = readCliConfig();

  if (!config.current_org_id && !orgSlug) {
    console.log(chalk.yellow("  No current organization set."));
    console.log(chalk.dim("  Set one with: threatcrush orgs use <slug>\n"));
    return;
  }

  console.log(chalk.green("  Servers\n"));

  try {
    let orgId = config.current_org_id;

    if (orgSlug) {
      const org = (await fetchOrgs()).find((o) => o.slug === orgSlug);
      if (!org) {
        console.log(chalk.red(`  Organization "/${orgSlug}" not found.\n`));
        return;
      }
      orgId = org.id;
    }

    if (!orgId) {
      console.log(chalk.red("  Could not resolve organization.\n"));
      return;
    }

    const res = await cloudFetch(`/api/orgs/${orgId}/servers`);
    if (!res.ok) {
      console.log(chalk.red(`  Failed to list servers: ${res.statusText}\n`));
      return;
    }

    const data = await res.json() as { servers?: Server[] };
    const servers = data.servers || [];

    if (servers.length === 0) {
      console.log(chalk.yellow("  No servers registered."));
      console.log(chalk.dim("  Link this machine: threatcrush servers link\n"));
      return;
    }

    for (const server of servers) {
      const statusColor = server.status === "online" ? chalk.green : server.status === "unreachable" ? chalk.red : chalk.gray;
      const statusDot = server.status === "online" ? "●" : "○";
      const self = server.id === config.server_id ? chalk.cyan(" (this machine)") : "";

      console.log(`  ${statusColor(statusDot)} ${chalk.bold(server.name)}${self}`);
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
