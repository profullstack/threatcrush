import chalk from "chalk";
import { homedir } from "node:os";
import { readFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { execSync, spawn } from "node:child_process";

const API_URL = process.env.THREATCRUSH_API_URL || "https://threatcrush.com";
const CONFIG_PATH = join(homedir(), ".threatcrush", "config.json");

interface CliConfig {
  email?: string;
  token?: string;
  current_org_id?: string;
  current_org_slug?: string;
}

interface Server {
  id: string;
  name: string;
  hostname: string | null;
  ip_address: string | null;
  port: number;
  ssh_username: string | null;
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

export async function connectCommand(options: {
  target?: string;
  org?: string;
  user?: string;
  port?: string;
  identity?: string;
}): Promise<void> {
  const { target, org, user, port, identity } = options;

  if (!target) {
    // Interactive mode — list available servers
    await interactiveConnect(org);
    return;
  }

  // Check if target is a server name (resolve via API)
  const server = await resolveServer(target, org);

  if (server) {
    // Connect via SSH using server metadata
    await sshConnect({
      hostname: server.hostname || server.ip_address,
      port: server.port,
      username: user || server.ssh_username || null,
      identity,
    });
  } else if (target.includes("@") || target.includes(".")) {
    // Treat as direct hostname
    await sshConnect({
      hostname: target.includes("@") ? target.split("@")[1] : target,
      port: parseInt(port || "22", 10),
      username: target.includes("@") ? target.split("@")[0] : (user || null),
      identity,
    });
  } else {
    console.log(chalk.red(`  Server "${target}" not found in your organizations.\n`));
    console.log(chalk.dim("  List available servers: threatcrush servers list"));
    console.log(chalk.dim("  Or connect directly: threatcrush connect user@hostname\n"));
  }
}

async function interactiveConnect(orgSlug?: string): Promise<void> {
  const config = readConfig();

  try {
    // Get orgs
    const orgsRes = await fetch(`${API_URL}/api/orgs`, { headers: getAuthHeaders() });
    if (!orgsRes.ok) {
      console.log(chalk.red("  Failed to fetch organizations. Are you logged in?\n"));
      return;
    }
    const orgsData = await orgsRes.json() as { organizations?: Array<Record<string, unknown>> };
    let orgs = orgsData.organizations || [];

    if (orgSlug) {
      orgs = orgs.filter((o) => o.slug === orgSlug);
    }

    if (orgs.length === 0) {
      console.log(chalk.yellow("  No organizations found."));
      console.log(chalk.dim("  Create one: threatcrush orgs create <name>\n"));
      return;
    }

    // If multiple orgs, pick current
    let orgId = config.current_org_id;
    if (orgs.length > 1 && !orgId) {
      orgId = orgs[0].id as string;
    }
    if (!orgId) {
      orgId = orgs[0].id as string;
    }

    // Get servers for org
    const serversRes = await fetch(`${API_URL}/api/orgs/${orgId}/servers`, { headers: getAuthHeaders() });
    if (!serversRes.ok) {
      console.log(chalk.red("  Failed to fetch servers.\n"));
      return;
    }
    const serversData = await serversRes.json() as { servers?: Server[] };
    const servers = serversData.servers || [];

    if (servers.length === 0) {
      console.log(chalk.yellow("  No servers in this organization."));
      console.log(chalk.dim("  Add servers via the web dashboard.\n"));
      return;
    }

    console.log(chalk.green("  Available Servers\n"));

    for (const server of servers) {
      const s = server as unknown as Record<string, unknown>;
      const status = s.status as string;
      const statusColor = status === "online" ? chalk.green : chalk.gray;
      const statusDot = status === "online" ? "●" : "○";
      console.log(`  ${chalk.bold((s.name as string).padEnd(20))} ${statusColor(statusDot)} ${chalk.dim(`${s.hostname || s.ip_address}:${s.port}`)}`);
    }

    console.log();
    console.log(chalk.dim("  Connect: threatcrush connect <server-name>"));
    console.log(chalk.dim("  Or:     threatcrush connect user@hostname\n"));
  } catch (err) {
    console.log(chalk.red(`  Failed: ${err instanceof Error ? err.message : err}\n`));
  }
}

async function resolveServer(nameOrSlug: string, orgSlug?: string): Promise<Server | null> {
  const config = readConfig();

  try {
    // Get orgs
    let orgId = config.current_org_id;

    if (orgSlug) {
      const orgsRes = await fetch(`${API_URL}/api/orgs`, { headers: getAuthHeaders() });
      if (!orgsRes.ok) return null;
      const orgsData = await orgsRes.json() as { organizations?: Array<Record<string, unknown>> };
      const org = (orgsData.organizations || []).find((o) => o.slug === orgSlug);
      if (!org) return null;
      orgId = org.id as string;
    }

    if (!orgId) {
      // Try first org
      const orgsRes = await fetch(`${API_URL}/api/orgs`, { headers: getAuthHeaders() });
      if (!orgsRes.ok) return null;
      const orgsData = await orgsRes.json() as { organizations?: Array<Record<string, unknown>> };
      orgId = (orgsData.organizations || [])[0]?.id as string;
      if (!orgId) return null;
    }

    // Get servers
    const serversRes = await fetch(`${API_URL}/api/orgs/${orgId}/servers`, { headers: getAuthHeaders() });
    if (!serversRes.ok) return null;
    const serversData = await serversRes.json() as { servers?: Server[] };
    const servers = serversData.servers || [];

    // Match by name
    const server = servers.find((s) => s.name.toLowerCase() === nameOrSlug.toLowerCase());
    return server || null;
  } catch {
    return null;
  }
}

async function sshConnect(options: {
  hostname: string | null;
  port: number;
  username: string | null;
  identity?: string;
}): Promise<void> {
  const { hostname, port, username, identity } = options;

  if (!hostname) {
    console.log(chalk.red("  No hostname available for this server.\n"));
    return;
  }

  const user = username || "root";

  console.log(chalk.green(`  Connecting to ${user}@${hostname}:${port}...\n`));
  console.log(chalk.dim("  (Spawning SSH session — exit with Ctrl+D or type 'exit')\n"));

  const sshArgs = ["-p", String(port)];
  if (identity) {
    sshArgs.push("-i", identity);
  }
  sshArgs.push(`${user}@${hostname}`);

  // Spawn SSH as a direct child process, inheriting stdio
  const ssh = spawn("ssh", sshArgs, { stdio: "inherit" });

  ssh.on("error", (err) => {
    console.log(chalk.red(`\n  SSH error: ${err.message}\n`));
  });

  ssh.on("exit", (code) => {
    if (code === 0) {
      console.log(chalk.dim("\n  SSH session ended.\n"));
    } else if (code !== null) {
      console.log(chalk.yellow(`\n  SSH exited with code ${code}\n`));
    }
  });
}
