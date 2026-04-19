#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import readline from "readline";
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { monitorCommand } from "./commands/monitor.js";
import { scanCommand } from "./commands/scan.js";
import { initCommand } from "./commands/init.js";
import { statusCommand } from "./commands/status.js";
import { modulesCommand } from "./commands/modules.js";
import { pentestCommand } from "./commands/pentest.js";
import { orgsCommand } from "./commands/orgs.js";
import { serversCommand } from "./commands/servers.js";
import { connectCommand } from "./commands/connect.js";
import { daemonForeground, daemonStart, daemonStop } from "./commands/daemon.js";
import { installServiceCommand, uninstallServiceCommand } from "./commands/service.js";
import { loginCommand, logoutCommand, whoamiCommand } from "./commands/login.js";
import { welcomeCommand } from "./commands/welcome.js";
import {
  propertiesAddCommand,
  propertiesImportCommand,
  propertiesListCommand,
  propertiesRemoveCommand,
  propertiesRunCommand,
  propertiesRunsCommand,
} from "./commands/properties.js";
import { PATHS } from "./daemon/paths.js";

let PKG_VERSION = "0.1.8";
try {
  const pkg = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf-8"));
  PKG_VERSION = pkg.version;
} catch {}

const LOGO = `
${chalk.green("  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗")}
${chalk.green("  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝")}
${chalk.green("     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ")}
${chalk.green("     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ")}
${chalk.green("     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ")}
${chalk.green("     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝")}
${chalk.dim("                    C R U S H")}
`;

const API_URL = process.env.THREATCRUSH_API_URL || "https://threatcrush.com";
const PKG_NAME = "@profullstack/threatcrush";
const DESKTOP_PKG_NAME = "@profullstack/threatcrush-desktop";
const INSTALL_CONFIG_PATH = join(homedir(), ".threatcrush", "install.json");

// ─── Helpers ───

async function joinWaitlist(email: string): Promise<{ referral_code?: string } | null> {
  try {
    const res = await fetch(`${API_URL}/api/waitlist`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    return await res.json();
  } catch {
    return null;
  }
}

function detectPackageManager(): string {
  // Check what installed us
  try {
    const npmGlobal = execSync("npm ls -g --depth=0 --json 2>/dev/null", { encoding: "utf-8" });
    if (npmGlobal.includes(PKG_NAME)) return "npm";
  } catch {}
  try {
    execSync("pnpm --version", { stdio: "pipe" });
    return "pnpm";
  } catch {}
  try {
    execSync("yarn --version", { stdio: "pipe" });
    return "yarn";
  } catch {}
  try {
    execSync("bun --version", { stdio: "pipe" });
    return "bun";
  } catch {}
  return "npm";
}

function readInstallConfig(): { installMode?: string; packageManager?: string; installMethod?: string } {
  try {
    return JSON.parse(readFileSync(INSTALL_CONFIG_PATH, "utf-8"));
  } catch {
    return {};
  }
}

function getGlobalInstallCommand(pm: string, pkgName: string, action: "install" | "update" | "remove"): string {
  const commands: Record<string, Record<string, string>> = {
    npm: {
      install: `npm i -g ${pkgName}`,
      update: `npm update -g ${pkgName}`,
      remove: `npm uninstall -g ${pkgName}`,
    },
    pnpm: {
      install: `pnpm add -g ${pkgName}`,
      update: `pnpm update -g ${pkgName}`,
      remove: `pnpm remove -g ${pkgName}`,
    },
    yarn: {
      install: `yarn global add ${pkgName}`,
      update: `yarn global upgrade ${pkgName}`,
      remove: `yarn global remove ${pkgName}`,
    },
    bun: {
      install: `bun add -g ${pkgName}`,
      update: `bun update -g ${pkgName}`,
      remove: `bun remove -g ${pkgName}`,
    },
  };

  return commands[pm]?.[action] || commands.npm[action];
}

function packageLooksInstalled(pm: string, pkgName: string): boolean {
  try {
    const listCommands: Record<string, string> = {
      npm: `npm ls -g ${pkgName} --depth=0`,
      pnpm: `pnpm list -g ${pkgName} --depth=0`,
      yarn: `yarn global list --pattern ${pkgName}`,
      bun: `bun pm ls -g`,
    };

    const output = execSync(listCommands[pm] || listCommands.npm, {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "pipe"],
    });

    return output.includes(pkgName);
  } catch {
    return false;
  }
}

// ─── Program ───

const program = new Command();

program
  .name("threatcrush")
  .description(
    `${chalk.green("⚡ ThreatCrush")} — All-in-one security agent

  Monitor every connection on every port. Detect live attacks,
  scan your code, pentest your APIs, and alert you in real-time.

  ${chalk.dim("Website:")}  ${chalk.green("https://threatcrush.com")}
  ${chalk.dim("GitHub:")}   ${chalk.green("https://github.com/profullstack/threatcrush")}
  ${chalk.dim("npm:")}      ${chalk.green("https://www.npmjs.com/package/@profullstack/threatcrush")}
  ${chalk.dim("License:")}  ${chalk.green("$499 lifetime")} (or $399 with referral)

${chalk.dim("Examples:")}
  ${chalk.green("$")} threatcrush monitor          ${chalk.dim("# Real-time monitoring")}
  ${chalk.green("$")} threatcrush tui              ${chalk.dim("# Interactive dashboard")}
  ${chalk.green("$")} threatcrush scan ./src       ${chalk.dim("# Scan code for vulns")}
  ${chalk.green("$")} threatcrush pentest URL      ${chalk.dim("# Pen test a URL")}
  ${chalk.green("$")} threatcrush modules install  ${chalk.dim("# Install a module")}
  ${chalk.green("$")} threatcrush update           ${chalk.dim("# Update to latest")}
  ${chalk.green("$")} threatcrush remove           ${chalk.dim("# Uninstall completely")}`)
  .version(PKG_VERSION, "-v, --version", "Show version number")
  .helpOption("-h, --help", "Show this help")
  .addHelpText("after", `
${chalk.dim("─────────────────────────────────────────────────────")}
${chalk.dim("Modules:")}
  ThreatCrush uses pluggable security modules. Core modules included:
  ${chalk.green("network-monitor")}  All TCP/UDP traffic, port scans, SYN floods
  ${chalk.green("log-watcher")}      nginx, Apache, syslog, journald
  ${chalk.green("ssh-guard")}        Failed logins, brute force, tunneling
  ${chalk.green("code-scanner")}     Vulnerabilities, secrets, dependency CVEs
  ${chalk.green("pentest-engine")}   SQLi, XSS, SSRF, API fuzzing
  ${chalk.green("dns-monitor")}      DNS tunneling, DGA detection
  ${chalk.green("firewall-rules")}   Auto-blocks via iptables/nftables
  ${chalk.green("alert-system")}     Slack, Discord, email, webhook, PagerDuty

  Browse community modules: ${chalk.green("threatcrush store")}
`);

// ─── Real commands ───

program
  .command("monitor")
  .description("Real-time security monitoring (all ports, all protocols)")
  .option("-m, --module <modules>", "Comma-separated module filter (e.g. ssh-guard,log-watcher)")
  .option("--tui", "Launch the interactive TUI dashboard")
  .action(async (opts) => {
    await monitorCommand({
      module: opts.module,
      tui: opts.tui,
    });
  });

program
  .command("tui")
  .description("Interactive security dashboard (htop for security)")
  .alias("dashboard")
  .action(async () => {
    await monitorCommand({ tui: true });
  });

program
  .command("init")
  .description("Sign in, auto-detect services, and configure ThreatCrush")
  .action(async () => {
    await initCommand();
  });

program
  .command("login")
  .description("Log in to your threatcrush.com account")
  .option("-e, --email <email>", "Email to log in with")
  .action(async (opts) => {
    await loginCommand({ email: opts.email });
  });

program
  .command("logout")
  .description("Clear stored threatcrush.com credentials")
  .action(async () => {
    await logoutCommand();
  });

program
  .command("whoami")
  .description("Show the currently logged-in threatcrush.com account")
  .action(async () => {
    await whoamiCommand();
  });

program
  .command("scan")
  .description("Scan codebase for vulnerabilities and secrets")
  .argument("[path]", "Path to scan", ".")
  .action(async (targetPath: string) => {
    await scanCommand(targetPath);
  });

program
  .command("pentest")
  .description("Penetration test URLs and APIs")
  .argument("<url>", "Target URL to pentest")
  .action(async (url: string) => {
    await pentestCommand(url);
  });

program
  .command("status")
  .description("Show daemon status and loaded modules")
  .action(async () => {
    await statusCommand();
  });

program
  .command("start")
  .description("Start the ThreatCrush daemon in the background")
  .action(async () => {
    console.log(LOGO);
    await daemonStart();
  });

program
  .command("stop")
  .description("Stop the ThreatCrush daemon")
  .action(async () => {
    console.log(LOGO);
    await daemonStop();
  });

program
  .command("daemon")
  .description("Run threatcrushd in the foreground (systemd / Docker ExecStart)")
  .action(async () => {
    await daemonForeground();
  });

program
  .command("install-service")
  .description("Install the threatcrushd systemd unit (Linux, requires sudo)")
  .action(async () => {
    await installServiceCommand();
  });

program
  .command("uninstall-service")
  .description("Remove the threatcrushd systemd unit (Linux, requires sudo)")
  .action(async () => {
    await uninstallServiceCommand();
  });

program
  .command("logs")
  .description("Tail daemon logs")
  .action(async () => {
    console.log(LOGO);
    const logPath = PATHS.logFile;
    if (!existsSync(logPath)) {
      console.log(chalk.yellow(`  No log file found at ${logPath}`));
      console.log(chalk.dim("  Start the daemon first with `threatcrush start`\n"));
      return;
    }
    console.log(chalk.green(`  Tailing ${logPath}...\n`));
    console.log(chalk.gray("  Press Ctrl+C to stop\n"));
    execSync(`tail -f ${logPath}`, { stdio: "inherit" });
  });

program
  .command("activate")
  .description("Activate your license key")
  .action(async () => {
    console.log(LOGO);
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const key = await new Promise<string>((resolve) => {
      rl.question(chalk.green("  Enter your ThreatCrush license key: "), (answer) => {
        rl.close();
        resolve(answer.trim());
      });
    });

    if (!key) {
      console.log(chalk.red("\n  No key provided.\n"));
      return;
    }

    console.log(chalk.dim("\n  Activating license..."));
    try {
      const res = await fetch(`${API_URL}/api/auth/activate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ license_key: key }),
      });
      const result = await res.json() as Record<string, unknown>;

      if (!res.ok) {
        console.log(chalk.red(`\n  ✗ Activation failed: ${(result as Record<string, string>).error || "Unknown error"}\n`));
        return;
      }

      console.log(chalk.green("\n  ✓ License activated successfully!\n"));
      console.log(chalk.dim(`  Status: ${String(result.status ?? "active")}`));
      console.log(chalk.dim(`  Expires: ${String(result.expires ?? "never")}\n`));
    } catch {
      console.log(chalk.red("\n  ✗ Activation failed. Check your connection and try again.\n"));
    }
  });

// ─── Real commands ───

program
  .command("update")
  .description("Update ThreatCrush CLI and installed bundle")
  .option("--cli", "Update CLI only")
  .option("--modules", "Update modules only")
  .option("--desktop", "Update desktop app too")
  .action(async (opts) => {
    console.log(LOGO);

    if (opts.modules) {
      console.log(LOGO);
      console.log(chalk.yellow("  Updating modules...\n"));
      const pm = detectPackageManager();
      const commands = [
        getGlobalInstallCommand(pm, PKG_NAME, "update"),
      ];
      try {
        for (const cmd of commands) {
          console.log(chalk.green(`  → ${cmd}\n`));
          execSync(cmd, { stdio: "inherit" });
        }
        console.log(chalk.green("\n  ✓ Modules updated successfully!\n"));
      } catch (err) {
        console.log(chalk.red("\n  ✗ Module update failed. Try manually:\n"));
        for (const cmd of commands) {
          console.log(chalk.dim(`    ${cmd}`));
        }
        console.log();
      }
      return;
    }

    const pm = detectPackageManager();
    const installConfig = readInstallConfig();
    const installMode = opts.cli ? "server" : (opts.desktop ? "desktop" : installConfig.installMode || "server");

    console.log(chalk.dim(`  Detected package manager: ${pm}`));
    console.log(chalk.dim(`  Install mode: ${installMode}\n`));

    const commands = [getGlobalInstallCommand(pm, PKG_NAME, "update")];

    if (installMode === "desktop") {
      commands.push(getGlobalInstallCommand(pm, DESKTOP_PKG_NAME, "update"));
    }

    try {
      for (const cmd of commands) {
        console.log(chalk.green(`  → ${cmd}\n`));
        execSync(cmd, { stdio: "inherit" });
      }

      console.log(chalk.green("\n  ✓ ThreatCrush updated successfully!\n"));
      if (installMode === "desktop") {
        console.log(chalk.dim("  Updated bundle: CLI + desktop app\n"));
      } else {
        console.log(chalk.dim("  Updated bundle: CLI only\n"));
      }
    } catch (err) {
      console.log(chalk.red("\n  ✗ Update failed. Try manually:\n"));
      for (const cmd of commands) {
        console.log(chalk.dim(`    ${cmd}`));
      }
      console.log();
    }
  });

program
  .command("remove")
  .description("Uninstall ThreatCrush and the installed bundle")
  .alias("uninstall")
  .action(async () => {
    console.log(LOGO);

    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const confirm = await new Promise<string>((resolve) => {
      rl.question(chalk.yellow("  Are you sure you want to uninstall ThreatCrush? (y/N): "), (answer) => {
        rl.close();
        resolve(answer.trim().toLowerCase());
      });
    });

    if (confirm !== "y" && confirm !== "yes") {
      console.log(chalk.dim("\n  Cancelled.\n"));
      return;
    }

    const pm = detectPackageManager();
    const installConfig = readInstallConfig();
    const installMode = installConfig.installMode || "server";
    const commands = [getGlobalInstallCommand(pm, PKG_NAME, "remove")];

    if (installMode === "desktop" && packageLooksInstalled(pm, DESKTOP_PKG_NAME)) {
      commands.push(getGlobalInstallCommand(pm, DESKTOP_PKG_NAME, "remove"));
    }

    console.log(chalk.dim(`\n  Detected package manager: ${pm}`));
    console.log(chalk.dim(`  Install mode: ${installMode}\n`));

    try {
      for (const cmd of commands) {
        console.log(chalk.green(`  → ${cmd}\n`));
        execSync(cmd, { stdio: "inherit" });
      }
      console.log(chalk.green("\n  ✓ ThreatCrush has been uninstalled.\n"));
      console.log(chalk.dim("  We're sorry to see you go! 👋\n"));
      console.log(chalk.dim("  Config files may remain at /etc/threatcrush/"));
      console.log(chalk.dim("  Logs may remain at /var/log/threatcrush/"));
      console.log(chalk.dim("  State may remain at /var/lib/threatcrush/"));
      console.log(chalk.dim(`  Local install metadata may remain at ${INSTALL_CONFIG_PATH}\n`));
    } catch (err) {
      console.log(chalk.red("\n  ✗ Uninstall failed. Try manually:\n"));
      for (const cmd of commands) {
        console.log(chalk.dim(`    ${cmd}`));
      }
      console.log();
    }
  });

program
  .command("modules")
  .description("Manage security modules")
  .argument("[action]", "list | install | remove | available")
  .argument("[name]", "Module name or path")
  .action(async (action?: string, name?: string) => {
    await modulesCommand({ action, name });
  });

const storeCmd = program
  .command("store")
  .description("Browse the module marketplace")
  .action(async () => {
    console.log(LOGO);
    console.log(chalk.green("  Module Marketplace\n"));
    console.log(chalk.dim("  Loading available modules..."));
    try {
      const res = await fetch(`${API_URL}/api/modules`);
      if (!res.ok) {
        console.log(chalk.red(`  ✗ Failed to load modules: ${res.statusText}\n`));
        return;
      }
      const data = await res.json() as { modules?: Array<{ slug: string; display_name: string; description: string; version: string; stars?: number }> };
      const mods = data.modules || [];
      if (mods.length === 0) {
        console.log(chalk.yellow("  No modules available yet.\n"));
        return;
      }
      console.log();
      for (const mod of mods) {
        console.log(`  ${chalk.green.bold(mod.display_name || mod.slug)} ${chalk.gray(`v${mod.version}`)}${mod.stars ? chalk.gray(` ⭐${mod.stars}`) : ""}`);
        console.log(`    ${chalk.dim(mod.description)}\n`);
      }
    } catch {
      console.log(chalk.dim("  (Marketplace offline — browse at threatcrush.com/store)\n"));
    }
  });

storeCmd
  .command("search <query>")
  .description("Search for modules in the store")
  .action(async (query: string) => {
    console.log(LOGO);
    console.log(chalk.green(`  Searching for "${query}"...\n`));
    try {
      const res = await fetch(`${API_URL}/api/modules?q=${encodeURIComponent(query)}`);
      if (!res.ok) {
        console.log(chalk.red(`  ✗ Search failed: ${res.statusText}\n`));
        return;
      }
      const data = await res.json() as { modules?: Array<{ slug: string; display_name: string; description: string; version: string }> };
      const mods = data.modules || [];
      if (mods.length === 0) {
        console.log(chalk.yellow(`  No modules matching "${query}"\n`));
        return;
      }
      for (const mod of mods) {
        console.log(`  ${chalk.green.bold(mod.display_name || mod.slug)} ${chalk.gray(`v${mod.version}`)}`);
        console.log(`    ${chalk.dim(mod.description)}\n`);
      }
    } catch {
      console.log(chalk.dim(`  (Search offline — browse at threatcrush.com/store)\n`));
    }
  });

storeCmd
  .command("publish <url>")
  .description("Publish a module from a git URL or web URL")
  .action(async (url: string) => {
    console.log(LOGO);

    // 1. Get email
    const configPath = join(homedir(), ".threatcrush", "config.json");
    let email = "";
    try {
      const config = JSON.parse(readFileSync(configPath, "utf-8"));
      email = config.email || "";
    } catch {}

    if (!email) {
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      email = await new Promise<string>((resolve) => {
        rl.question(chalk.green("  Enter your email: "), (answer) => {
          rl.close();
          resolve(answer.trim());
        });
      });

      if (!email || !email.includes("@")) {
        console.log(chalk.red("\n  Invalid email.\n"));
        return;
      }

      // Save email
      try {
        const dir = join(homedir(), ".threatcrush");
        if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
        writeFileSync(configPath, JSON.stringify({ email }, null, 2));
        console.log(chalk.dim(`  Saved email to ${configPath}`));
      } catch {}
    }

    console.log(chalk.dim(`\n  Fetching metadata from ${url}...\n`));

    // 2. Fetch metadata
    let meta: Record<string, unknown>;
    try {
      const res = await fetch(`${API_URL}/api/modules/fetch-meta`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, git_url: url }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        console.log(chalk.red(`  ✗ Failed to fetch metadata: ${(err as Record<string, string>).error}\n`));
        return;
      }
      meta = await res.json() as Record<string, unknown>;
    } catch (err) {
      console.log(chalk.red(`  ✗ Failed to fetch metadata: ${err instanceof Error ? err.message : err}\n`));
      return;
    }

    // 3. Preview
    console.log(chalk.green("  ── Module Preview ──\n"));
    console.log(`  ${chalk.bold("Name:")}         ${meta.name || chalk.dim("(none)")}`);
    console.log(`  ${chalk.bold("Display:")}      ${meta.display_name || chalk.dim("(none)")}`);
    console.log(`  ${chalk.bold("Description:")}  ${meta.description || chalk.dim("(none)")}`);
    console.log(`  ${chalk.bold("Version:")}      ${meta.version || "0.1.0"}`);
    console.log(`  ${chalk.bold("License:")}      ${meta.license || "MIT"}`);
    console.log(`  ${chalk.bold("Author:")}       ${meta.author_name || chalk.dim("(none)")}`);
    console.log(`  ${chalk.bold("Homepage:")}     ${meta.homepage_url || chalk.dim("(none)")}`);
    console.log(`  ${chalk.bold("Git:")}          ${meta.git_url || url}`);
    if (Array.isArray(meta.tags) && meta.tags.length > 0) {
      console.log(`  ${chalk.bold("Tags:")}         ${(meta.tags as string[]).join(", ")}`);
    }
    if (meta.stars) {
      console.log(`  ${chalk.bold("Stars:")}        ⭐ ${meta.stars}`);
    }
    console.log();

    // 4. Confirm
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const confirm = await new Promise<string>((resolve) => {
      rl.question(chalk.yellow("  Publish this module? (y/N): "), (answer) => {
        rl.close();
        resolve(answer.trim().toLowerCase());
      });
    });

    if (confirm !== "y" && confirm !== "yes") {
      console.log(chalk.dim("\n  Cancelled.\n"));
      return;
    }

    // 5. Publish
    console.log(chalk.dim("\n  Publishing..."));
    try {
      const res = await fetch(`${API_URL}/api/modules`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...meta,
          author_email: email,
          git_url: (meta.git_url as string) || url,
          homepage_url: (meta.homepage_url as string) || url,
        }),
      });

      const result = await res.json() as Record<string, unknown>;

      if (!res.ok) {
        console.log(chalk.red(`\n  ✗ Publish failed: ${(result as Record<string, string>).error}\n`));
        return;
      }

      const mod = result.module as Record<string, string>;
      const slug = mod?.slug || meta.name;
      console.log(chalk.green(`\n  ✓ Module published!`));
      console.log(chalk.dim(`  ${API_URL}/store/${slug}\n`));
    } catch (err) {
      console.log(chalk.red(`\n  ✗ Publish failed: ${err instanceof Error ? err.message : err}\n`));
    }
  });

// ─── Organization commands ───

const orgsCmd = program
  .command("orgs")
  .alias("org")
  .description("Manage organizations")
  .action(async () => {
    await orgsCommand({});
  });

orgsCmd
  .command("list")
  .alias("ls")
  .description("List your organizations")
  .action(async () => {
    await orgsCommand({ action: "list" });
  });

orgsCmd
  .command("create <name>")
  .description("Create a new organization")
  .action(async (name: string) => {
    await orgsCommand({ action: "create", name });
  });

orgsCmd
  .command("use <slug>")
  .description("Switch to an organization")
  .action(async (slug: string) => {
    await orgsCommand({ action: "use", name: slug });
  });

// ─── Server commands ───

const serversCmd = program
  .command("servers")
  .alias("server")
  .alias("srv")
  .description("Manage servers")
  .action(async (opts) => {
    await serversCommand({ action: opts });
  });

serversCmd
  .command("list")
  .alias("ls")
  .option("--org <slug>", "Filter by organization slug")
  .description("List servers in current organization")
  .action(async (opts) => {
    await serversCommand({ action: "list", org: opts.org });
  });

// ─── Properties ───

const propsCmd = program
  .command("properties")
  .alias("props")
  .alias("targets")
  .description("Manage scan/pentest targets (properties) in the current org")
  .action(async () => {
    await propertiesListCommand({});
  });

propsCmd
  .command("list")
  .alias("ls")
  .description("List properties in the current org")
  .option("--org <slug>", "Organization slug")
  .option("--kind <kind>", "Filter by kind (url|api|domain|ip|repo)")
  .action(async (opts) => {
    await propertiesListCommand({ org: opts.org, kind: opts.kind });
  });

propsCmd
  .command("add <name> <target>")
  .description("Add a new property (url, api, domain, ip, or repo)")
  .option("--org <slug>", "Organization slug")
  .option("-k, --kind <kind>", "url | api | domain | ip | repo (auto-detected if omitted)")
  .option("-t, --tag <tags>", "Comma-separated tags")
  .option("-d, --description <text>", "Description of the property")
  .option("--disabled", "Create the property disabled")
  .action(async (name: string, target: string, opts) => {
    await propertiesAddCommand(name, target, {
      org: opts.org,
      kind: opts.kind,
      tag: opts.tag,
      description: opts.description,
      disabled: opts.disabled,
    });
  });

propsCmd
  .command("remove <nameOrId>")
  .alias("rm")
  .description("Delete a property")
  .option("--org <slug>", "Organization slug")
  .option("-y, --yes", "Skip confirmation prompt")
  .action(async (nameOrId: string, opts) => {
    await propertiesRemoveCommand(nameOrId, { org: opts.org, yes: opts.yes });
  });

propsCmd
  .command("run")
  .description("Run a scan or pentest against matching properties")
  .option("--org <slug>", "Organization slug")
  .option("-t, --type <type>", "pentest | scan (default: pentest)")
  .option("-k, --kind <kind>", "Limit to a single kind (url|api|domain|ip|repo)")
  .option("-n, --name <name>", "Run only the property with this name")
  .action(async (opts) => {
    await propertiesRunCommand({
      org: opts.org,
      type: opts.type,
      kind: opts.kind,
      name: opts.name,
    });
  });

propsCmd
  .command("runs")
  .alias("history")
  .description("Show recent scan/pentest run history")
  .option("--org <slug>", "Organization slug")
  .option("-p, --property <name>", "Show history for a single property")
  .option("-l, --limit <n>", "Max runs per property", "10")
  .action(async (opts) => {
    await propertiesRunsCommand({
      org: opts.org,
      property: opts.property,
      limit: parseInt(opts.limit, 10) || 10,
    });
  });

propsCmd
  .command("import <file>")
  .description("Bulk-import properties from a .json, .csv, or .tsv file")
  .option("--org <slug>", "Organization slug")
  .option("-n, --dry-run", "Preview without writing")
  .action(async (file: string, opts) => {
    await propertiesImportCommand(file, { org: opts.org, dryRun: opts.dryRun });
  });

// ─── Connect command ───

program
  .command("connect")
  .description("Connect to a ThreatCrush server via SSH")
  .argument("[target]", "Server name, user@hostname, or hostname")
  .option("--org <slug>", "Organization slug")
  .option("-u, --user <user>", "SSH username")
  .option("-p, --port <port>", "SSH port", "22")
  .option("-i, --identity <path>", "SSH identity file")
  .action(async (target, opts) => {
    await connectCommand({
      target,
      org: opts.org,
      user: opts.user,
      port: opts.port,
      identity: opts.identity,
    });
  });

program
  .command("help")
  .description("Show help for threatcrush or a specific command")
  .argument("[command]", "Command to show help for")
  .action((commandName?: string) => {
    if (!commandName) {
      console.log(LOGO);
      program.outputHelp();
      return;
    }
    const sub = program.commands.find(
      (c) => c.name() === commandName || c.aliases().includes(commandName),
    );
    if (!sub) {
      console.log(chalk.yellow(`  Unknown command: ${commandName}\n`));
      program.outputHelp();
      return;
    }
    sub.outputHelp();
  });

// Default action (no command — smart welcome based on current state)
program.action(() => {
  welcomeCommand();
});

program.parse();
