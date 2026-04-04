#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import readline from "readline";
import { execSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

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

// ─── Helpers ───

async function promptEmail(): Promise<string | null> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(chalk.green("\n  Enter your email to continue: "), (answer) => {
      rl.close();
      resolve(answer.trim() || null);
    });
  });
}

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

async function emailGate(): Promise<boolean> {
  console.log(LOGO);
  console.log(chalk.yellow("  ⚡ Coming soon — ThreatCrush is in private beta.\n"));

  const email = await promptEmail();
  if (!email || !email.includes("@")) {
    console.log(chalk.red("\n  Invalid email. Try again.\n"));
    return false;
  }

  const result = await joinWaitlist(email);
  if (result?.referral_code) {
    console.log(chalk.green(`\n  ✓ You're on the list!`));
    console.log(chalk.dim(`  Referral code: ${chalk.white(result.referral_code)}`));
    console.log(chalk.dim(`  Share: ${API_URL}?ref=${result.referral_code}`));
    console.log(chalk.green(`\n  🎁 Refer a friend → they save $100, you earn $100 in crypto via CoinPayPortal\n`));
  } else {
    console.log(chalk.green(`\n  ✓ Thanks! We'll notify you when ThreatCrush launches.\n`));
  }

  return true;
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

// ─── Gated commands (coming soon) ───

const gatedCommand = (name: string, desc: string, aliases?: string[]) => {
  const cmd = program.command(name).description(desc).action(async () => {
    await emailGate();
  });
  if (aliases) {
    for (const alias of aliases) {
      cmd.alias(alias);
    }
  }
};

gatedCommand("monitor", "Real-time security monitoring (all ports, all protocols)");
gatedCommand("tui", "Interactive security dashboard (htop for security)", ["dashboard"]);
gatedCommand("init", "Auto-detect services and configure ThreatCrush");
gatedCommand("scan", "Scan codebase for vulnerabilities and secrets");
gatedCommand("pentest", "Penetration test URLs and APIs");
gatedCommand("status", "Show daemon status and loaded modules");
gatedCommand("start", "Start the ThreatCrush daemon");
gatedCommand("stop", "Stop the ThreatCrush daemon");
gatedCommand("logs", "Tail daemon logs");
gatedCommand("activate", "Activate your license key");

// ─── Real commands ───

program
  .command("update")
  .description("Update ThreatCrush CLI and all installed modules")
  .option("--cli", "Update CLI only")
  .option("--modules", "Update modules only")
  .action(async (opts) => {
    console.log(LOGO);

    if (opts.modules) {
      console.log(chalk.yellow("  Module updates coming soon.\n"));
      return;
    }

    const pm = detectPackageManager();
    console.log(chalk.dim(`  Detected package manager: ${pm}\n`));

    const commands: Record<string, string> = {
      npm: `npm update -g ${PKG_NAME}`,
      pnpm: `pnpm update -g ${PKG_NAME}`,
      yarn: `yarn global upgrade ${PKG_NAME}`,
      bun: `bun update -g ${PKG_NAME}`,
    };

    const cmd = commands[pm] || commands.npm;
    console.log(chalk.green(`  → ${cmd}\n`));

    try {
      execSync(cmd, { stdio: "inherit" });
      console.log(chalk.green("\n  ✓ ThreatCrush updated successfully!\n"));

      // Show new version
      try {
        const newVersion = execSync(`${pm === "npm" ? "npm" : pm} list -g ${PKG_NAME} --depth=0`, {
          encoding: "utf-8",
          stdio: ["pipe", "pipe", "pipe"],
        });
        const match = newVersion.match(/@[\d.]+/);
        if (match) {
          console.log(chalk.dim(`  Version: ${match[0]}\n`));
        }
      } catch {}
    } catch (err) {
      console.log(chalk.red("\n  ✗ Update failed. Try manually:\n"));
      console.log(chalk.dim(`    ${cmd}\n`));
    }
  });

program
  .command("remove")
  .description("Uninstall ThreatCrush CLI completely")
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
    console.log(chalk.dim(`\n  Detected package manager: ${pm}\n`));

    const commands: Record<string, string> = {
      npm: `npm uninstall -g ${PKG_NAME}`,
      pnpm: `pnpm remove -g ${PKG_NAME}`,
      yarn: `yarn global remove ${PKG_NAME}`,
      bun: `bun remove -g ${PKG_NAME}`,
    };

    const cmd = commands[pm] || commands.npm;
    console.log(chalk.green(`  → ${cmd}\n`));

    try {
      execSync(cmd, { stdio: "inherit" });
      console.log(chalk.green("\n  ✓ ThreatCrush has been uninstalled.\n"));
      console.log(chalk.dim("  We're sorry to see you go! 👋\n"));
      console.log(chalk.dim("  Config files may remain at /etc/threatcrush/"));
      console.log(chalk.dim("  Logs may remain at /var/log/threatcrush/"));
      console.log(chalk.dim("  State may remain at /var/lib/threatcrush/\n"));
    } catch (err) {
      console.log(chalk.red("\n  ✗ Uninstall failed. Try manually:\n"));
      console.log(chalk.dim(`    ${cmd}\n`));
    }
  });

program
  .command("modules")
  .description("Manage security modules")
  .argument("[action]", "list | install | remove | available | update")
  .argument("[name]", "module name")
  .action(async () => {
    await emailGate();
  });

const storeCmd = program
  .command("store")
  .description("Browse the module marketplace")
  .action(async () => {
    await emailGate();
  });

storeCmd
  .command("search <query>")
  .description("Search for modules in the store")
  .action(async () => {
    await emailGate();
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

// Default action (no command — show help)
program.action(() => {
  console.log(LOGO);
  program.help();
});

program.parse();
