#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import readline from "readline";

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
    console.log(chalk.green(`\n  🎁 Refer a friend → both get lifetime access for $249 (instead of $499)\n`));
  } else {
    console.log(chalk.green(`\n  ✓ Thanks! We'll notify you when ThreatCrush launches.\n`));
  }

  return true;
}

const program = new Command();

program
  .name("threatcrush")
  .description("All-in-one security agent — monitor, detect, scan, protect")
  .version("0.1.0");

// Every command goes through email gate for now
const gatedCommand = (name: string, desc: string) => {
  program.command(name).description(desc).action(async () => {
    await emailGate();
  });
};

gatedCommand("monitor", "Real-time security monitoring (all ports, all protocols)");
gatedCommand("tui", "Interactive security dashboard (htop for security)");
gatedCommand("init", "Auto-detect services and configure ThreatCrush");
gatedCommand("scan", "Scan codebase for vulnerabilities and secrets");
gatedCommand("pentest", "Penetration test URLs and APIs");
gatedCommand("status", "Show daemon status and loaded modules");
gatedCommand("start", "Start the ThreatCrush daemon");
gatedCommand("stop", "Stop the ThreatCrush daemon");
gatedCommand("logs", "Tail daemon logs");
gatedCommand("update", "Update CLI and all installed modules");
gatedCommand("activate", "Activate your license key");

program
  .command("modules")
  .description("Manage security modules")
  .argument("[action]", "list | install | remove | available")
  .argument("[name]", "module name")
  .action(async () => {
    await emailGate();
  });

program
  .command("store")
  .description("Browse the module marketplace")
  .argument("[action]", "search | info | publish")
  .argument("[query]", "search query or module name")
  .action(async () => {
    await emailGate();
  });

// Default action (no command)
program.action(async () => {
  await emailGate();
});

program.parse();
