import chalk from "chalk";
import { homedir } from "node:os";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * `threatcrush reputation <ip>` and `threatcrush reputation subscribe`:
 * the community reputation lookup at threatcrush.com/api/v1/reputation.
 * Auth is THREATCRUSH_API_KEY (a tc_agent_ key) or the `threatcrush login`
 * session with its current org (`threatcrush orgs use`).
 */

const API_URL = process.env.THREATCRUSH_API_URL || "https://threatcrush.com";
const CONFIG_PATH = join(homedir(), ".threatcrush", "config.json");

interface CliConfig {
  token?: string;
  current_org_id?: string;
}

function readConfig(): CliConfig {
  try {
    return JSON.parse(readFileSync(CONFIG_PATH, "utf-8"));
  } catch {
    return {};
  }
}

export function authFor(env: NodeJS.ProcessEnv = process.env, config: CliConfig = readConfig()): {
  headers: Record<string, string>;
  orgId: string | null;
} | null {
  const key = env.THREATCRUSH_API_KEY?.trim();
  if (key) return { headers: { Authorization: `Bearer ${key}` }, orgId: null };
  if (config.token) return { headers: { Authorization: `Bearer ${config.token}` }, orgId: config.current_org_id ?? null };
  return null;
}

interface Report {
  ip: string;
  tier: string;
  listed: boolean;
  score: number;
  severity: string;
  reports: number;
  reporters: number;
  last_seen: string | null;
  rule_ids: string[];
  country: string | null;
  public_record: string;
  pro?: {
    reasons: string[];
    city: string | null;
    network: string;
    neighbours: { count: number; addresses: Array<{ ip: string; reports: number }> };
    history: Array<{ day: string; reports: number; rules: string[] }>;
  };
  upgrade?: { url: string };
}

export function formatReport(r: Report): string[] {
  const lines: string[] = [];
  const head = r.listed ? chalk.red(`LISTED  score ${r.score}/100`) : chalk.green("not listed");
  lines.push(`  ${chalk.bold(r.ip)}  ${head}  ${chalk.dim(`(${r.tier})`)}`);
  if (r.reports) {
    lines.push(
      `  ${r.severity} · ${r.reports} reports from ${r.reporters} reporter${r.reporters === 1 ? "" : "s"} · last seen ${String(r.last_seen ?? "").slice(0, 10)}${r.country ? ` · ${r.country}` : ""}`,
    );
    if (r.rule_ids.length) lines.push(`  rules: ${r.rule_ids.join(", ")}`);
  }
  if (r.pro) {
    for (const reason of r.pro.reasons) lines.push(`  · ${reason}`);
    lines.push(`  ${r.pro.network}: ${r.pro.neighbours.count} other listed`);
    for (const d of r.pro.history.slice(0, 14)) lines.push(`  ${d.day}  ${String(d.reports).padStart(5)}  ${d.rules.join(", ")}`);
  } else if (r.upgrade) {
    lines.push(chalk.dim(`  history, /24 neighbours and score reasons: ${r.upgrade.url}`));
  }
  lines.push(chalk.dim(`  public record: ${r.public_record}`));
  return lines;
}

export async function reputationLookupCommand(ip: string, opts: { json?: boolean; org?: string }): Promise<void> {
  const auth = authFor();
  if (!auth) {
    console.log(chalk.red("  Set THREATCRUSH_API_KEY or run `threatcrush login` first. Keyless: https://nichedb.dev/reputation\n"));
    process.exitCode = 2;
    return;
  }
  const org = opts.org ?? auth.orgId;
  const url = `${API_URL}/api/v1/reputation/${encodeURIComponent(ip)}${org ? `?org=${encodeURIComponent(org)}` : ""}`;
  const res = await fetch(url, { headers: auth.headers });
  const body = (await res.json().catch(() => ({}))) as Report & { error?: string };
  if (!res.ok) {
    console.log(chalk.red(`  ${body.error ?? `HTTP ${res.status}`}\n`));
    process.exitCode = 2;
    return;
  }
  if (opts.json) console.log(JSON.stringify(body, null, 2));
  else console.log(`\n${formatReport(body).join("\n")}\n`);
  if (body.listed) process.exitCode = 1;
}

export async function reputationSubscribeCommand(opts: { plan?: string; currency?: string; org?: string; json?: boolean }): Promise<void> {
  const auth = authFor();
  if (!auth) {
    console.log(chalk.red("  Set THREATCRUSH_API_KEY (an admin key) or run `threatcrush login` first.\n"));
    process.exitCode = 2;
    return;
  }
  const res = await fetch(`${API_URL}/api/v1/reputation/subscribe`, {
    method: "POST",
    headers: { ...auth.headers, "Content-Type": "application/json" },
    body: JSON.stringify({
      plan: opts.plan ?? "pro-monthly",
      currency: opts.currency ?? "usdc_pol",
      org_id: opts.org ?? auth.orgId ?? undefined,
    }),
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) {
    console.log(chalk.red(`  ${String(body.error ?? `HTTP ${res.status}`)}\n`));
    process.exitCode = 2;
    return;
  }
  if (opts.json) {
    console.log(JSON.stringify(body, null, 2));
    return;
  }
  console.log(`\n  ${chalk.bold("Reputation Pro")} ${body.plan}: $${body.amount_usd} in ${body.currency}`);
  if (body.address) console.log(`  send ${body.amount_crypto ?? ""} to ${chalk.green(String(body.address))}`);
  if (body.checkout_url) console.log(`  or pay at ${body.checkout_url}`);
  console.log(chalk.dim(`  payment ${body.payment_id}; Pro turns on when CoinPay confirms it.\n`));
}
