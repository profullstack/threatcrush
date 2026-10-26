import chalk from "chalk";
import { homedir } from "node:os";
import { readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * `threatcrush redeem <code>` and `threatcrush invites [list|create|accept|revoke]`:
 * credit codes and scarce invites on threatcrush.com. Both belong to a person,
 * so they use the `threatcrush login` session, never a tc_agent_ key.
 */

const API_URL = process.env.THREATCRUSH_API_URL || "https://threatcrush.com";
const CONFIG_PATH = join(homedir(), ".threatcrush", "config.json");

function sessionToken(): string | null {
  try {
    const cfg = JSON.parse(readFileSync(CONFIG_PATH, "utf-8")) as { token?: string };
    return cfg.token ?? null;
  } catch {
    return null;
  }
}

type Fetch = typeof fetch;

async function api(path: string, init: RequestInit = {}, f: Fetch = fetch): Promise<{ ok: boolean; status: number; body: Record<string, unknown> }> {
  const token = sessionToken();
  if (!token) {
    console.error(chalk.red("  Not signed in. Run `threatcrush login` first."));
    process.exitCode = 1;
    return { ok: false, status: 401, body: {} };
  }
  const res = await f(`${API_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}`, ...(init.headers ?? {}) },
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (res.status === 401) console.error(chalk.red("  Session expired. Run `threatcrush login` again."));
  return { ok: res.ok, status: res.status, body };
}

function fail(body: Record<string, unknown>, fallback: string) {
  console.error(chalk.red(`  ${String(body.error ?? fallback)}`));
  process.exitCode = 1;
}

export async function redeemCommand(code: string, f: Fetch = fetch): Promise<void> {
  const r = await api("/api/credits/redeem", { method: "POST", body: JSON.stringify({ code }) }, f);
  if (r.status === 401 && !r.body.error) return;
  if (!r.ok) return fail(r.body, "Could not redeem the code.");
  console.log(chalk.green(`  ${String(r.body.message)}`));
  if (typeof r.body.balance_usd === "number") console.log(`  Credit balance: $${r.body.balance_usd.toFixed(2)}`);
}

interface InviteRow {
  id: string;
  createdAt: number;
  note: string;
  status: string;
  usedByEmail?: string | null;
  bonus?: string;
}

export async function invitesCommand(action = "list", arg?: string, f: Fetch = fetch): Promise<void> {
  if (action === "create") {
    const r = await api("/api/credits/invites", { method: "POST", body: JSON.stringify({ note: arg ?? "" }) }, f);
    if (!r.ok) return fail(r.body, "Could not create an invite.");
    console.log(chalk.green("  Invite created. Send this link (it is shown once):"));
    console.log(`  ${chalk.bold(String(r.body.url))}`);
    return;
  }
  if (action === "accept") {
    if (!arg) return fail({}, "Usage: threatcrush invites accept <code>");
    const r = await api("/api/credits/invites/accept", { method: "POST", body: JSON.stringify({ code: arg }) }, f);
    if (!r.ok) return fail(r.body, "Could not accept the invite.");
    console.log(chalk.green(`  ${String(r.body.message)}`));
    return;
  }
  if (action === "revoke") {
    if (!arg) return fail({}, "Usage: threatcrush invites revoke <id>");
    const r = await api(`/api/credits/invites/${encodeURIComponent(arg)}`, { method: "DELETE" }, f);
    if (!r.ok) return fail(r.body, "Could not withdraw the invite.");
    console.log(chalk.green("  Invite withdrawn."));
    return;
  }
  const r = await api("/api/credits/invites", {}, f);
  if (!r.ok) return fail(r.body, "Could not load invites.");
  const q = r.body.quota as { left: number; total: number };
  console.log(`  Invites left: ${chalk.bold(`${q.left} / ${q.total}`)}  (bonus: ${String(r.body.bonusCredits)} credits each)`);
  if (!r.body.canInvite) {
    console.log(chalk.yellow(r.body.unlocksAt ? `  Invites unlock on ${String(r.body.unlocksAt).slice(0, 10)}.` : `  Cannot invite: ${String(r.body.blockedReason)}`));
  }
  for (const i of (r.body.invites as InviteRow[]) ?? []) {
    const who = i.usedByEmail ? ` ${i.usedByEmail}` : "";
    const bonus = i.status === "used" ? ` (credits ${i.bonus})` : "";
    console.log(`  ${chalk.dim(i.id)}  ${new Date(i.createdAt).toISOString().slice(0, 10)}  ${i.status}${who}${bonus}  ${i.note}`);
  }
}
