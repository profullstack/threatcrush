import chalk from 'chalk';
import { readFile } from 'node:fs/promises';
import { cloudFetch, readCliConfig } from '../core/cli-config.js';

/**
 * `threatcrush fleet import <file|url>` and `threatcrush fleet cost`: the org's
 * OpenDevice inventory (https://logicsrc.com/docs/opendevice) on threatcrush.com.
 * The inventory lists every machine, daemon or not, and what each costs; the
 * dashboard's Fleet panel and `fleet cost` merge it with the linked daemons.
 * Both use the `threatcrush login` session (inventories belong to people).
 */

type Json = Record<string, unknown>;

interface OrgRow { id: string; slug: string; name: string; user_role?: string }

async function call(path: string, init: { method?: string; body?: string } = {}): Promise<{ ok: boolean; status: number; body: Json }> {
  const res = await cloudFetch(path, init);
  const body = (await res.json().catch(() => ({}))) as Json;
  return { ok: res.ok, status: res.status, body };
}

function fail(message: string): void {
  console.error(chalk.red(`  ${message}`));
  process.exitCode = 1;
}

/** --org (slug or id), else the `orgs use` org, else the only org you administer. */
export async function resolveOrg(wanted?: string): Promise<OrgRow | null> {
  const r = await call('/api/orgs');
  if (r.status === 401) { fail('Not signed in. Run `threatcrush login` first.'); return null; }
  if (!r.ok) { fail(String(r.body.error ?? `Could not list organizations (${r.status})`)); return null; }
  const orgs = (r.body.organizations ?? []) as OrgRow[];
  const pick = wanted ?? readCliConfig().current_org_id;
  if (pick) {
    const org = orgs.find((o) => o.id === pick || o.slug === pick);
    if (!org) fail(`No organization "${pick}". See: threatcrush orgs list`);
    return org ?? null;
  }
  const admin = orgs.filter((o) => o.user_role === 'owner' || o.user_role === 'admin');
  if (admin.length === 1) return admin[0];
  fail(admin.length === 0
    ? 'You administer no organization. Create one: threatcrush orgs create <name>'
    : `Pick an organization: --org <slug> (${admin.map((o) => o.slug).join(', ')})`);
  return null;
}

/** Read the inventory from a file or an http(s) URL. */
export async function readInventorySource(source: string, f: typeof fetch = fetch): Promise<string> {
  if (/^https?:\/\//i.test(source)) {
    const res = await f(source, { signal: AbortSignal.timeout(30_000) });
    if (!res.ok) throw new Error(`${source} answered ${res.status}`);
    return res.text();
  }
  return readFile(source, 'utf-8');
}

export async function fleetImportCommand(source: string, opts: { org?: string } = {}): Promise<void> {
  let text: string;
  try {
    text = await readInventorySource(source);
    JSON.parse(text);
  } catch (err) {
    return fail(`Could not read ${source}: ${err instanceof Error ? err.message : String(err)}`);
  }

  const org = await resolveOrg(opts.org);
  if (!org) return;

  const r = await call(`/api/orgs/${encodeURIComponent(org.id)}/inventory`, { method: 'PUT', body: text });
  const warnings = (r.body.warnings ?? []) as string[];
  if (!r.ok) {
    fail(String(r.body.error ?? `Import failed (${r.status})`));
    for (const e of (r.body.errors ?? []) as string[]) console.error(chalk.red(`    - ${e}`));
    for (const w of warnings) console.error(chalk.yellow(`    ! ${w}`));
    return;
  }

  const cost = r.body.cost as { devices: number; monthly: Record<string, number>; counted: number; unstated: string[] };
  console.log(chalk.green(`  Imported ${cost.devices} device${cost.devices === 1 ? '' : 's'} into ${org.name} (/${org.slug}).`));
  console.log(`  Monthly: ${chalk.bold(formatTotal(cost.monthly))}  (${cost.counted} counted, ${cost.unstated.length} unstated)`);
  if (cost.unstated.length > 0) console.log(chalk.dim(`  Unstated: ${cost.unstated.join(', ')}`));
  for (const w of warnings) console.log(chalk.yellow(`  ! ${w}`));
  console.log(chalk.dim('  See it: threatcrush fleet cost, or threatcrush.com/dashboard'));
}

interface FleetRow {
  name: string;
  org_slug: string;
  connection: string;
  agent: boolean;
  device: { provider: string | null; profile: string; status: string; monthly: { amount: number | null }; monthly_label: string } | null;
}

export async function fleetCostCommand(opts: { json?: boolean } = {}): Promise<void> {
  const r = await call('/api/fleet');
  if (r.status === 401) return fail('Not signed in. Run `threatcrush login` first.');
  if (!r.ok) return fail(String(r.body.error ?? `Could not load the fleet (${r.status})`));
  if (opts.json) {
    console.log(JSON.stringify(r.body, null, 2));
    return;
  }

  const servers = (r.body.servers ?? []) as FleetRow[];
  const s = r.body.summary as {
    inventories: number; monthly_total_label: string; cost_counted: number; cost_unstated: number;
    installs: number; no_agent: number;
  };
  if (s.inventories === 0) {
    console.log(chalk.yellow('  No OpenDevice inventory yet. Import one: threatcrush fleet import <file|url>'));
  }

  const width = Math.max(6, ...servers.map((x) => x.name.length));
  console.log(chalk.dim(`  ${'SERVER'.padEnd(width)}  ${'STATUS'.padEnd(8)}  ${'PROVIDER'.padEnd(14)}  $/MO`));
  for (const x of servers) {
    const status = x.connection === 'online' ? chalk.green('online  ') : x.connection === 'no-agent' ? chalk.dim('no agent') : chalk.red('offline ');
    const cost = !x.device ? chalk.dim('—') : x.device.monthly.amount == null ? chalk.dim(x.device.monthly_label) : x.device.monthly_label;
    console.log(`  ${x.name.padEnd(width)}  ${status}  ${(x.device?.provider ?? '—').slice(0, 14).padEnd(14)}  ${cost}`);
  }
  console.log();
  console.log(`  Total: ${chalk.bold(s.monthly_total_label)}/mo  (${s.cost_counted} counted, ${s.cost_unstated} unstated)`);
  console.log(chalk.dim(`  ${s.installs} with a daemon, ${s.no_agent} without${s.no_agent > 0 ? ' (install: threatcrush login && threatcrush servers link)' : ''}`));
}

function formatTotal(monthly: Record<string, number>): string {
  const parts = Object.entries(monthly ?? {}).map(([cur, n]) =>
    new Intl.NumberFormat('en-US', { style: 'currency', currency: cur }).format(n));
  return parts.length ? parts.join(' + ') : '—';
}
