import chalk from 'chalk';
import { cloudFetch, hasSession, readCliConfig } from '../core/cli-config.js';

// `threatcrush findings` — the same tracked findings the web app and desktop
// app show: everything `scan`, `pentest` and `ai-scan` uploaded to the current
// org, deduped across runs, with a triage status.

export const TRIAGE = {
  ack: 'acknowledged',
  fix: 'fixed',
  fp: 'false_positive',
  ignore: 'ignored',
  reopen: 'open',
} as const;
export type TriageVerb = keyof typeof TRIAGE;

export interface CloudFinding {
  id: string;
  source: string;
  type: string;
  severity: string;
  message: string;
  location: string | null;
  status: string;
  note: string | null;
  first_seen_at: string;
  last_seen_at: string;
  times_seen: number;
  properties?: { name: string; kind: string; target: string } | null;
  details?: Record<string, unknown>;
}

const SEV_COLOR: Record<string, (s: string) => string> = {
  critical: chalk.bgRed.white, high: chalk.red, medium: chalk.yellow, low: chalk.blue, info: chalk.gray,
};
const STATUS_LABEL: Record<string, string> = {
  open: 'open', acknowledged: 'ack', fixed: 'fixed', false_positive: 'false+', ignored: 'ignored',
};

function orgOrExplain(): string | null {
  if (!hasSession()) {
    console.log(chalk.red(`  Not signed in. Run ${chalk.white('threatcrush login')} first.\n`));
    process.exitCode = 1;
    return null;
  }
  const org = readCliConfig().current_org_id;
  if (!org) {
    console.log(chalk.red(`  No current org. Run ${chalk.white('threatcrush orgs use <slug>')}.\n`));
    process.exitCode = 1;
    return null;
  }
  return org;
}

async function api<T>(path: string, init?: { method?: string; body?: string }): Promise<T | null> {
  const res = await cloudFetch(path, init);
  const data = await res.json().catch(() => ({})) as T & { error?: string };
  if (!res.ok) {
    console.log(chalk.red(`  ${data.error || `HTTP ${res.status}`}${res.status === 401 ? ` — run ${chalk.white('threatcrush login')}` : ''}\n`));
    process.exitCode = 1;
    return null;
  }
  return data;
}

const short = (id: string) => id.slice(0, 8);
const day = (iso: string) => iso.slice(0, 10);

export async function findingsListCommand(opts: { status?: string; severity?: string; source?: string; json?: boolean; limit?: string }): Promise<void> {
  const org = orgOrExplain();
  if (!org) return;
  const qs = new URLSearchParams();
  if (opts.status) qs.set('status', opts.status);
  if (opts.severity) qs.set('severity', opts.severity);
  if (opts.source) qs.set('source', opts.source);
  qs.set('limit', String(Math.min(500, Number(opts.limit) || 100)));
  const data = await api<{ findings: CloudFinding[]; total: number; counts: Record<string, number> }>(`/api/orgs/${org}/scan-findings?${qs}`);
  if (!data) return;
  if (opts.json) {
    console.log(JSON.stringify(data, null, 2));
    return;
  }
  const slug = readCliConfig().current_org_slug || org;
  const c = data.counts;
  console.log(chalk.bold(`\n  Findings in ${slug}`) + chalk.dim(`  open ${c.open ?? 0} · ack ${c.acknowledged ?? 0} · fixed ${c.fixed ?? 0} · false+ ${c.false_positive ?? 0} · ignored ${c.ignored ?? 0}\n`));
  if (!data.findings.length) {
    console.log(chalk.green('  Nothing matches. ') + chalk.dim(opts.status ? '' : 'Showing open + acknowledged; use --status all for everything.') + '\n');
    return;
  }
  for (const f of data.findings) {
    const sev = (SEV_COLOR[f.severity] ?? chalk.white)(f.severity.toUpperCase().padEnd(8));
    console.log(`  ${chalk.gray(short(f.id))} ${sev} ${chalk.dim((STATUS_LABEL[f.status] ?? f.status).padEnd(7))} ${f.message}`);
    console.log(chalk.dim(`           ${f.source} · ${f.properties?.name ?? '?'}${f.location ? ` · ${f.location}` : ''} · seen ${f.times_seen}x, last ${day(f.last_seen_at)}`));
  }
  if (data.total > data.findings.length) console.log(chalk.dim(`\n  ${data.findings.length} of ${data.total} shown; --limit for more.`));
  console.log(chalk.dim(`\n  Triage: threatcrush findings ack|fix|fp|ignore|reopen <id...> [--note "why"]  ·  details: threatcrush findings show <id>\n`));
}

/** Expands 8-char prefixes (as `list` prints them) to full ids. */
async function resolveIds(org: string, prefixes: string[]): Promise<string[] | null> {
  const full = prefixes.filter((p) => /^[0-9a-f-]{36}$/i.test(p));
  const partial = prefixes.filter((p) => !full.includes(p));
  if (!partial.length) return full;
  const data = await api<{ findings: CloudFinding[] }>(`/api/orgs/${org}/scan-findings?status=all&limit=500`);
  if (!data) return null;
  for (const p of partial) {
    const hits = data.findings.filter((f) => f.id.startsWith(p.toLowerCase()));
    if (hits.length !== 1) {
      console.log(chalk.red(`  ${p}: ${hits.length ? 'matches more than one finding, use more characters' : 'no such finding'}\n`));
      process.exitCode = 1;
      return null;
    }
    full.push(hits[0].id);
  }
  return full;
}

export async function findingsShowCommand(id: string, opts: { json?: boolean }): Promise<void> {
  const org = orgOrExplain();
  if (!org) return;
  const [full] = (await resolveIds(org, [id])) ?? [];
  if (!full) return;
  const data = await api<{ finding: CloudFinding }>(`/api/orgs/${org}/scan-findings/${full}`);
  if (!data) return;
  if (opts.json) {
    console.log(JSON.stringify(data.finding, null, 2));
    return;
  }
  const f = data.finding;
  const d = f.details ?? {};
  console.log(`\n  ${(SEV_COLOR[f.severity] ?? chalk.white)(f.severity.toUpperCase())} ${chalk.bold(f.message)}`);
  console.log(chalk.dim(`  ${f.id} · ${f.status} · ${f.source} · ${f.type}`));
  console.log(`  ${chalk.gray('Property:')} ${f.properties?.name ?? '?'} ${chalk.dim(f.properties?.target ?? '')}`);
  if (f.location) console.log(`  ${chalk.gray('Where:')}    ${f.location}`);
  if (typeof d.snippet === 'string') console.log(`  ${chalk.gray('Code:')}     ${d.snippet}`);
  if (typeof d.remediation === 'string') console.log(`  ${chalk.gray('Fix:')}      ${d.remediation}`);
  console.log(`  ${chalk.gray('Seen:')}     ${f.times_seen}x, first ${day(f.first_seen_at)}, last ${day(f.last_seen_at)}`);
  if (f.note) console.log(`  ${chalk.gray('Note:')}     ${f.note}`);
  console.log();
}

export async function findingsTriageCommand(verb: TriageVerb, ids: string[], opts: { note?: string }): Promise<void> {
  const org = orgOrExplain();
  if (!org) return;
  if (!ids.length) {
    console.log(chalk.red(`  Give at least one finding id (see threatcrush findings).\n`));
    process.exitCode = 1;
    return;
  }
  const full = await resolveIds(org, ids);
  if (!full) return;
  const body: Record<string, unknown> = { ids: full, status: TRIAGE[verb] };
  if (opts.note !== undefined) body.note = opts.note;
  const data = await api<{ updated: Array<{ id: string; status: string }> }>(`/api/orgs/${org}/scan-findings`, { method: 'PATCH', body: JSON.stringify(body) });
  if (!data) return;
  console.log(chalk.green(`  ✓ ${data.updated.length} finding(s) → ${TRIAGE[verb].replace('_', ' ')}\n`));
}
