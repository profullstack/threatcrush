import { readFileSync } from 'node:fs';
import { extname } from 'node:path';
import readline from 'node:readline';
import chalk from 'chalk';
import ora from 'ora';
import { banner } from '../core/logger.js';
import { authHeaders, isLoggedIn, readCliConfig } from '../core/cli-config.js';
import { runScan } from './scan.js';
import { runPentest } from './pentest.js';
import { workerId, type RunResult } from '../core/run-result.js';

const API_URL = process.env.THREATCRUSH_API_URL || 'https://threatcrush.com';

const KINDS = ['url', 'api', 'domain', 'ip', 'repo'] as const;
type Kind = typeof KINDS[number];

interface Property {
  id: string;
  name: string;
  kind: Kind;
  target: string;
  description: string | null;
  tags: string[];
  enabled: boolean;
  last_run_at: string | null;
  last_run_status: string | null;
  created_at: string;
}

interface Org {
  id: string;
  slug: string;
  name: string;
}

function prompt(question: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(question, (answer) => {
    rl.close();
    resolve(answer.trim());
  }));
}

async function requireAuth(): Promise<boolean> {
  if (isLoggedIn()) return true;
  console.log(chalk.red('  You must be logged in.'));
  console.log(chalk.dim(`  Run ${chalk.white('threatcrush login')}\n`));
  return false;
}

async function resolveOrgId(orgFlag?: string): Promise<{ org: Org } | null> {
  const cfg = readCliConfig();

  if (!orgFlag && cfg.current_org_id && cfg.current_org_slug) {
    return { org: { id: cfg.current_org_id, slug: cfg.current_org_slug, name: cfg.current_org_slug } };
  }

  let orgs: Org[] = [];
  try {
    const res = await fetch(`${API_URL}/api/orgs`, { headers: authHeaders() });
    if (!res.ok) {
      console.log(chalk.red(`  Failed to list organizations (${res.status})\n`));
      return null;
    }
    const data = await res.json() as { organizations?: Org[] };
    orgs = data.organizations || [];
  } catch (err) {
    console.log(chalk.red(`  ${(err as Error).message}\n`));
    return null;
  }

  if (orgs.length === 0) {
    console.log(chalk.yellow('  You are not a member of any organization yet.'));
    console.log(chalk.dim(`  Create one: ${chalk.white('threatcrush orgs create <name>')}\n`));
    return null;
  }

  const slug = orgFlag || cfg.current_org_slug;
  const org = slug ? orgs.find((o) => o.slug === slug) : orgs[0];
  if (!org) {
    console.log(chalk.red(`  Organization not found: ${slug}\n`));
    return null;
  }
  return { org };
}

async function fetchProperties(orgId: string, kind?: Kind): Promise<Property[] | null> {
  const qs = kind ? `?kind=${kind}` : '';
  const res = await fetch(`${API_URL}/api/orgs/${orgId}/properties${qs}`, { headers: authHeaders() });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    console.log(chalk.red(`  ${body.error || 'Failed to load properties'}\n`));
    return null;
  }
  const data = await res.json() as { properties?: Property[] };
  return data.properties || [];
}

const KIND_COLOR: Record<Kind, (s: string) => string> = {
  url: chalk.blue,
  api: chalk.magenta,
  domain: chalk.cyan,
  ip: chalk.yellow,
  repo: chalk.hex('#f78cc6'),
};

function printList(props: Property[], org: Org): void {
  console.log(chalk.green.bold(`  Properties in ${chalk.white(org.slug)}`));
  console.log(chalk.gray('  ' + '─'.repeat(76)));
  if (props.length === 0) {
    console.log(chalk.gray('  No properties yet.'));
    console.log();
    console.log(chalk.dim(`  Add one with: ${chalk.white('threatcrush properties add <name> <target> --kind url')}`));
    console.log();
    return;
  }
  console.log(
    chalk.gray('  ') +
      chalk.white.bold('Name'.padEnd(20)) +
      chalk.white.bold('Kind'.padEnd(8)) +
      chalk.white.bold('Status'.padEnd(10)) +
      chalk.white.bold('Target'),
  );
  console.log(chalk.gray('  ' + '─'.repeat(76)));
  for (const p of props) {
    const color = KIND_COLOR[p.kind] || chalk.white;
    const status = p.enabled ? chalk.green('● enabled ') : chalk.gray('○ disabled');
    console.log(
      chalk.gray('  ') +
        chalk.white(p.name.padEnd(20)) +
        color(p.kind.padEnd(8)) +
        status.padEnd(19) +
        chalk.dim(p.target),
    );
    if (p.tags.length > 0) {
      console.log(chalk.gray('  ' + ' '.repeat(28)) + chalk.gray('tags: ' + p.tags.join(', ')));
    }
  }
  console.log();
}

export async function propertiesListCommand(opts: { org?: string; kind?: Kind }): Promise<void> {
  banner();
  if (!(await requireAuth())) return;
  const resolved = await resolveOrgId(opts.org);
  if (!resolved) return;
  const props = await fetchProperties(resolved.org.id, opts.kind);
  if (props === null) return;
  printList(props, resolved.org);
}

export async function propertiesAddCommand(
  name: string,
  target: string,
  opts: { org?: string; kind?: Kind; tag?: string; description?: string; disabled?: boolean },
): Promise<void> {
  banner();
  if (!(await requireAuth())) return;
  const resolved = await resolveOrgId(opts.org);
  if (!resolved) return;

  let kind = opts.kind;
  if (kind && !KINDS.includes(kind)) {
    console.log(chalk.red(`  Invalid kind: ${kind}. Must be one of: ${KINDS.join(', ')}\n`));
    return;
  }
  if (!kind) {
    // infer from target
    if (target.startsWith('http://') || target.startsWith('https://')) kind = 'url';
    else if (target.includes('/') && !target.startsWith('/') && !target.match(/^\d/)) kind = 'repo';
    else if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(target)) kind = 'ip';
    else kind = 'domain';
    console.log(chalk.dim(`  (auto-detected kind: ${kind})`));
  }

  const tags = opts.tag
    ? opts.tag.split(',').map((t) => t.trim()).filter(Boolean)
    : [];

  const body = {
    name,
    kind,
    target,
    description: opts.description,
    tags,
    enabled: !opts.disabled,
  };

  const spinner = ora({ text: `Creating property ${chalk.white(name)}...`, color: 'green' }).start();
  try {
    const res = await fetch(`${API_URL}/api/orgs/${resolved.org.id}/properties`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({ error: res.statusText })) as {
      property?: Property;
      error?: string;
    };
    if (!res.ok || !data.property) {
      spinner.fail(`${data.error || 'Failed to create property'}`);
      return;
    }
    spinner.succeed(`Added ${chalk.white(data.property.name)} (${data.property.kind}) → ${data.property.target}`);
    console.log();
  } catch (err) {
    spinner.fail((err as Error).message);
  }
}

export async function propertiesRemoveCommand(nameOrId: string, opts: { org?: string; yes?: boolean }): Promise<void> {
  banner();
  if (!(await requireAuth())) return;
  const resolved = await resolveOrgId(opts.org);
  if (!resolved) return;

  const props = await fetchProperties(resolved.org.id);
  if (props === null) return;
  const match = props.find((p) => p.id === nameOrId || p.name === nameOrId);
  if (!match) {
    console.log(chalk.red(`  No property named "${nameOrId}" in ${resolved.org.slug}\n`));
    return;
  }

  if (!opts.yes) {
    const answer = (await prompt(chalk.yellow(`  Delete property "${match.name}"? (y/N): `))).toLowerCase();
    if (answer !== 'y' && answer !== 'yes') {
      console.log(chalk.dim('  Cancelled.\n'));
      return;
    }
  }

  const res = await fetch(`${API_URL}/api/orgs/${resolved.org.id}/properties/${match.id}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    console.log(chalk.red(`  ${body.error || 'Failed to delete'}\n`));
    return;
  }
  console.log(chalk.green(`  ✓ Deleted ${chalk.white(match.name)}\n`));
}

type RunType = 'scan' | 'pentest';

async function enqueueRun(orgId: string, propertyId: string, type: RunType, trigger: 'cli' | 'manual' = 'cli'): Promise<string | null> {
  try {
    const res = await fetch(`${API_URL}/api/orgs/${orgId}/properties/${propertyId}/runs`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ type, trigger }),
    });
    const data = await res.json().catch(() => ({})) as { run?: { id: string } };
    return data.run?.id || null;
  } catch {
    return null;
  }
}

async function finalizeRun(
  orgId: string,
  propertyId: string,
  runId: string,
  result: RunResult,
): Promise<void> {
  try {
    await fetch(`${API_URL}/api/orgs/${orgId}/properties/${propertyId}/runs/${runId}`, {
      method: 'PATCH',
      headers: authHeaders(),
      body: JSON.stringify({
        status: result.error ? 'failed' : 'succeeded',
        findings_count: result.findings.length,
        severity_summary: result.severity_summary,
        summary: result.summary,
        findings: result.findings,
        error: result.error,
        source: 'local',
        worker_id: workerId(),
      }),
    });
  } catch {
    // best-effort
  }
}

export async function propertiesRunCommand(
  opts: { org?: string; type?: RunType; kind?: Kind; name?: string },
): Promise<void> {
  banner();
  if (!(await requireAuth())) return;
  const resolved = await resolveOrgId(opts.org);
  if (!resolved) return;

  const type: RunType = opts.type || 'pentest';
  const allProps = await fetchProperties(resolved.org.id);
  if (allProps === null) return;

  let targets = allProps.filter((p) => p.enabled);
  if (opts.kind) targets = targets.filter((p) => p.kind === opts.kind);
  if (opts.name) targets = targets.filter((p) => p.name === opts.name);

  if (!opts.kind && !opts.name) {
    if (type === 'pentest') targets = targets.filter((p) => p.kind === 'url' || p.kind === 'api');
    else if (type === 'scan') targets = targets.filter((p) => p.kind === 'repo');
  }

  if (targets.length === 0) {
    console.log(chalk.yellow('  No enabled properties match the filter.\n'));
    console.log(chalk.dim(`  List them: ${chalk.white('threatcrush properties list')}\n`));
    return;
  }

  console.log(chalk.green.bold(`  Running ${type} against ${targets.length} property(s) in ${resolved.org.slug}`));
  console.log(chalk.gray('  ' + '─'.repeat(76)));
  for (const t of targets) {
    console.log(`  ${KIND_COLOR[t.kind](`[${t.kind}]`)} ${chalk.white(t.name)}  ${chalk.dim(t.target)}`);
  }
  console.log();

  let failures = 0;
  for (const t of targets) {
    console.log(chalk.green(`→ ${type} ${t.name} (${t.target})\n`));
    const runId = await enqueueRun(resolved.org.id, t.id, type);
    let result: RunResult;
    try {
      result = type === 'pentest' ? await runPentest(t.target) : await runScan(t.target);
    } catch (err) {
      result = {
        type,
        target: t.target,
        findings: [],
        severity_summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        summary: `Execution failed: ${(err as Error).message}`,
        error: (err as Error).message,
      };
    }

    const c = result.severity_summary;
    const line = `  ${result.error ? chalk.red('✗ failed') : chalk.green('✓ done')}  ${chalk.white(t.name)}  — ${result.summary}`;
    console.log(line);
    if (!result.error && result.findings.length > 0) {
      console.log(chalk.gray(`    critical:${c.critical} high:${c.high} medium:${c.medium} low:${c.low}`));
    }
    if (result.error) failures++;

    if (runId) await finalizeRun(resolved.org.id, t.id, runId, result);
  }

  console.log();
  console.log(chalk.gray('  ' + '─'.repeat(76)));
  if (failures === 0) {
    console.log(chalk.green(`  ✓ Completed ${targets.length} run(s)\n`));
  } else {
    console.log(chalk.yellow(`  Completed with ${failures} failure(s) out of ${targets.length} run(s)\n`));
  }
}

interface PropertyRun {
  id: string;
  property_id: string;
  type: RunType;
  status: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
  trigger: string;
  source: string | null;
  queued_at: string;
  started_at: string | null;
  completed_at: string | null;
  findings_count: number;
  severity_summary: Record<string, number> | null;
  summary: string | null;
  error: string | null;
}

export async function propertiesRunsCommand(opts: { org?: string; property?: string; limit?: number }): Promise<void> {
  banner();
  if (!(await requireAuth())) return;
  const resolved = await resolveOrgId(opts.org);
  if (!resolved) return;

  const props = await fetchProperties(resolved.org.id);
  if (props === null) return;

  let propsToShow = props;
  if (opts.property) {
    const match = props.find((p) => p.name === opts.property || p.id === opts.property);
    if (!match) {
      console.log(chalk.red(`  Property "${opts.property}" not found.\n`));
      return;
    }
    propsToShow = [match];
  }

  const limit = opts.limit || 10;
  console.log(chalk.green.bold(`  Recent runs in ${chalk.white(resolved.org.slug)}`));
  console.log(chalk.gray('  ' + '─'.repeat(76)));

  let total = 0;
  for (const prop of propsToShow) {
    const res = await fetch(
      `${API_URL}/api/orgs/${resolved.org.id}/properties/${prop.id}/runs?limit=${limit}`,
      { headers: authHeaders() },
    );
    if (!res.ok) continue;
    const data = await res.json() as { runs?: PropertyRun[] };
    const runs = data.runs || [];
    if (runs.length === 0) continue;

    console.log(`  ${chalk.white.bold(prop.name)}  ${KIND_COLOR[prop.kind](`[${prop.kind}]`)}`);
    for (const run of runs) {
      const statusColor =
        run.status === 'succeeded' ? chalk.green :
        run.status === 'failed' ? chalk.red :
        run.status === 'running' ? chalk.yellow :
        run.status === 'cancelled' ? chalk.gray :
        chalk.cyan;
      const when = (run.completed_at || run.started_at || run.queued_at).slice(0, 19).replace('T', ' ');
      const sev = run.severity_summary as Record<string, number> | null;
      const sevStr = sev
        ? chalk.dim(`[${sev.critical || 0}C/${sev.high || 0}H/${sev.medium || 0}M/${sev.low || 0}L]`)
        : chalk.dim('[–]');
      console.log(`    ${chalk.gray(when)}  ${statusColor(run.status.padEnd(10))}  ${chalk.dim(run.type.padEnd(8))}  ${sevStr}  ${chalk.gray(run.summary || '')}`);
      total++;
    }
    console.log();
  }

  if (total === 0) {
    console.log(chalk.gray('  No runs recorded yet.'));
    console.log(chalk.dim(`  Kick one off with: ${chalk.white('threatcrush properties run')}\n`));
  }
}

interface ImportRecord {
  name: string;
  target: string;
  kind?: Kind;
  description?: string;
  tags?: string[] | string;
  enabled?: boolean;
}

function parseImportFile(path: string): ImportRecord[] {
  const ext = extname(path).toLowerCase();
  const raw = readFileSync(path, 'utf-8');
  if (ext === '.json') {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error('JSON must be an array of objects');
    return parsed as ImportRecord[];
  }
  if (ext === '.csv' || ext === '.tsv') {
    const delim = ext === '.tsv' ? '\t' : ',';
    const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
    if (lines.length < 1) return [];
    const header = lines[0].split(delim).map((h) => h.trim().toLowerCase());
    const idx = {
      name: header.indexOf('name'),
      target: header.indexOf('target'),
      kind: header.indexOf('kind'),
      description: header.indexOf('description'),
      tags: header.indexOf('tags'),
      enabled: header.indexOf('enabled'),
    };
    if (idx.name < 0 || idx.target < 0) {
      throw new Error('CSV must have at least "name" and "target" columns');
    }
    return lines.slice(1).map((line) => {
      const cols = line.split(delim).map((c) => c.trim());
      const rec: ImportRecord = {
        name: cols[idx.name] || '',
        target: cols[idx.target] || '',
      };
      if (idx.kind >= 0 && cols[idx.kind]) rec.kind = cols[idx.kind] as Kind;
      if (idx.description >= 0 && cols[idx.description]) rec.description = cols[idx.description];
      if (idx.tags >= 0 && cols[idx.tags]) rec.tags = cols[idx.tags].split('|').map((t) => t.trim()).filter(Boolean);
      if (idx.enabled >= 0 && cols[idx.enabled]) rec.enabled = /^(true|1|yes)$/i.test(cols[idx.enabled]);
      return rec;
    });
  }
  throw new Error(`Unsupported file type: ${ext}. Use .json, .csv, or .tsv.`);
}

function inferKind(target: string): Kind {
  if (/^https?:\/\//.test(target)) return 'url';
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(target)) return 'ip';
  if (target.includes('/') && !target.startsWith('/')) return 'repo';
  return 'domain';
}

export async function propertiesImportCommand(filePath: string, opts: { org?: string; dryRun?: boolean }): Promise<void> {
  banner();
  if (!(await requireAuth())) return;
  const resolved = await resolveOrgId(opts.org);
  if (!resolved) return;

  let records: ImportRecord[];
  try {
    records = parseImportFile(filePath);
  } catch (err) {
    console.log(chalk.red(`  ✗ ${(err as Error).message}\n`));
    return;
  }

  if (records.length === 0) {
    console.log(chalk.yellow('  No records to import.\n'));
    return;
  }

  console.log(chalk.green.bold(`  Importing ${records.length} property(s) into ${resolved.org.slug}`));
  console.log(chalk.gray('  ' + '─'.repeat(76)));

  let created = 0;
  let skipped = 0;
  let failed = 0;

  for (const rec of records) {
    if (!rec.name || !rec.target) {
      console.log(chalk.yellow(`  ! skipped (missing name or target): ${JSON.stringify(rec)}`));
      skipped++;
      continue;
    }
    const kind = (rec.kind && KINDS.includes(rec.kind)) ? rec.kind : inferKind(rec.target);
    const tags = Array.isArray(rec.tags) ? rec.tags : (typeof rec.tags === 'string' ? rec.tags.split(',').map((t) => t.trim()).filter(Boolean) : []);

    if (opts.dryRun) {
      console.log(`  ${chalk.dim('[dry-run]')} ${chalk.white(rec.name.padEnd(24))} ${KIND_COLOR[kind](`[${kind}]`)} ${chalk.dim(rec.target)}`);
      continue;
    }

    try {
      const res = await fetch(`${API_URL}/api/orgs/${resolved.org.id}/properties`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          name: rec.name,
          target: rec.target,
          kind,
          description: rec.description,
          tags,
          enabled: rec.enabled !== false,
        }),
      });
      if (res.status === 409) {
        console.log(`  ${chalk.yellow('!')}  ${chalk.white(rec.name.padEnd(24))} already exists — skipped`);
        skipped++;
        continue;
      }
      if (!res.ok) {
        const body = await res.json().catch(() => ({ error: res.statusText }));
        console.log(`  ${chalk.red('✗')}  ${chalk.white(rec.name.padEnd(24))} ${chalk.red(body.error || 'failed')}`);
        failed++;
        continue;
      }
      console.log(`  ${chalk.green('✓')}  ${chalk.white(rec.name.padEnd(24))} ${KIND_COLOR[kind](`[${kind}]`)} ${chalk.dim(rec.target)}`);
      created++;
    } catch (err) {
      console.log(`  ${chalk.red('✗')}  ${chalk.white(rec.name.padEnd(24))} ${chalk.red((err as Error).message)}`);
      failed++;
    }
  }

  console.log();
  console.log(chalk.gray('  ' + '─'.repeat(76)));
  console.log(`  ${chalk.green(`${created} created`)}  ${chalk.yellow(`${skipped} skipped`)}  ${chalk.red(`${failed} failed`)}\n`);
}
