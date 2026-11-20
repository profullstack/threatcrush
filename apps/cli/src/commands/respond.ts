/**
 * `threatcrush respond`: incident containment for one box or a fleet.
 *
 * Built from the 2026-11-20 incident, where stolen SSH keys and a stolen
 * password were contained by hand across five servers. Dry-run by default;
 * `--apply` acts. Two mistakes from that night are refused here: removing the
 * only trusted key before installing a replacement (it locked everyone out),
 * and treating `command=`-restricted keys as safe (they were stolen deploy keys).
 */
import { existsSync, readFileSync, statSync } from 'node:fs';
import chalk from 'chalk';
import type { Command } from 'commander';
import { IpcClient } from '../core/ipc-client.js';
import { parseDuration } from '../daemon/firewall/backoff.js';
import { FINGERPRINT_RE, resolveKeyTargets } from '../core/respond/keys.js';
import { isValidIp, reportFailed } from '../core/respond/plan.js';
import { localSh, parseHosts, runHosts, runLocal, sshExec, type DaemonBan, type ScriptRunner, type SshExec } from '../core/respond/run.js';
import type { Report, RespondRequest, RespondSub } from '../core/respond/types.js';

interface CommonOpts {
  apply?: boolean;
  json?: boolean;
  hosts?: string;
}

/** Ban through the local daemon with `strict`, so a stolen-key session is not "an operator". */
export const daemonBan: DaemonBan = async (ip, ttl) => {
  if (!IpcClient.isDaemonRunning()) return null;
  const client = new IpcClient();
  try {
    await client.connect();
    const entry = await client.block(ip, 'threatcrush respond ip', ttl, { strict: true });
    // A dry-run daemon writes no rule: fall back to the direct firewall rule.
    if (entry.dry_run) return null;
    return { ok: true, message: `banned via threatcrushd for ${ttl} (offence #${entry.strikes})` };
  } catch (err) {
    return { ok: false, message: `threatcrushd refused: ${(err as Error).message}` };
  } finally {
    client.close();
  }
};

export interface RespondDeps {
  run: ScriptRunner;
  ssh: SshExec;
  ban?: DaemonBan;
  log: (line: string) => void;
}

const defaultDeps: RespondDeps = { run: localSh, ssh: sshExec, ban: daemonBan, log: (l) => console.log(l) };

/** Run a validated request here or on `--hosts`, print it, set the exit code. */
export async function respondCommand(req: RespondRequest, opts: CommonOpts, deps: RespondDeps = defaultDeps): Promise<Report[]> {
  let reports: Report[];
  if (opts.hosts) {
    const { hosts, errors } = parseHosts(opts.hosts, (p) => {
      try { return existsSync(p) && statSync(p).isFile() ? readFileSync(p, 'utf-8') : null; } catch { return null; }
    });
    if (errors.length || hosts.length === 0) {
      fail(deps, opts, errors.length ? errors : ['--hosts named no hosts']);
      return [];
    }
    reports = await runHosts(hosts, req, deps.ssh);
  } else {
    reports = [await runLocal(req, { run: deps.run, ban: deps.ban })];
  }

  if (opts.json) {
    deps.log(JSON.stringify(opts.hosts ? { hosts: reports } : reports[0], null, 2));
  } else {
    for (const r of reports) for (const line of renderReport(r)) deps.log(line);
    if (reports.length > 1) deps.log(renderSummary(reports));
  }
  if (reports.some(reportFailed)) process.exitCode = 1;
  return reports;
}

function fail(deps: RespondDeps, opts: CommonOpts, errors: string[]): void {
  if (opts.json) deps.log(JSON.stringify({ error: errors.join('; ') }));
  else for (const e of errors) deps.log(chalk.red(`  ✗ ${e}`));
  process.exitCode = 1;
}

const STATUS: Record<string, (s: string) => string> = {
  planned: chalk.cyan,
  done: chalk.green,
  failed: chalk.red,
  refused: chalk.red,
  'needs-root': chalk.yellow,
};

const when = (ms: number | null) => (ms ? new Date(ms).toISOString().replace('T', ' ').slice(0, 16) + 'Z' : 'never');

export function renderReport(r: Report): string[] {
  const out: string[] = [];
  const mode = r.apply ? chalk.red('APPLY') : chalk.cyan('dry-run');
  out.push('');
  out.push(chalk.green.bold(`  respond ${r.sub}  ${chalk.white(r.host)}${r.hostname && r.hostname !== r.host ? chalk.gray(` (${r.hostname})`) : ''}  ${mode}  ${chalk.gray(`via ${r.via}${r.root ? ', root' : ', NOT root'}`)}`));
  out.push(chalk.gray('  ' + '─'.repeat(70)));
  if (r.error) {
    out.push(chalk.red(`  ✗ ${r.error}`));
    return out;
  }

  if (r.connections) {
    out.push(chalk.bold(`  Established connections (${r.connections.length})`));
    for (const c of r.connections) {
      out.push(`    ${c.ip.padEnd(18)} ${c.local} <- ${c.peer}  ${chalk.gray(c.processes.map((p) => `${p.name}[${p.pid}]`).join(' '))}`);
    }
  }
  if (r.logins) {
    out.push(chalk.bold(`  Accepted logins in the last 30 days (${r.logins.length})`));
    for (const l of r.logins.slice(0, 25)) {
      out.push(`    ${when(l.at)}  ${l.ip.padEnd(18)} ${l.user.padEnd(12)} ${l.method}${l.fingerprint ? ' ' + l.fingerprint : ''}`);
    }
    if (r.logins.length > 25) out.push(chalk.gray(`    ... ${r.logins.length - 25} more (--json for all)`));
  }
  if (r.failedAttempts) {
    const parts = Object.entries(r.failedAttempts).map(([ip, n]) => `${ip}: ${n}`);
    if (parts.length) out.push(chalk.gray(`  Failed attempts: ${parts.join(', ')}`));
  }
  if (r.keys) {
    out.push(chalk.bold(`  ${r.sub === 'keys-audit' ? 'Authorized keys' : 'Matching authorized keys'} (${r.keys.length})`));
    for (const k of r.keys) {
      out.push(`    ${chalk.white((k.user ?? '?').padEnd(12))} ${k.fingerprint ?? '(bad key)'}  ${chalk.gray(k.comment || '(no comment)')}`);
      out.push(chalk.gray(`      ${k.file}:${k.line}${k.live ? '' : ' [stale copy]'}  last used: ${when(k.lastUsed)}${k.restrictions.length ? '  ' + k.restrictions.join(' ') : ''}`));
      for (const f of k.flags) out.push(chalk.yellow(`      ! ${f}`));
    }
  }
  if (r.staleFiles?.length) {
    out.push(chalk.bold('  Stale authorized_keys copies (not read by sshd; delete them)'));
    for (const f of r.staleFiles) out.push(`    ${f}`);
  }
  if (r.privateKeys) {
    out.push(chalk.bold(`  Private-key copies on disk (${r.privateKeys.length})`));
    for (const p of r.privateKeys) out.push(`    ${p.path}  ${chalk.gray(p.fingerprint ?? '')}`);
  }
  const showEffective = (label: string, v?: Record<string, string>) => {
    if (!v || !Object.keys(v).length) return;
    out.push(chalk.bold(`  Effective sshd settings ${label}`));
    for (const [k, val] of Object.entries(v)) out.push(`    ${k.padEnd(30)} ${val}`);
  };
  showEffective('before', r.effectiveBefore);
  showEffective('after', r.effectiveAfter);

  if (r.actions.length) {
    out.push(chalk.bold('  Actions'));
    for (const a of r.actions) {
      const color = STATUS[a.status] ?? ((s: string) => s);
      out.push(`    ${color(a.status.padEnd(10))} ${a.summary}`);
      if (a.message) out.push(chalk.gray(`               ${a.message}`));
    }
  } else if (r.sub !== 'keys-audit') {
    out.push(chalk.gray('  Nothing to do.'));
  }
  for (const w of r.warnings) out.push(chalk.yellow(`  ! ${w}`));
  if (r.replacementHelp) for (const l of r.replacementHelp) out.push(chalk.yellow(`  ${l}`));
  if (!r.root && r.needsRoot.length) {
    out.push(chalk.yellow('  Not root: read-only. These need root (sudo):'));
    for (const n of r.needsRoot) out.push(chalk.yellow(`    - ${n}`));
  }
  if (!r.apply && r.actions.some((a) => a.status === 'planned')) out.push(chalk.cyan('  Dry run: nothing changed. Re-run with --apply to act.'));
  return out;
}

export function renderSummary(reports: Report[]): string {
  const lines = ['', chalk.bold('  Summary')];
  for (const r of reports) {
    const counts: Record<string, number> = {};
    for (const a of r.actions) counts[a.status] = (counts[a.status] ?? 0) + 1;
    const text = r.error ? chalk.red(`error: ${r.error}`) : Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(', ') || 'nothing to do';
    lines.push(`    ${r.host.padEnd(24)} ${text}`);
  }
  return lines.join('\n');
}

// ─── commander wiring ───

function common(cmd: Command): Command {
  return cmd
    .option('--apply', 'act (default is a dry run that changes nothing)')
    .option('--json', 'machine-readable JSON')
    .option('--hosts <file|list>', 'run on these hosts over ssh (a file, one per line, or a comma list); 3 at a time');
}

function bail(opts: CommonOpts, message: string): void {
  fail(defaultDeps, opts, [message]);
}

export function registerRespond(program: Command): void {
  const respond = program
    .command('respond')
    .description('Incident response: kill sessions, ban IPs, pull stolen keys, lock sshd down (dry run unless --apply)')
    .addHelpText('after', `
Runbook (stolen key + attacker IP, whole fleet):
  threatcrush respond keys-audit --hosts fleet.txt
  threatcrush respond ip 203.0.113.7 --hosts fleet.txt --apply
  threatcrush respond key SHA256:AbC... --hosts fleet.txt            # check the lockout guard first
  threatcrush respond key SHA256:AbC... --hosts fleet.txt --apply
  threatcrush respond sshd --lockdown --hosts fleet.txt --apply
`);

  common(respond.command('ip').argument('<ip...>', 'attacker address(es)'))
    .description('Ban an address, kill its sshd sessions and connections, list its logins')
    .option('--ttl <duration>', 'ban length (e.g. 12h, 30d)', '30d')
    .action(async (ips: string[], opts: CommonOpts & { ttl: string }) => {
      const bad = ips.filter((ip) => !isValidIp(ip));
      if (bad.length) return bail(opts, `not an IP address: ${bad.join(', ')}`);
      if (!parseDuration(opts.ttl)) return bail(opts, `bad --ttl ${opts.ttl}`);
      await respondCommand({ sub: 'ip', apply: Boolean(opts.apply), ips: [...new Set(ips)], ttl: opts.ttl }, opts);
    });

  common(respond.command('key').argument('<key...>', 'SHA256:fingerprint, or a public/private key file'))
    .description('Remove a key from every authorized_keys on the box and shred private copies of it')
    .option('--allow-lockout', 'remove even if it is the only key that lets you (the invoking user) in')
    .option('--search <dir>', 'also search this directory for private-key copies (repeatable; default /root /home)', (v: string, acc: string[]) => [...acc, v], [] as string[])
    .action(async (keys: string[], opts: CommonOpts & { allowLockout?: boolean; search: string[] }) => {
      const { fingerprints, errors } = resolveKeyTargets(keys, { readFile: (p) => readFileSync(p, 'utf-8') });
      if (errors.length || !fingerprints.length) return bail(opts, errors.join('; ') || 'no keys given');
      if (fingerprints.some((fp) => !FINGERPRINT_RE.test(fp))) return bail(opts, 'bad fingerprint');
      const badRoot = opts.search.find((d) => !/^\/[A-Za-z0-9._/-]+$/.test(d));
      if (badRoot) return bail(opts, `--search needs an absolute path: ${badRoot}`);
      await respondCommand({
        sub: 'key', apply: Boolean(opts.apply), fingerprints, allowLockout: Boolean(opts.allowLockout),
        searchRoots: opts.search.length ? ['/root', '/home', ...opts.search] : undefined,
      }, opts);
    });

  common(respond.command('sshd'))
    .description('Show effective root/password settings; --lockdown writes validated sshd drop-ins')
    .option('--lockdown', 'PermitRootLogin no, PasswordAuthentication no, KbdInteractiveAuthentication no')
    .option('--allow-root-localhost', 'with --lockdown: root may still log in by key from 127.0.0.1 / ::1')
    .action(async (opts: CommonOpts & { lockdown?: boolean; allowRootLocalhost?: boolean }) => {
      if (opts.allowRootLocalhost && !opts.lockdown) return bail(opts, '--allow-root-localhost only makes sense with --lockdown');
      await respondCommand({ sub: 'sshd', apply: Boolean(opts.apply), lockdown: Boolean(opts.lockdown), allowRootLocalhost: Boolean(opts.allowRootLocalhost) }, opts);
    });

  common(respond.command('keys-audit'))
    .description('List every authorized key with user, restrictions and last use; flag risky ones')
    .action(async (opts: CommonOpts) => {
      await respondCommand({ sub: 'keys-audit' as RespondSub, apply: false }, opts);
    });
}
