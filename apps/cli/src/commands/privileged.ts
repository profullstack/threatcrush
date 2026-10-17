import { existsSync, readFileSync, readdirSync } from 'node:fs';
import chalk from 'chalk';
import { takeSnapshot } from '../core/privileges/index.js';
import { getModuleEvents, initStateDB } from '../core/state.js';
import { PATHS } from '../daemon/paths.js';
import type { ThreatEvent } from '../types/events.js';

const SEV: Record<string, (s: string) => string> = {
  critical: chalk.red.bold, high: chalk.red, medium: chalk.yellow, low: chalk.cyan, info: chalk.gray,
};

/**
 * `threatcrush privileged` — who can become root on this box right now, and
 * the daemon's recent record of changes and sudo commands.
 */
export async function privilegedCommand(opts: { json?: boolean; limit?: string }): Promise<void> {
  const snapshot = takeSnapshot({
    readFile: (p) => { try { return readFileSync(p, 'utf-8'); } catch { return null; } },
    readDir: (p) => { try { return readdirSync(p); } catch { return null; } },
    exists: (p) => existsSync(p),
  });

  let events: ThreatEvent[] = [];
  let ledgerNote = '';
  try {
    initStateDB(PATHS.stateDb);
    events = getModuleEvents('privileged-access', Number(opts.limit) || 25);
  } catch {
    ledgerNote = `the daemon's state database (${PATHS.stateDb}) is not readable here`;
  }

  if (opts.json) {
    console.log(JSON.stringify({ snapshot, events }, null, 2));
    return;
  }

  console.log(`  ${chalk.white.bold('uid 0 accounts:')} ${snapshot.uid0.join(', ') || '—'}`);
  for (const [group, members] of Object.entries(snapshot.admin_groups)) {
    console.log(`  ${chalk.white.bold(`${group} group:`)} ${members.join(', ') || '—'}`);
  }
  const rules = Object.entries(snapshot.sudoers).filter(([, r]) => r.length > 0);
  console.log(`  ${chalk.white.bold('sudoers:')} ${rules.length} file(s) with rules`);
  for (const [path, r] of rules) {
    for (const rule of r.filter((x) => !/^Defaults\b/.test(x))) console.log(chalk.gray(`    ${path.replace('/etc/', '')}: ${rule}`));
  }
  console.log(`  ${chalk.white.bold('authorized keys:')}`);
  for (const [user, keys] of Object.entries(snapshot.keys)) {
    for (const [fp, k] of Object.entries(keys)) console.log(`    ${user.padEnd(12)} ${k.type.padEnd(20)} ${fp} ${chalk.gray(k.comment)}`);
  }
  if (snapshot.unreadable.length) {
    console.log(chalk.yellow(`  ! not readable as this user: ${snapshot.unreadable.join(', ')} (run with sudo for the full picture)`));
  }

  console.log(`\n  ${chalk.white.bold('Recent changes and sudo commands')}`);
  if (ledgerNote) console.log(chalk.gray(`    ${ledgerNote}`));
  else if (events.length === 0) console.log(chalk.gray('    none recorded yet (the daemon records them from its first run on)'));
  for (const e of events) {
    const at = new Date(e.timestamp).toISOString().replace('T', ' ').slice(0, 19);
    console.log(`    ${chalk.gray(at)} ${(SEV[e.severity] ?? chalk.white)(e.severity.padEnd(8))} ${e.message}`);
  }
  console.log();
}
