import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import chalk from 'chalk';
import { RESOLVER_FILES, RESOLVER_HOOKS, hostsBlocklist, unboundBlocklist } from '../core/threat-feeds/index.js';

/**
 * `threatcrush feeds resolver install|remove|status` — the one root step that
 * lets dnsmasq or unbound refuse the abuse.ch domains (issue #304).
 *
 * The daemon runs under ProtectSystem and cannot write /etc, so it only
 * rewrites its blocklists in its own state dir. This command, run once as
 * root, drops a one-line pointer into the resolver's config, validates the
 * result with the resolver's own checker, and only then restarts it; a config
 * the checker rejects is rolled back. systemd-resolved has no blocklist
 * support and is reported as such.
 */

export type ResolverName = 'dnsmasq' | 'unbound';

export interface ResolverIO {
  exists(path: string): boolean;
  read(path: string): string | null;
  write(path: string, content: string): void;
  remove(path: string): void;
  /** Exit code and combined output. */
  run(cmd: string, args: string[]): { code: number; out: string };
}

const realIO: ResolverIO = {
  exists: (p) => existsSync(p),
  read: (p) => { try { return readFileSync(p, 'utf-8'); } catch { return null; } },
  write: (p, c) => writeFileSync(p, c),
  remove: (p) => rmSync(p, { force: true }),
  run: (cmd, args) => {
    const r = spawnSync(cmd, args, { encoding: 'utf-8', timeout: 30_000 });
    return { code: r.status ?? 1, out: `${r.stdout ?? ''}${r.stderr ?? ''}`.trim() };
  },
};

const APPARMOR_LOCAL = '/etc/apparmor.d/local/usr.sbin.unbound';
const APPARMOR_PROFILE = '/etc/apparmor.d/usr.sbin.unbound';

export function hookContent(resolver: ResolverName, stateDir: string): string {
  const head = '# Installed by `threatcrush feeds resolver install`; `threatcrush feeds resolver remove` takes it out.\n';
  return resolver === 'dnsmasq'
    ? `${head}addn-hosts=${join(stateDir, RESOLVER_FILES.hosts)}\n`
    : `${head}include: "${join(stateDir, RESOLVER_FILES.unbound)}"\n`;
}

export function apparmorRule(stateDir: string): string {
  return `  ${join(stateDir, RESOLVER_FILES.unbound)} r,  # threatcrush`;
}

/** Which resolvers are installed here and could take a hook. */
export function detectResolvers(io: ResolverIO = realIO): ResolverName[] {
  const found: ResolverName[] = [];
  if (io.exists(dirname(RESOLVER_HOOKS.dnsmasq)) && io.run('dnsmasq', ['--version']).code === 0) found.push('dnsmasq');
  if (io.exists(dirname(RESOLVER_HOOKS.unbound)) && io.run('unbound-checkconf', ['-h']).code !== 127) found.push('unbound');
  return found;
}

function check(resolver: ResolverName, io: ResolverIO): { code: number; out: string } {
  return resolver === 'dnsmasq' ? io.run('dnsmasq', ['--test']) : io.run('unbound-checkconf', []);
}

function restartIfActive(resolver: ResolverName, io: ResolverIO): string {
  if (io.run('systemctl', ['is-active', '--quiet', `${resolver}.service`]).code !== 0) return 'not running; takes effect when it starts';
  const r = io.run('systemctl', ['restart', `${resolver}.service`]);
  return r.code === 0 ? 'restarted' : `restart failed: ${r.out.split('\n')[0]}`;
}

export function installHook(resolver: ResolverName, stateDir: string, io: ResolverIO = realIO): { ok: boolean; message: string } {
  const hook = RESOLVER_HOOKS[resolver];
  // The resolver must find a file even before the daemon's first refresh.
  const file = join(stateDir, resolver === 'dnsmasq' ? RESOLVER_FILES.hosts : RESOLVER_FILES.unbound);
  if (!io.exists(file)) io.write(file, resolver === 'dnsmasq' ? hostsBlocklist([]) : unboundBlocklist([]));

  io.write(hook, hookContent(resolver, stateDir));
  if (resolver === 'unbound' && io.exists(APPARMOR_LOCAL)) {
    const local = io.read(APPARMOR_LOCAL) ?? '';
    if (!local.includes(apparmorRule(stateDir))) io.write(APPARMOR_LOCAL, `${local.replace(/\n?$/, '\n')}${apparmorRule(stateDir)}\n`);
    if (io.exists(APPARMOR_PROFILE)) io.run('apparmor_parser', ['-r', APPARMOR_PROFILE]);
  }

  const checked = check(resolver, io);
  if (checked.code !== 0) {
    removeHook(resolver, stateDir, io, { restart: false });
    return { ok: false, message: `${resolver} rejected the config, so nothing was changed: ${checked.out.split('\n').slice(-2).join(' ')}` };
  }
  return { ok: true, message: `${hook} installed; ${resolver} ${restartIfActive(resolver, io)}` };
}

export function removeHook(resolver: ResolverName, stateDir: string, io: ResolverIO = realIO, opts = { restart: true }): string {
  const hook = RESOLVER_HOOKS[resolver];
  const had = io.exists(hook);
  io.remove(hook);
  if (resolver === 'unbound' && io.exists(APPARMOR_LOCAL)) {
    const local = io.read(APPARMOR_LOCAL) ?? '';
    const kept = local.split('\n').filter((l) => l !== apparmorRule(stateDir)).join('\n');
    if (kept !== local) {
      io.write(APPARMOR_LOCAL, kept);
      if (io.exists(APPARMOR_PROFILE)) io.run('apparmor_parser', ['-r', APPARMOR_PROFILE]);
    }
  }
  if (!had) return `${resolver}: no hook installed`;
  return `${hook} removed${opts.restart ? `; ${resolver} ${restartIfActive(resolver, io)}` : ''}`;
}

function countListed(text: string | null, pattern: RegExp): number {
  return text ? (text.match(pattern) ?? []).length : 0;
}

export function resolverCommand(sub: string | undefined, stateDir: string, io: ResolverIO = realIO): number {
  const found = detectResolvers(io);
  const root = typeof process.getuid !== 'function' || process.getuid() === 0;

  if (sub === 'install' || sub === 'remove') {
    if (!root) {
      console.error(`Run as root: sudo $(which threatcrush) feeds resolver ${sub}`);
      return 1;
    }
    if (sub === 'install' && found.length === 0) {
      console.error('No dnsmasq or unbound here. systemd-resolved cannot refuse names from a list; listed domains stay detection-only (dns-monitor), and listed IPs can still be blocked with [threat_feeds] block = true.');
      return 1;
    }
    let failed = false;
    for (const resolver of sub === 'install' ? found : (['dnsmasq', 'unbound'] as ResolverName[])) {
      if (sub === 'install') {
        const r = installHook(resolver, stateDir, io);
        failed ||= !r.ok;
        console.log(`${r.ok ? chalk.green('✓') : chalk.red('✗')} ${r.message}`);
      } else {
        console.log(`  ${removeHook(resolver, stateDir, io)}`);
      }
    }
    if (sub === 'install' && !failed) {
      console.log(chalk.gray('  Now set [threat_feeds] block_domains = true (with [remediation] in enforce mode) and restart threatcrushd; until then the lists stay empty.'));
    }
    return failed ? 1 : 0;
  }

  const hosts = io.read(join(stateDir, RESOLVER_FILES.hosts));
  const unbound = io.read(join(stateDir, RESOLVER_FILES.unbound));
  console.log(`  resolvers here: ${found.join(', ') || 'none that can block (systemd-resolved only?)'}`);
  for (const r of ['dnsmasq', 'unbound'] as ResolverName[]) {
    console.log(`  ${r.padEnd(8)} hook ${io.exists(RESOLVER_HOOKS[r]) ? chalk.green('installed') : chalk.gray('not installed')}`);
  }
  console.log(`  listed now: ${countListed(hosts, /^0\.0\.0\.0 /gm)} names in ${RESOLVER_FILES.hosts}, ${countListed(unbound, /local-zone:/g)} zones in ${RESOLVER_FILES.unbound}`);
  return 0;
}
