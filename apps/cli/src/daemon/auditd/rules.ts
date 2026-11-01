import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { isAbsolute } from 'node:path';
import type { EdrSettings } from '../workers/edr.js';

const WEB_TOOLS = ['sh', 'bash', 'dash', 'zsh', 'curl', 'wget'];
const MINER_NAMES = ['xmrig', 'minerd', 'cpuminer', 'cpuminer-multi', 'kdevtmpfsi', 'kinsing', 'cryptonight'];
const CONNECT_KEY = 'threatcrush_edr_connect';
const LISTEN_KEY = 'threatcrush_edr_listen';

function passwdByName(): Map<string, number> {
  let raw = '';
  try {
    raw = execFileSync('getent', ['passwd'], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] });
  } catch {
    try { raw = readFileSync('/etc/passwd', 'utf8'); } catch { return new Map(); }
  }
  const out = new Map<string, number>();
  for (const line of raw.split('\n')) {
    const fields = line.split(':');
    const uid = Number(fields[2]);
    if (fields[0] && Number.isInteger(uid)) out.set(fields[0], uid);
  }
  return out;
}

function existingExecutables(names: string[]): string[] {
  const paths = new Set<string>();
  for (const name of names) {
    for (const prefix of ['/bin', '/usr/bin', '/usr/local/bin']) {
      const candidate = `${prefix}/${name}`;
      try {
        if (!existsSync(candidate) || !statSync(candidate).isFile()) continue;
        paths.add(realpathSync(candidate));
      } catch { /* not installed */ }
    }
  }
  return [...paths].sort();
}

function existingDirectories(paths: string[]): string[] {
  return [...new Set(paths)].filter((path) => {
    if (!isAbsolute(path) || /[\s\r\n]/.test(path)) return false;
    try { return statSync(path).isDirectory(); } catch { return false; }
  }).sort();
}

/**
 * Narrow auditd rules for execution detections. Optional network syscall rules
 * are broader and generated only after an explicit opt-in. The generated rules
 * observe only shell/downloader execution by selected service accounts,
 * execution from selected writable trees, and known miner process names.
 */
export function generateAuditRules(settings: EdrSettings): { rules: string[]; warnings: string[] } {
  const rules = new Set<string>();
  const warnings: string[] = [];
  const ids = passwdByName();
  const serviceIds = [...new Set(settings.webServiceUsers.flatMap((name) => {
    const uid = ids.get(name);
    return uid === undefined ? [] : [uid];
  }))].sort((a, b) => a - b);
  const missingUsers = settings.webServiceUsers.filter((name) => !ids.has(name));
  if (missingUsers.length) warnings.push(`service account(s) not found in /etc/passwd: ${missingUsers.join(', ')}`);
  if (serviceIds.length === 0) warnings.push('no web-service account UIDs resolved; web child-process rules were not generated');

  const architectures = process.arch === 'x64' ? ['b64', 'b32'] : process.arch === 'ia32' ? ['b32'] : ['b64'];
  const tools = existingExecutables(WEB_TOOLS);
  for (const arch of architectures) {
    for (const uid of serviceIds) {
      for (const executable of tools) {
        rules.add(`-a always,exit -F arch=${arch} -S execve,execveat -F success=1 -F euid=${uid} -F exe=${executable} -k threatcrush_edr_web`);
      }
    }
    for (const directory of existingDirectories(settings.tempExecPaths)) {
      rules.add(`-a always,exit -F arch=${arch} -F dir=${directory} -F perm=x -k threatcrush_edr_temp`);
    }
    for (const comm of MINER_NAMES) {
      rules.add(`-a always,exit -F arch=${arch} -S execve,execveat -F success=1 -F comm=${comm} -k threatcrush_edr_miner`);
    }
    if (settings.watchNetworkSyscalls) {
      rules.add(`-a always,exit -F arch=${arch} -S connect -F success=1 -k ${CONNECT_KEY}`);
      rules.add(`-a always,exit -F arch=${arch} -S listen -F success=1 -k ${LISTEN_KEY}`);
    }
  }
  if (tools.length === 0) warnings.push('no configured shell or downloader executables were found');
  if (existingDirectories(settings.tempExecPaths).length === 0) warnings.push('no configured temporary execution directories exist');
  if (settings.watchNetworkSyscalls) warnings.push('network syscall rules can generate substantial audit volume; review host capacity and retention before loading');
  return { rules: [...rules], warnings };
}
