import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import type { AvDetection } from '../types';

/**
 * ClamAV bridge. ClamAV (GPL, Cisco Talos) carries millions of signatures and
 * runs on Windows, macOS and Linux; CrushAV drives it as a separate program
 * when it is installed, so its signature database backs every desktop scan.
 */

export interface ClamInfo {
  available: boolean;
  /** Absolute path of the binary used. */
  binary: string | null;
  /** `clamdscan` talks to a running daemon (fast); `clamscan` loads the DB itself. */
  mode: 'clamdscan' | 'clamscan' | null;
  /** e.g. "ClamAV 1.4.2/27447/Sat Nov 1 08:42:01 2026" */
  version: string | null;
  /** Signature database date, when the version line has one. */
  signaturesDate: string | null;
}

const WINDOWS_DIRS = ['C:\\Program Files\\ClamAV', 'C:\\Program Files (x86)\\ClamAV', 'C:\\ProgramData\\chocolatey\\bin'];

export function findBinary(name: string, env: NodeJS.ProcessEnv = process.env, platform = process.platform): string | null {
  const exe = platform === 'win32' ? `${name}.exe` : name;
  const dirs = (env.PATH ?? env.Path ?? '').split(delimiter).filter(Boolean);
  if (platform === 'win32') dirs.push(...WINDOWS_DIRS);
  if (platform === 'darwin') dirs.push('/opt/homebrew/bin', '/usr/local/bin');
  for (const d of dirs) {
    const p = join(d, exe);
    if (existsSync(p)) return p;
  }
  return null;
}

function run(bin: string, args: string[], timeoutMs: number, signal?: AbortSignal): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(bin, args, { windowsHide: true, signal });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ code: null, stdout, stderr: stderr || String(e) });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

export async function detectClamAV(): Promise<ClamInfo> {
  const none: ClamInfo = { available: false, binary: null, mode: null, version: null, signaturesDate: null };
  const clamscan = findBinary('clamscan');
  const clamdscan = findBinary('clamdscan');
  let mode: ClamInfo['mode'] = null;
  let binary: string | null = null;
  if (clamdscan) {
    // clamdscan exists without a daemon on many installs; --ping proves one is up.
    const ping = await run(clamdscan, ['--ping', '1'], 5000);
    if (ping.code === 0) {
      mode = 'clamdscan';
      binary = clamdscan;
    }
  }
  if (!binary && clamscan) {
    mode = 'clamscan';
    binary = clamscan;
  }
  if (!binary) return none;
  const v = await run(binary, ['--version'], 15000);
  const version = v.stdout.trim().split('\n')[0] || null;
  const parts = version?.split('/') ?? [];
  return { available: v.code === 0, binary, mode, version, signaturesDate: parts.length >= 3 ? parts.slice(2).join('/').trim() : null };
}

/** Parse `path: Signature.Name FOUND` lines. Paths may contain ": ". */
export function parseClamOutput(stdout: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const line of stdout.split(/\r?\n/)) {
    const m = /^(.*): (\S+) FOUND$/.exec(line.trim());
    if (!m) continue;
    const list = out.get(m[1]) ?? [];
    list.push(m[2]);
    out.set(m[1], list);
  }
  return out;
}

export function clamDetection(sig: string): AvDetection {
  const pua = /^PUA\./i.test(sig);
  const heuristic = /^Heuristics\./i.test(sig);
  return {
    engine: 'clamav',
    id: `ClamAV.${sig}`,
    name: sig,
    severity: pua ? 'medium' : heuristic ? 'medium' : /EICAR/i.test(sig) ? 'low' : 'critical',
    impact: pua || heuristic ? 'suspicious' : 'malicious',
    description: pua
      ? 'ClamAV flags this as a potentially unwanted program (adware, bundleware or a tool that can be misused).'
      : heuristic
        ? 'ClamAV heuristics flag this file as likely malicious, without an exact signature match.'
        : /EICAR/i.test(sig)
          ? 'The harmless antivirus test file, recognised by ClamAV too.'
          : `ClamAV recognises this file as malware (${sig}). Quarantine or delete it.`,
  };
}

/**
 * Scan many files in one ClamAV run (loading the database once).
 * Returns detections keyed by path, or an error string.
 */
export async function clamScanFiles(
  info: ClamInfo,
  files: string[],
  opts: { timeoutMs?: number; signal?: AbortSignal } = {},
): Promise<{ detections: Map<string, AvDetection[]>; error: string | null }> {
  const detections = new Map<string, AvDetection[]>();
  if (!info.available || !info.binary || files.length === 0) return { detections, error: null };
  const dir = await mkdtemp(join(tmpdir(), 'crushav-'));
  const list = join(dir, 'files.txt');
  try {
    // Trailing newline: line readers that stop at EOF would otherwise drop the last file.
    await writeFile(list, `${files.join('\n')}\n`);
    const args = ['--no-summary', '--infected', '--stdout', `--file-list=${list}`];
    if (info.mode === 'clamdscan') args.push('--fdpass', '--multiscan');
    const r = await run(info.binary, args, opts.timeoutMs ?? 60 * 60 * 1000, opts.signal);
    // Exit codes: 0 clean, 1 found, 2 errors (some files unreadable is still 2).
    for (const [path, sigs] of parseClamOutput(r.stdout)) detections.set(path, sigs.map(clamDetection));
    const error = r.code === null || (r.code === 2 && detections.size === 0 && !r.stdout.trim()) ? (r.stderr.trim().split('\n').pop() ?? 'clamav failed') : null;
    return { detections, error };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** How to install ClamAV on this platform, for messages. */
export function clamInstallHint(platform = process.platform): string {
  switch (platform) {
    case 'win32':
      return 'winget install Cisco.ClamAV   (then run "freshclam" once)';
    case 'darwin':
      return 'brew install clamav && cp $(brew --prefix)/etc/clamav/freshclam.conf.sample $(brew --prefix)/etc/clamav/freshclam.conf && sed -i "" "/^Example/d" $(brew --prefix)/etc/clamav/freshclam.conf && freshclam';
    default:
      return 'sudo apt install clamav clamav-daemon   (Fedora: sudo dnf install clamav clamd; Arch: sudo pacman -S clamav)';
  }
}
