import { spawnSync } from 'node:child_process';

/**
 * The oldest Node the daemon can run on. better-sqlite3 13 declares
 * `engines.node >= 22`, and on Node 20 it does not throw — it loads, then
 * segfaults on the first statement. dev1's unit pointed at Node 20.20.2 after a
 * reinstall on 2026-09-26 and crash-looped ~119,000 times over four days,
 * logging nothing but "starting threatcrushd" and banning nobody.
 */
export const MIN_DAEMON_NODE_MAJOR = 22;

/** Major version of a `process.versions.node`-style string, or null. */
export function nodeMajor(version: string | null | undefined): number | null {
  const m = String(version ?? '').trim().replace(/^v/, '').match(/^(\d+)\./);
  return m ? Number(m[1]) : null;
}

/** Why this Node cannot run the daemon, or null when it can. */
export function daemonNodeProblem(version: string | null | undefined): string | null {
  const major = nodeMajor(version);
  if (major === null) return `cannot tell which Node version this is (${version ?? 'unknown'})`;
  if (major >= MIN_DAEMON_NODE_MAJOR) return null;
  return (
    `Node ${version} is too old for threatcrushd (needs ${MIN_DAEMON_NODE_MAJOR}+): ` +
    'its SQLite driver crashes the process with SIGSEGV. Install threatcrush with ' +
    `Node ${MIN_DAEMON_NODE_MAJOR} or newer and re-run threatcrush install-service.`
  );
}

/** The version of the node binary at `path`; the running one when it is ours. */
export function versionOfNode(path: string): string | null {
  if (path === process.execPath) return process.versions.node;
  const res = spawnSync(path, ['-p', 'process.versions.node'], { encoding: 'utf-8', timeout: 5000 });
  return res.status === 0 ? res.stdout.trim() : null;
}
