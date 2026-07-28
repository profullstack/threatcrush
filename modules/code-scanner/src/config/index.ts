/**
 * Misconfiguration scanning — the `config` subsystem of `code-scanner`.
 *
 * Implements PRD 0005. This is the subsystem with the least overlap with CI
 * tooling and, for small-team servers, probably the highest yield: a
 * `docker-compose.yml` in a repository says what someone *intended*, while the
 * file on the box — plus what is actually served, plus the permissions on the
 * directory — says what is *true*. Only an agent on the host sees the second.
 *
 * The web-root inference in here is the weakest link and is treated as such:
 * when it cannot determine what is served it reports `unknown` rather than
 * assuming nothing is exposed, because a confident "nothing found" derived from
 * a failed inference is the exact failure this whole module was built to avoid.
 */

export * from './checks.js';

import { open, readdir, stat } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { join } from 'node:path';

import {
  CONVENTIONAL_WEB_ROOTS,
  REACHABILITY_RANK,
  checkComposeFile,
  checkDebugSettings,
  checkMode,
  checkWebserverConfig,
  parseWebRoots,
  rankFindings,
  sensitiveInWebroot,
  type ConfigFinding,
  type Reachability,
} from './checks.js';

export interface ConfigOptions {
  paths: readonly string[];
  maxDepth: number;
  /** Explicit web roots. Empty means infer. */
  webRoots: readonly string[];
  checkPermissions: boolean;
  checkContainers: boolean;
  minReachability: Reachability;
}

export interface ConfigResult {
  findings: ConfigFinding[];
  /** Web roots used, and how they were determined — inference can be wrong. */
  webRoots: { path: string; source: 'configured' | 'parsed' | 'conventional' }[];
  /** True when no web root could be established; exposure checks are then blind. */
  webRootUnknown: boolean;
  filesInspected: number;
}

export const CONFIG_DEFAULTS: ConfigOptions = {
  paths: ['/srv', '/var/www', '/opt', '/etc'],
  maxDepth: 6,
  webRoots: [],
  checkPermissions: true,
  checkContainers: true,
  minReachability: 'local',
};

const WEBSERVER_CONFIGS = [
  '/etc/nginx/nginx.conf',
  '/etc/nginx/sites-enabled',
  '/etc/nginx/conf.d',
  '/etc/apache2/apache2.conf',
  '/etc/apache2/sites-enabled',
  '/etc/httpd/conf/httpd.conf',
];

async function readTextFile(path: string, maxBytes = 2_000_000): Promise<string | null> {
  // Single handle for stat and read, as in the other subsystems: a separate
  // stat leaves a window in which the path can be swapped.
  let handle: FileHandle | undefined;
  try {
    handle = await open(path, 'r');
    if ((await handle.stat()).size > maxBytes) return null;
    return await handle.readFile('utf8');
  } catch {
    return null;
  } finally {
    await handle?.close().catch(() => {
      /* a failed close must not abort the scan */
    });
  }
}

async function listFiles(path: string): Promise<string[]> {
  try {
    const entries = await readdir(path, { withFileTypes: true });
    return entries.filter((e) => e.isFile()).map((e) => join(path, e.name));
  } catch {
    return [];
  }
}

/**
 * Determine what the webserver actually serves.
 *
 * Configured roots win; then directives scraped from nginx/Apache config; then
 * conventional locations that exist on disk. The source is reported alongside
 * because a conventional guess deserves less confidence than a parsed
 * directive, and the operator should be able to see which they got.
 */
export async function resolveWebRoots(
  configured: readonly string[],
): Promise<ConfigResult['webRoots']> {
  if (configured.length > 0) {
    return configured.map((path) => ({ path, source: 'configured' as const }));
  }

  const parsed = new Set<string>();
  for (const location of WEBSERVER_CONFIGS) {
    let files: string[] = [];
    try {
      files = (await stat(location)).isDirectory() ? await listFiles(location) : [location];
    } catch {
      continue;
    }

    for (const file of files) {
      const text = await readTextFile(file);
      if (!text) continue;
      for (const root of parseWebRoots(text)) parsed.add(root);
    }
  }

  if (parsed.size > 0) {
    return [...parsed].map((path) => ({ path, source: 'parsed' as const }));
  }

  const conventional: ConfigResult['webRoots'] = [];
  for (const path of CONVENTIONAL_WEB_ROOTS) {
    try {
      if ((await stat(path)).isDirectory()) {
        conventional.push({ path, source: 'conventional' });
      }
    } catch {
      /* not present */
    }
  }
  return conventional;
}

async function walkEntries(
  dir: string,
  depth: number,
  maxDepth: number,
  out: { path: string; isDirectory: boolean }[],
): Promise<void> {
  if (depth > maxDepth) return;

  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    const path = join(dir, entry.name);
    // `.git` is itself a finding when served, so it is recorded rather than
    // skipped the way the other subsystems skip it.
    out.push({ path, isDirectory: entry.isDirectory() });
    if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.git') {
      await walkEntries(path, depth + 1, maxDepth, out);
    }
  }
}

/** Run the misconfiguration checks. Options in, result out — no ModuleContext. */
export async function scanConfig(options: ConfigOptions): Promise<ConfigResult> {
  const findings: ConfigFinding[] = [];
  const webRoots = await resolveWebRoots(options.webRoots);
  let filesInspected = 0;

  // ---- exposure: sensitive files inside something that is served ----------
  for (const root of webRoots) {
    const entries: { path: string; isDirectory: boolean }[] = [];
    await walkEntries(root.path, 0, options.maxDepth, entries);

    for (const entry of entries) {
      filesInspected += 1;
      const name = entry.path.split('/').pop() ?? '';
      const what = sensitiveInWebroot(name);
      if (!what) continue;

      findings.push({
        checkId: 'sensitive-file-in-webroot',
        title: `${what} inside a served directory`,
        subject: entry.path,
        reachability: 'exposed',
        severity: 'critical',
        consequence: `Anyone who requests this path over HTTP receives the ${what}, including anything it contains.`,
        remediation:
          `Move it above the web root, or deny it in the server config. Then rotate every credential it held — ` +
          `assume it was read. (web root determined by: ${root.source})`,
      });
    }
  }

  // ---- application and container configuration ----------------------------
  for (const base of options.paths) {
    const entries: { path: string; isDirectory: boolean }[] = [];
    await walkEntries(base, 0, Math.min(options.maxDepth, 4), entries);

    for (const entry of entries) {
      if (entry.isDirectory) {
        if (options.checkPermissions) {
          try {
            const info = await stat(entry.path);
            const finding = checkMode({
              path: entry.path,
              mode: info.mode & 0o777,
              isDirectory: true,
            });
            if (finding) findings.push(finding);
          } catch {
            /* unreadable */
          }
        }
        continue;
      }

      const name = entry.path.split('/').pop() ?? '';

      if (/^\.env(\..+)?$/i.test(name)) {
        const text = await readTextFile(entry.path);
        if (text) {
          filesInspected += 1;
          findings.push(...checkDebugSettings(entry.path, text));
        }
      }

      if (options.checkContainers && /^docker-compose\.ya?ml$/i.test(name)) {
        const text = await readTextFile(entry.path);
        if (text) {
          filesInspected += 1;
          findings.push(...checkComposeFile(entry.path, text));
        }
      }

      if (/^(?:nginx\.conf|httpd\.conf|apache2\.conf)$/i.test(name) || /sites-enabled/.test(entry.path)) {
        const text = await readTextFile(entry.path);
        if (text) {
          filesInspected += 1;
          findings.push(...checkWebserverConfig(entry.path, text));
        }
      }

      if (options.checkPermissions && /^\.env|^id_(?:rsa|dsa|ecdsa|ed25519)$|\.pem$|\.key$/i.test(name)) {
        try {
          const info = await stat(entry.path);
          const finding = checkMode({
            path: entry.path,
            mode: info.mode & 0o777,
            isDirectory: false,
          });
          if (finding) findings.push(finding);
        } catch {
          /* unreadable */
        }
      }
    }
  }

  const floor = REACHABILITY_RANK[options.minReachability];
  const visible = findings.filter((f) => REACHABILITY_RANK[f.reachability] >= floor);

  return {
    findings: rankFindings(visible),
    webRoots,
    webRootUnknown: webRoots.length === 0,
    filesInspected,
  };
}
