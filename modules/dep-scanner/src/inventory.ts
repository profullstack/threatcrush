/**
 * Dependency inventory (PRD 0002 R1–R3, R6).
 *
 * This file exists because of one specific failure. A general-purpose analyzer
 * pointed at a 13-package pnpm workspace reported "0 direct dependencies,
 * 0 circular dependencies, coupling 0/100 (low - good)" — it read the root
 * `package.json`, never resolved `pnpm-workspace.yaml`, found nothing, and
 * called the nothing *good*. For a productivity tool that is an annoyance; for
 * a security tool it is a clean bill of health issued without an examination.
 *
 * So the contract here is:
 *
 *  1. **Resolve the workspace.** A monorepo's dependencies are in its member
 *     manifests, not its root.
 *  2. **Prefer the installed tree.** The lockfile records what *should* be
 *     there; `node_modules` is what will actually execute tonight. Where they
 *     disagree the installed tree wins for reporting, and the disagreement is
 *     itself a finding.
 *  3. **Never let silence read as success.** Every root carries a status of
 *     `parsed | partial | failed` with a reason, and a caller cannot obtain a
 *     package list without also obtaining that status.
 */

import { readdir, readFile, stat } from 'node:fs/promises';
import { basename, join, relative } from 'node:path';

export type ParseStatus = 'parsed' | 'partial' | 'failed';

export interface PackageRecord {
  name: string;
  version: string;
  ecosystem: 'npm';
  /** Present in a manifest's own dependency list, rather than pulled in. */
  direct: boolean;
  /** Reachable only through devDependencies. Ranked down, never hidden. */
  dev: boolean;
  path: string;
}

export interface RootReport {
  root: string;
  status: ParseStatus;
  /** Why a root is partial or failed, in words an operator can act on. */
  reason?: string;
  manifests: number;
  packages: PackageRecord[];
  /** Installed versions that disagree with the lockfile (R3). */
  drift: { name: string; locked: string; installed: string }[];
}

export interface Inventory {
  roots: RootReport[];
  packages: PackageRecord[];
  /** True when any root failed — the caller must not report "clean". */
  incomplete: boolean;
}

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'coverage',
  '.next',
  '.turbo',
  '.cache',
  'vendor',
]);

async function readJson<T>(file: string): Promise<T | null> {
  try {
    return JSON.parse(await readFile(file, 'utf8')) as T;
  } catch {
    return null;
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
}

/**
 * Find project roots: directories holding a `package.json` that are not
 * themselves inside a `node_modules` tree.
 */
export async function findRoots(base: string, maxDepth = 4): Promise<string[]> {
  const roots: string[] = [];

  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > maxDepth) return;
    if (await exists(join(dir, 'package.json'))) roots.push(dir);

    let entries: string[] = [];
    try {
      entries = (await readdir(dir, { withFileTypes: true }))
        .filter((e) => e.isDirectory() && !SKIP_DIRS.has(e.name) && !e.name.startsWith('.'))
        .map((e) => e.name);
    } catch {
      return;
    }

    for (const entry of entries) {
      await walk(join(dir, entry), depth + 1);
    }
  }

  await walk(base, 0);
  return roots;
}

/**
 * Expand workspace globs to member directories.
 *
 * Only the shapes package managers actually emit are handled — `packages/*`,
 * `apps/*`, a literal path, and a trailing `**`. A general glob engine would be
 * a dependency, and this covers npm/pnpm/yarn workspace declarations in
 * practice. Anything unrecognized is reported rather than dropped, because a
 * silently-skipped workspace is the original bug.
 */
export async function expandWorkspaceGlobs(
  root: string,
  patterns: readonly string[],
): Promise<{ dirs: string[]; unresolved: string[] }> {
  const dirs: string[] = [];
  const unresolved: string[] = [];

  for (const raw of patterns) {
    const pattern = raw.trim().replace(/^['"]|['"]$/g, '');
    if (!pattern || pattern.startsWith('!')) continue;

    const star = pattern.indexOf('*');
    if (star === -1) {
      if (await exists(join(root, pattern, 'package.json'))) dirs.push(join(root, pattern));
      continue;
    }

    // "packages/*" and "packages/**" both mean "the directories under packages".
    const prefix = pattern.slice(0, star).replace(/\/$/, '');
    const parent = join(root, prefix);

    let entries: string[];
    try {
      entries = (await readdir(parent, { withFileTypes: true }))
        .filter((e) => e.isDirectory())
        .map((e) => e.name);
    } catch {
      unresolved.push(pattern);
      continue;
    }

    for (const entry of entries) {
      const candidate = join(parent, entry);
      if (await exists(join(candidate, 'package.json'))) dirs.push(candidate);
    }
  }

  return { dirs, unresolved };
}

/** Workspace patterns from `package.json` or `pnpm-workspace.yaml`. */
export async function readWorkspacePatterns(root: string): Promise<string[]> {
  const pkg = await readJson<{ workspaces?: string[] | { packages?: string[] } }>(
    join(root, 'package.json'),
  );
  const fromPkg = Array.isArray(pkg?.workspaces)
    ? pkg?.workspaces
    : (pkg?.workspaces as { packages?: string[] } | undefined)?.packages;
  if (fromPkg?.length) return fromPkg;

  // pnpm-workspace.yaml is a one-key document; a list-item scrape is enough
  // and avoids a YAML dependency. Anything more exotic surfaces as unresolved.
  try {
    const text = await readFile(join(root, 'pnpm-workspace.yaml'), 'utf8');
    const patterns: string[] = [];
    let inPackages = false;

    for (const line of text.split('\n')) {
      if (/^packages:\s*$/.test(line)) {
        inPackages = true;
        continue;
      }
      if (inPackages) {
        const item = /^\s+-\s+(.+?)\s*$/.exec(line);
        if (item?.[1]) patterns.push(item[1]);
        else if (/^\S/.test(line)) inPackages = false;
      }
    }
    return patterns;
  } catch {
    return [];
  }
}

/** Packages recorded by `package-lock.json` (lockfileVersion 2/3). */
export function parsePackageLock(lock: {
  lockfileVersion?: number;
  packages?: Record<string, { version?: string; dev?: boolean; link?: boolean }>;
  dependencies?: Record<string, { version?: string; dev?: boolean }>;
}): PackageRecord[] {
  const out: PackageRecord[] = [];

  if (lock.packages) {
    for (const [path, entry] of Object.entries(lock.packages)) {
      // "" is the root project itself; links are workspace members already
      // covered by their own manifest.
      if (path === '' || entry.link) continue;
      const name = path.replace(/^.*node_modules\//, '');
      if (!name || !entry.version) continue;
      out.push({
        name,
        version: entry.version,
        ecosystem: 'npm',
        direct: !path.slice('node_modules/'.length).includes('node_modules/'),
        dev: Boolean(entry.dev),
        path,
      });
    }
    return out;
  }

  for (const [name, entry] of Object.entries(lock.dependencies ?? {})) {
    if (!entry.version) continue;
    out.push({
      name,
      version: entry.version,
      ecosystem: 'npm',
      direct: true,
      dev: Boolean(entry.dev),
      path: `node_modules/${name}`,
    });
  }
  return out;
}

/** Walk an installed `node_modules`, including scoped packages. */
export async function walkNodeModules(root: string): Promise<PackageRecord[]> {
  const modules = join(root, 'node_modules');
  const found: PackageRecord[] = [];

  let entries: string[];
  try {
    entries = (await readdir(modules, { withFileTypes: true }))
      .filter((e) => e.isDirectory() || e.isSymbolicLink())
      .map((e) => e.name);
  } catch {
    return found;
  }

  for (const entry of entries) {
    if (entry === '.bin' || entry === '.cache') continue;

    if (entry.startsWith('@')) {
      let scoped: string[] = [];
      try {
        scoped = (await readdir(join(modules, entry), { withFileTypes: true }))
          .filter((e) => e.isDirectory() || e.isSymbolicLink())
          .map((e) => e.name);
      } catch {
        continue;
      }
      for (const child of scoped) {
        const record = await readInstalled(modules, `${entry}/${child}`);
        if (record) found.push(record);
      }
      continue;
    }

    if (entry.startsWith('.')) continue;
    const record = await readInstalled(modules, entry);
    if (record) found.push(record);
  }

  return found;
}

async function readInstalled(modules: string, name: string): Promise<PackageRecord | null> {
  const pkg = await readJson<{ name?: string; version?: string }>(
    join(modules, name, 'package.json'),
  );
  if (!pkg?.version) return null;
  return {
    name: pkg.name ?? name,
    version: pkg.version,
    ecosystem: 'npm',
    direct: true,
    dev: false,
    path: join('node_modules', name),
  };
}

/**
 * Inventory one root, including its workspace members.
 *
 * Status is the load-bearing output. `failed` means nothing was read and the
 * caller must not treat the empty package list as good news.
 */
export async function inventoryRoot(root: string): Promise<RootReport> {
  const report: RootReport = {
    root,
    status: 'parsed',
    manifests: 0,
    packages: [],
    drift: [],
  };

  const rootPkg = await readJson<Record<string, unknown>>(join(root, 'package.json'));
  if (!rootPkg) {
    return { ...report, status: 'failed', reason: 'package.json missing or unparseable' };
  }
  report.manifests = 1;

  // Yarn's Plug'n'Play stores the graph in a binary-ish .pnp.cjs with no
  // node_modules to walk. Rather than guess, say so — an unsupported root must
  // read as unexamined, not as clean.
  if (await exists(join(root, '.pnp.cjs'))) {
    return { ...report, status: 'failed', reason: 'Yarn PnP is not supported yet' };
  }

  const patterns = await readWorkspacePatterns(root);
  const { dirs: members, unresolved } = await expandWorkspaceGlobs(root, patterns);
  const notes: string[] = [];
  if (unresolved.length > 0) {
    notes.push(`unresolved workspace patterns: ${unresolved.join(', ')}`);
  }

  const seen = new Map<string, PackageRecord>();
  const add = (record: PackageRecord) => {
    const key = `${record.name}@${record.version}`;
    const existing = seen.get(key);
    if (!existing) seen.set(key, record);
    else if (existing.dev && !record.dev) seen.set(key, record);
  };

  // Declared dependencies of the root and every workspace member.
  for (const dir of [root, ...members]) {
    const manifest = await readJson<{
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    }>(join(dir, 'package.json'));
    if (!manifest) continue;
    if (dir !== root) report.manifests += 1;

    for (const [group, dev] of [
      [manifest.dependencies, false],
      [manifest.devDependencies, true],
    ] as const) {
      for (const [name, range] of Object.entries(group ?? {})) {
        // Workspace protocol members resolve internally and carry no version.
        if (typeof range === 'string' && range.startsWith('workspace:')) continue;
        add({
          name,
          version: String(range).replace(/^[\^~>=<\s]*/, ''),
          ecosystem: 'npm',
          direct: true,
          dev,
          path: relative(root, dir) || '.',
        });
      }
    }
  }

  const lock = await readJson<Parameters<typeof parsePackageLock>[0]>(
    join(root, 'package-lock.json'),
  );
  const locked = lock ? parsePackageLock(lock) : [];
  for (const record of locked) add(record);

  const installed = await walkNodeModules(root);
  for (const record of installed) add(record);

  // Installed-vs-locked divergence: manual hotfixes and tampering live here.
  const lockedBy = new Map(locked.map((r) => [r.name, r.version]));
  for (const record of installed) {
    const lockedVersion = lockedBy.get(record.name);
    if (lockedVersion && lockedVersion !== record.version) {
      report.drift.push({
        name: record.name,
        locked: lockedVersion,
        installed: record.version,
      });
    }
  }

  if (!lock && installed.length === 0) {
    notes.push('no lockfile and no node_modules — only declared ranges were read');
  } else if (!lock) {
    notes.push('no package-lock.json — transitive closure inferred from node_modules');
  }

  report.packages = [...seen.values()];
  if (notes.length > 0) {
    report.status = 'partial';
    report.reason = notes.join('; ');
  }
  if (report.packages.length === 0 && report.status !== 'failed') {
    report.status = 'partial';
    report.reason = report.reason ?? 'no dependencies resolved';
  }

  return report;
}

/** Inventory every root under the configured paths. */
export async function buildInventory(paths: readonly string[], maxDepth = 4): Promise<Inventory> {
  const roots: RootReport[] = [];

  for (const base of paths) {
    for (const root of await findRoots(base, maxDepth)) {
      roots.push(await inventoryRoot(root));
    }
  }

  const packages = new Map<string, PackageRecord>();
  for (const report of roots) {
    for (const record of report.packages) {
      packages.set(`${record.name}@${record.version}`, record);
    }
  }

  return {
    roots,
    packages: [...packages.values()],
    incomplete: roots.some((r) => r.status === 'failed'),
  };
}

export { basename };
