import { lstat, opendir } from 'node:fs/promises';
import { join } from 'node:path';
import type { ScanTarget } from './locations';

/**
 * Directories never worth walking: pseudo-filesystems, version-control
 * internals and package caches that are huge, rebuilt from the network, and
 * covered by `threatcrush scan --deps` instead.
 */
export const SKIP_DIR_NAMES = new Set([
  '.git', '.hg', '.svn', 'node_modules', '.pnpm-store', '.npm', '.yarn', '__pycache__', '.venv', 'venv',
  '.cargo', '.rustup', '.gradle', '.m2', '.cache', '.Trash', '$Recycle.Bin', 'System Volume Information',
  '.threatcrush',
]);
export const SKIP_ROOTS = ['/proc', '/sys', '/dev/pts', '/run', '/snap'];

export interface WalkOptions {
  skipDirNames?: Set<string>;
  /** Called for each unreadable entry. */
  onSkip?: (path: string, reason: string) => void;
  signal?: AbortSignal;
}

export interface WalkedFile {
  path: string;
  size: number;
}

/** Yield regular files under each target. Never follows symlinks. */
export async function* walkTargets(targets: ScanTarget[], opts: WalkOptions = {}): AsyncGenerator<WalkedFile> {
  const skip = opts.skipDirNames ?? SKIP_DIR_NAMES;
  const seen = new Set<string>();
  for (const t of targets) {
    let st;
    try {
      st = await lstat(t.path);
    } catch (e) {
      opts.onSkip?.(t.path, (e as NodeJS.ErrnoException).code ?? 'unreadable');
      continue;
    }
    if (st.isFile()) {
      if (!seen.has(t.path)) {
        seen.add(t.path);
        yield { path: t.path, size: st.size };
      }
      continue;
    }
    if (!st.isDirectory()) continue;
    const stack: Array<[string, number]> = [[t.path, 0]];
    while (stack.length) {
      if (opts.signal?.aborted) return;
      const [dir, depth] = stack.pop()!;
      if (SKIP_ROOTS.some((r) => dir === r || dir.startsWith(`${r}/`))) continue;
      let handle;
      try {
        handle = await opendir(dir);
      } catch (e) {
        opts.onSkip?.(dir, (e as NodeJS.ErrnoException).code ?? 'unreadable');
        continue;
      }
      for await (const ent of handle) {
        const p = join(dir, ent.name);
        if (ent.isSymbolicLink()) continue;
        if (ent.isDirectory()) {
          if (depth + 1 < t.depth && !skip.has(ent.name)) stack.push([p, depth + 1]);
          continue;
        }
        if (!ent.isFile() || seen.has(p)) continue;
        seen.add(p);
        try {
          const s = await lstat(p);
          yield { path: p, size: s.size };
        } catch (e) {
          opts.onSkip?.(p, (e as NodeJS.ErrnoException).code ?? 'unreadable');
        }
      }
    }
  }
}

export interface WalkFilesOptions extends WalkOptions {
  /** Directories read at once. Default 8. */
  concurrency?: number;
}

/**
 * Yield regular-file paths under each target, reading several directories at
 * once and never stat-ing files (the scanner `fstat`s what it opens). Built
 * for full-disk scans of millions of files; {@link walkTargets} stays for
 * callers that want sizes.
 *
 * Overlapping targets are walked without listing a file twice: each directory
 * remembers how deep it was walked, and a deeper revisit only descends into
 * the part not seen before.
 */
export async function* walkFiles(targets: ScanTarget[], opts: WalkFilesOptions = {}): AsyncGenerator<string> {
  const skipNames = opts.skipDirNames ?? SKIP_DIR_NAMES;
  const limit = Math.max(1, opts.concurrency ?? 8);
  const HIGH_WATER = 8192;
  const visited = new Map<string, number>();
  const fileTargets = new Set<string>();
  // Deepest first, so a shallow target nested in a deep one is a pure revisit.
  const ordered = [...targets].sort((a, b) => (a.depth === b.depth ? 0 : b.depth > a.depth ? 1 : -1));

  // Single files first, so a directory walk that reaches one can leave it out.
  const dirs: ScanTarget[] = [];
  for (const t of ordered) {
    let st;
    try {
      st = await lstat(t.path);
    } catch (e) {
      opts.onSkip?.(t.path, (e as NodeJS.ErrnoException).code ?? 'unreadable');
      continue;
    }
    if (st.isFile()) {
      if (!fileTargets.has(t.path)) {
        fileTargets.add(t.path);
        yield t.path;
      }
    } else if (st.isDirectory() && t.depth >= 1) dirs.push(t);
  }

  for (const t of dirs) {
    const stack: Array<[string, number]> = [[t.path, t.depth]];
    const out: string[] = [];
    let active = 0;
    let wake: (() => void) | null = null;
    const notify = () => {
      const w = wake;
      wake = null;
      w?.();
    };

    const readDir = async (dir: string, remaining: number, filesToo: boolean) => {
      try {
        const handle = await opendir(dir, { bufferSize: 256 });
        for await (const ent of handle) {
          if (ent.isSymbolicLink()) continue;
          const p = join(dir, ent.name);
          if (ent.isDirectory()) {
            if (remaining > 1 && !skipNames.has(ent.name)) stack.push([p, remaining - 1]);
          } else if (filesToo && ent.isFile() && !fileTargets.has(p)) {
            out.push(p);
            if (out.length >= 512) notify();
          }
        }
      } catch (e) {
        opts.onSkip?.(dir, (e as NodeJS.ErrnoException).code ?? 'unreadable');
      } finally {
        active--;
        notify();
      }
    };

    for (;;) {
      if (opts.signal?.aborted) return;
      while (active < limit && stack.length && out.length < HIGH_WATER) {
        const [dir, remaining] = stack.pop()!;
        if (SKIP_ROOTS.some((r) => dir === r || dir.startsWith(`${r}/`))) continue;
        const before = visited.get(dir);
        if (before !== undefined && before >= remaining) continue;
        visited.set(dir, remaining);
        active++;
        void readDir(dir, remaining, before === undefined);
      }
      if (out.length) {
        for (const p of out.splice(0)) yield p;
        continue;
      }
      if (!active && !stack.length) break;
      await new Promise<void>((resolve) => {
        wake = resolve;
      });
    }
  }
}
