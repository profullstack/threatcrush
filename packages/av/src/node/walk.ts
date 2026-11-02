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
