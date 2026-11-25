/**
 * Read-only code tools for explore workers.
 *
 * An explore worker investigates a vulnerability hypothesis against a codebase
 * the operator owns. Its only capabilities are reading that tree: list files,
 * read a bounded slice of a file, and search. No shell, no network, no writes —
 * the engine is a vulnerability-research aid over local source, not an exploit
 * runner. Every path is resolved and confined to the target root; a `..` escape
 * or a symlink pointing outside is refused.
 */

import { readFileSync, readdirSync, statSync, realpathSync } from 'node:fs';
import { join, resolve, relative, sep } from 'node:path';

const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', 'build', '.next', 'coverage', 'vendor', '.venv', '__pycache__']);
const MAX_READ_BYTES = 64_000;
const MAX_LIST = 400;
const MAX_MATCHES = 60;

export class Workspace {
  readonly root: string;

  constructor(root: string) {
    this.root = realpathSync(resolve(root));
    if (!statSync(this.root).isDirectory()) throw new Error(`not a directory: ${root}`);
  }

  /** Resolve a repo-relative path and confine it to the root. */
  private within(rel: string): string {
    const abs = resolve(this.root, rel);
    const rp = (() => {
      try {
        return realpathSync(abs);
      } catch {
        return abs;
      }
    })();
    if (rp !== this.root && !rp.startsWith(this.root + sep)) throw new Error(`path escapes workspace: ${rel}`);
    return abs;
  }

  /** Relative POSIX-ish paths under `dir`, directories suffixed with `/`. */
  list(dir = '.'): string[] {
    const base = this.within(dir);
    const out: string[] = [];
    const walk = (d: string, depth: number): void => {
      if (out.length >= MAX_LIST || depth > 6) return;
      let entries: import('node:fs').Dirent[];
      try {
        entries = readdirSync(d, { withFileTypes: true });
      } catch {
        return;
      }
      for (const e of entries.sort((a, b) => a.name.localeCompare(b.name))) {
        if (e.name.startsWith('.') && e.name !== '.env' && e.name !== '.github') continue;
        if (e.isDirectory() && SKIP_DIRS.has(e.name)) continue;
        const abs = join(d, e.name);
        const rel = relative(this.root, abs);
        if (out.length >= MAX_LIST) return;
        if (e.isDirectory()) {
          out.push(rel + '/');
          walk(abs, depth + 1);
        } else if (e.isFile()) {
          out.push(rel);
        }
      }
    };
    walk(base, 0);
    return out;
  }

  /** Read a file, optionally a line window [from,to] (1-based), capped in size. */
  read(path: string, from?: number, to?: number): string {
    const abs = this.within(path);
    let text: string;
    try {
      text = readFileSync(abs, 'utf-8');
    } catch (e) {
      return `(cannot read ${path}: ${(e as Error).message})`;
    }
    const lines = text.split('\n');
    const start = from && from > 0 ? from : 1;
    const end = to && to >= start ? Math.min(to, lines.length) : lines.length;
    let body = lines.slice(start - 1, end).map((l, n) => `${start + n}| ${l}`).join('\n');
    if (body.length > MAX_READ_BYTES) body = body.slice(0, MAX_READ_BYTES) + '\n… (truncated)';
    return body || '(empty)';
  }

  /** Case-insensitive substring search across text files; returns `path:line: text`. */
  grep(needle: string, dir = '.'): string[] {
    const q = needle.trim();
    if (!q) return [];
    const hits: string[] = [];
    for (const rel of this.list(dir)) {
      if (rel.endsWith('/')) continue;
      if (hits.length >= MAX_MATCHES) break;
      let text: string;
      try {
        text = readFileSync(join(this.root, rel), 'utf-8');
      } catch {
        continue;
      }
      const lines = text.split('\n');
      for (let n = 0; n < lines.length; n += 1) {
        if (lines[n].toLowerCase().includes(q.toLowerCase())) {
          hits.push(`${rel}:${n + 1}: ${lines[n].trim().slice(0, 200)}`);
          if (hits.length >= MAX_MATCHES) break;
        }
      }
    }
    return hits;
  }
}
