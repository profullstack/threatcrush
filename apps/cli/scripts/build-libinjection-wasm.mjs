#!/usr/bin/env node
// Builds src/core/crs/libinjection/libinjection.wasm from the vendored
// libinjection C sources (vendor/libinjection, BSD-3-Clause) and
// scripts/libinjection-wasm.c, the interface ThreatCrush calls.
//
//   node scripts/build-libinjection-wasm.mjs          rebuild and write the module
//   node scripts/build-libinjection-wasm.mjs --check  fail if the checked-in module
//                                                     differs from a fresh build
//
// The module is checked in, so building and testing ThreatCrush needs no C
// toolchain; only this script needs zig, at exactly ZIG_VERSION (another
// version compiles different bytes). `zig` is taken from $ZIG or the PATH.
//
// libinjection v4.0.0, commit 211782219663f889f471650150df12b623c5766e of
// github.com/libinjection/libinjection — the commit ModSecurity v3 builds
// against. Its src/ files are vendored unmodified, with COPYING and a subset of
// its test vectors (tests/, data/) that src/core/crs/__tests__ runs.
//
// wasm32-wasi in the reactor model links zig's bundled wasi-libc statically
// and leaves no entry point: libinjection needs only memchr/strlen-style
// functions and malloc, none of which reach the host, so the module imports
// nothing. NDEBUG compiles out libinjection's assert()s, which would otherwise
// pull in WASI's fd_write and proc_exit to report and abort.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_ROOT = join(HERE, '..');
const OUT = join(CLI_ROOT, 'src', 'core', 'crs', 'libinjection', 'libinjection.wasm');

export const ZIG_VERSION = '0.16.0';
export const LIBINJECTION_VERSION = '4.0.0';

// Relative to CLI_ROOT, which is the compiler's working directory, so no
// absolute path can reach the output.
const SOURCES = [
  'vendor/libinjection/src/libinjection_sqli.c',
  'vendor/libinjection/src/libinjection_xss.c',
  'vendor/libinjection/src/libinjection_html5.c',
  'scripts/libinjection-wasm.c',
];
const EXPORTS = ['tc_input', 'tc_sqli', 'tc_fingerprint', 'tc_xss'];

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

function zig(args, options = {}) {
  return execFileSync(process.env.ZIG || 'zig', args, { cwd: CLI_ROOT, encoding: 'utf8', ...options });
}

function build() {
  let version;
  try {
    version = zig(['version']).trim();
  } catch {
    throw new Error(`zig ${ZIG_VERSION} is needed to build libinjection.wasm (set $ZIG or put it on the PATH)`);
  }
  if (version !== ZIG_VERSION) throw new Error(`zig ${ZIG_VERSION} is needed to build libinjection.wasm, found ${version}`);

  const tmp = mkdtempSync(join(tmpdir(), 'libinjection-wasm-'));
  try {
    const bin = join(tmp, 'libinjection.wasm');
    zig([
      'build-exe',
      '-target', 'wasm32-wasi',
      '-mexec-model=reactor',
      '-fno-entry',
      '-O', 'ReleaseFast',
      '-fstrip',
      '-fsingle-threaded',
      '-cflags', '-std=c99', '-DNDEBUG', '-Ivendor/libinjection/src', '--',
      ...SOURCES,
      '-lc',
      ...EXPORTS.map((e) => `--export=${e}`),
      `-femit-bin=${bin}`,
      '--cache-dir', join(tmp, 'cache'),
    ], { stdio: ['ignore', 'inherit', 'inherit'] });
    const bytes = readFileSync(bin);
    const imports = WebAssembly.Module.imports(new WebAssembly.Module(bytes));
    if (imports.length) throw new Error(`libinjection.wasm must import nothing, but imports ${imports.map((i) => `${i.module}.${i.name}`).join(', ')}`);
    return bytes;
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}

function main() {
  const bytes = build();
  console.log(`libinjection ${LIBINJECTION_VERSION}, zig ${ZIG_VERSION}: ${bytes.length} bytes, sha256 ${sha256(bytes)}`);
  if (process.argv.includes('--check')) {
    let current;
    try { current = readFileSync(OUT); } catch { /* missing */ }
    if (!current || sha256(current) !== sha256(bytes)) {
      console.error(`${OUT} (sha256 ${current ? sha256(current) : 'missing'}) is not what the sources build — run scripts/build-libinjection-wasm.mjs`);
      process.exit(1);
    }
    return;
  }
  writeFileSync(OUT, bytes);
  console.log(`wrote ${OUT}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
