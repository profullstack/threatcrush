// libinjection (github.com/libinjection/libinjection, BSD-3-Clause), compiled
// to WebAssembly by scripts/build-libinjection-wasm.mjs: the SQLi and XSS
// detectors behind CRS's @detectSQLi (942100) and @detectXSS (941100).
//
// The module sits at libinjection/libinjection.wasm beside this file in the
// source tree, and beside the bundle in dist/ (tsup copies it), so one path
// resolves from both. It imports nothing, and is compiled and instantiated
// synchronously, once: when a CrsEngine is built, or on the first detector call.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/** libinjection's injection_result_t: TRUE, FALSE, or ERROR when its parser reached an invalid state. */
export type InjectionResult = 1 | 0 | -1;

export interface SqliResult {
  result: InjectionResult;
  /** The token fingerprint that matched (e.g. `s&1`), when result is TRUE; else empty. */
  fingerprint: string;
}

/** What libinjection.wasm exports (scripts/libinjection-wasm.c). */
export interface LibinjectionModule {
  memory: WebAssembly.Memory;
  _initialize(): void;
  tc_input(n: number): number;
  tc_sqli(n: number): number;
  tc_fingerprint(): number;
  tc_xss(n: number): number;
}

let wasm: LibinjectionModule | undefined;

/** Compiles and instantiates the module, once; the detectors call this themselves. */
export function loadLibinjection(): LibinjectionModule {
  if (!wasm) {
    const bytes = readFileSync(join(__dirname, 'libinjection', 'libinjection.wasm'));
    wasm = new WebAssembly.Instance(new WebAssembly.Module(bytes), {}).exports as unknown as LibinjectionModule;
    wasm._initialize();
  }
  return wasm;
}

/** A view of the module's memory, replaced when the memory grows (which detaches the old buffer). */
let view: Buffer | undefined;

/** Copies a byte string (one char per byte) into the module's input buffer. */
function put(w: LibinjectionModule, bytes: string): void {
  const ptr = w.tc_input(bytes.length);
  if (ptr === 0) throw new Error(`libinjection: cannot allocate ${bytes.length} bytes`);
  if (view?.buffer !== w.memory.buffer) view = Buffer.from(w.memory.buffer);
  view.write(bytes, ptr, bytes.length, 'latin1');
}

/** libinjection_sqli over a byte string (one char per byte). */
export function detectSQLi(bytes: string): SqliResult {
  const w = loadLibinjection();
  put(w, bytes);
  const result = w.tc_sqli(bytes.length) as InjectionResult;
  if (result !== 1) return { result, fingerprint: '' };
  const start = w.tc_fingerprint();
  if (view?.buffer !== w.memory.buffer) view = Buffer.from(w.memory.buffer);
  return { result, fingerprint: view.toString('latin1', start, view.indexOf(0, start)) };
}

/** libinjection_xss over a byte string (one char per byte). */
export function detectXSS(bytes: string): InjectionResult {
  const w = loadLibinjection();
  put(w, bytes);
  return w.tc_xss(bytes.length) as InjectionResult;
}
