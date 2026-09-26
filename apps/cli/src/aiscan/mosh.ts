/**
 * moshscript seam for the AI scanner: run a `.mosh` file as JavaScript with the
 * scanner vocabulary injected as globals. Same model as moshscript.com — "all JS
 * is legal" — so a script can loop, threshold, branch and fail a pipeline on the
 * result instead of scraping stdout.
 *
 *   #!/usr/bin/env threatcrush-mosh
 *   const r = await aiScan(argv[0], { categories: ["prompt-injection"] });
 *   for (const f of r.findings) say(`${f.severity}  ${f.message}`);
 *   if (r.severity_summary.high > 0) fail("prompt injection reachable");
 *
 * The vocabulary is injected via a `with(scope)` Proxy; const/let and real JS
 * fall through to normal scoping, so ordinary JavaScript works unchanged.
 */

import { runAiScan, httpSender, type AiScanOptions } from './runner.js';
import { selectProbes, type ProbeCategory } from './probes.js';
import type { RunResult } from '../core/run-result.js';

const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor as
  new (...args: string[]) => (...args: unknown[]) => Promise<unknown>;

/** Strip a leading `#!…` shebang so `#!/usr/bin/env threatcrush-mosh` files parse. */
export function stripShebang(src: string): string {
  return src.replace(/^﻿?#![^\r\n]*(?:\r?\n|$)/, '');
}

export interface MoshOptions {
  argv?: string[];
  env?: NodeJS.ProcessEnv;
  out?: (s: string) => void;
  /** Default request shape for aiScan(url) when the script passes no template. */
  defaults?: Partial<Parameters<typeof httpSender>[0]>;
}

export interface MoshResult {
  /** Every RunResult the script produced via aiScan(), in call order. */
  scans: RunResult[];
  failed?: string;
}

/** The verbs a `.mosh` script can call bare. */
function makeVocabulary(ctx: {
  out: (s: string) => void;
  scans: RunResult[];
  defaults: MoshOptions['defaults'];
}) {
  return {
    /** Run the scanner against `url`. opts may include a full httpSender config. */
    aiScan: async (
      url: string,
      opts: AiScanOptions & Partial<Parameters<typeof httpSender>[0]> = {},
    ): Promise<RunResult> => {
      const send = httpSender({ url, ...ctx.defaults, ...opts });
      const result = await runAiScan(url, send, opts);
      ctx.scans.push(result);
      return result;
    },
    /** Probe catalogue (metadata only), optionally filtered by category. */
    probes: (categories: ProbeCategory[] = []) =>
      selectProbes(categories).map((p) => ({
        id: p.id, category: p.category, owasp: p.owasp, title: p.title, severity: p.severity,
      })),
    /** Print a line. */
    say: (...parts: unknown[]) => ctx.out(parts.map(String).join(' ')),
    /** Abort the script (non-zero exit) with a reason. */
    fail: (msg: string) => { throw new MoshFail(msg); },
  };
}

class MoshFail extends Error {}

export async function runMosh(source: string, opts: MoshOptions = {}): Promise<MoshResult> {
  const out = opts.out ?? ((s: string) => console.log(s));
  const scans: RunResult[] = [];
  const vocab = makeVocabulary({ out, scans, defaults: opts.defaults });

  const owns = (k: string | symbol) =>
    typeof k === 'string' && (k === 'argv' || k === 'env' || k in vocab);

  const scope = new Proxy(Object.create(null), {
    has(_t, key) {
      if (typeof key === 'symbol') return false; // let Symbol.unscopables fall through
      return owns(key);
    },
    get(_t, key) {
      if (key === 'argv') return opts.argv ?? [];
      if (key === 'env') return opts.env ?? process.env;
      return (vocab as Record<string | symbol, unknown>)[key];
    },
    set() { return false; }, // the vocabulary is read-only
  });

  const body = `with (__scope__) {\n${stripShebang(source)}\n}`;
  const fn = new AsyncFunction('__scope__', body);
  try {
    await fn(scope);
  } catch (err) {
    if (err instanceof MoshFail) return { scans, failed: err.message };
    throw err;
  }
  return { scans };
}
