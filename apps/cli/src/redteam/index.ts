/**
 * Redteam — an autonomous, agentic security pass against a target you own.
 *
 * It mirrors the ARTEX-class loop (recon → prioritise → probe → verify →
 * report) but is deliberately SIMPLER to use: one target, no framework to stand
 * up, deterministic by default, and benign/non-destructive throughout. It
 * reuses the attack-surface map (recon), a risk-ranked plan (plan), and safe
 * probes (execute), then rolls everything into the standard RunResult.
 */

import { emptyCounts, summarize, type RunResult, type StructuredFinding } from '../core/run-result.js';
import { discoverSurface, type Fetcher, type Surface } from './recon.js';
import { planActions, aiPrioritize, type Action, type AiPrioritizeConfig } from './plan.js';
import { executeAction } from './execute.js';

export interface RedteamStep {
  method: string;
  path: string;
  status: number | null;
  findings: number;
  note: string;
}

export interface RedteamOptions {
  /** Max actions to probe (budget). Default 25. */
  maxActions?: number;
  /** Per-request timeout in ms. Default 8000. */
  timeoutMs?: number;
  /** Recon from HTML only (skip specs/robots/sitemap). */
  htmlOnly?: boolean;
  /** Opt-in c0mpute re-ranking of the queue. */
  ai?: AiPrioritizeConfig;
  /** Progress callback. */
  onStep?: (step: RedteamStep, done: number, total: number) => void;
}

export interface RedteamReport {
  result: RunResult;
  surface: Surface;
  steps: RedteamStep[];
}

/** The default fetch adapter (global fetch is structurally a Fetcher). */
export const defaultFetcher: Fetcher = (url, init) => fetch(url, init);

export async function runRedteam(
  target: string,
  fetchFn: Fetcher = defaultFetcher,
  opts: RedteamOptions = {},
): Promise<RedteamReport> {
  const url = target.startsWith('http') ? target : `https://${target}`;
  const surface = await discoverSurface(url, fetchFn, { htmlOnly: opts.htmlOnly });

  let actions: Action[] = planActions(surface);
  if (opts.ai?.computeUrl) actions = await aiPrioritize(actions, opts.ai);

  const budget = opts.maxActions ?? 25;
  const queue = actions.slice(0, budget);

  const steps: RedteamStep[] = [];
  const findings: StructuredFinding[] = [];
  for (let i = 0; i < queue.length; i++) {
    const r = await executeAction(queue[i], fetchFn, { timeoutMs: opts.timeoutMs });
    findings.push(...r.findings);
    const step: RedteamStep = {
      method: queue[i].method,
      path: queue[i].path,
      status: r.status,
      findings: r.findings.length,
      note: r.note,
    };
    steps.push(step);
    opts.onStep?.(step, i + 1, queue.length);
  }

  // De-duplicate identical findings (same type + location).
  const deduped = dedupe(findings);
  const counts = deduped.length ? summarize(deduped) : emptyCounts();
  const result: RunResult = {
    type: 'redteam',
    target: url,
    findings: deduped,
    severity_summary: counts,
    summary:
      `Mapped ${surface.routes.length} route(s), probed ${queue.length}. ` +
      (deduped.length === 0
        ? 'No issues found.'
        : `${deduped.length} finding(s): ${counts.critical}C ${counts.high}H ${counts.medium}M ${counts.low}L ${counts.info}I`),
  };
  return { result, surface, steps };
}

function dedupe(findings: StructuredFinding[]): StructuredFinding[] {
  const seen = new Set<string>();
  const out: StructuredFinding[] = [];
  for (const f of findings) {
    const k = `${f.type}|${f.location ?? ''}|${f.message}`;
    if (!seen.has(k)) { seen.add(k); out.push(f); }
  }
  return out;
}

export * from './recon.js';
export * from './plan.js';
export * from './execute.js';
