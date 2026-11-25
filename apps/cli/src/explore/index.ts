/**
 * `threatcrush explore` — a blackboard state-space engine for authorized
 * source-code vulnerability research.
 *
 * A goal-directed search over a codebase you own: from an origin (the repo) the
 * engine grows a Fact/Intent graph toward a goal (find the most serious
 * exploitable weakness), driven by LLM workers that may only read the code.
 * It is a clean-room build of the Fact/Intent/Hint blackboard model — our own
 * code, on `@profullstack/ai-providers` (c0mpute or a local endpoint), scoped to
 * safe, read-only local analysis. It complements `threatcrush redteam` (a
 * linear network pass) with a non-linear, graph-driven code search.
 */

import { basename, resolve } from 'node:path';
import { emptyCounts, summarize, type RunResult, type StructuredFinding } from '../core/run-result.js';
import { buildProvider, describeTarget, type VerifyOptions } from '../scanverify/index.js';
import { Board } from './graph.js';
import { Workspace } from './tools.js';
import { runEngine, type EngineEvents, type EngineResult } from './engine.js';
import type { ToolCall } from './tasks.js';

export { Board } from './graph.js';
export { Workspace } from './tools.js';
export { runEngine } from './engine.js';
export * from './tasks.js';

export interface ExploreOptions {
  /** Default goal when none is given. */
  goal?: string;
  hints?: string[];
  /** OpenAI-compatible endpoint (local Ollama) instead of c0mpute. */
  aiUrl?: string;
  aiKey?: string;
  model?: string;
  maxSteps?: number;
  maxToolCalls?: number;
  /** Per-call model timeout (ms). Default 600s — local CPU models are slow. */
  timeoutMs?: number;
  worker?: string;
  env?: NodeJS.ProcessEnv;
  /** Test seam: a ready-made provider, bypassing c0mpute/endpoint selection. */
  provider?: import('@profullstack/ai-providers').TextProvider;
  onStep?: EngineEvents['onStep'];
  onError?: EngineEvents['onError'];
  onTool?: (call: ToolCall, resultChars: number) => void;
}

export interface ExploreReport {
  result: RunResult;
  engine: EngineResult;
  target: { local: boolean; label: string };
}

const DEFAULT_GOAL = 'Find the single most serious exploitable security vulnerability in this codebase.';

export async function runExploreEngine(dir: string, opts: ExploreOptions = {}): Promise<ExploreReport> {
  const root = resolve(dir);
  const workspace = new Workspace(root);
  const name = basename(root);
  const goal = (opts.goal ?? DEFAULT_GOAL).trim();

  const board = new Board({
    origin: `Source code of the project "${name}" at the repository root. Audit it for exploitable weaknesses.`,
    goal,
    hints: (opts.hints ?? []).map((content) => ({ content, creator: 'human' })),
  });

  const verifyOpts: VerifyOptions = {
    aiUrl: opts.aiUrl,
    aiKey: opts.aiKey,
    model: opts.model,
    env: opts.env,
    provider: opts.provider,
    // Explore turns can be long (a tool loop then an answer); give slow local
    // CPU models room rather than aborting mid-think.
    timeoutMs: opts.timeoutMs ?? 600_000,
  };
  const { provider } = buildProvider(verifyOpts);
  const target = describeTarget(verifyOpts);
  const worker = opts.worker ?? 'explore-1';

  const engine = await runEngine(
    board,
    { provider, workspace, options: { maxToolCalls: opts.maxToolCalls, model: opts.model }, onTool: opts.onTool },
    { worker, maxSteps: opts.maxSteps },
    { onStep: opts.onStep, onError: opts.onError },
  );

  const findings: StructuredFinding[] = engine.findings.map(({ factId, finding }) => ({
    type: finding.title,
    severity: finding.severity,
    message: finding.evidence ? `${finding.title} — ${finding.evidence}` : finding.title,
    location: finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ''}` : undefined,
    details: {
      factId,
      cwe: finding.cwe,
      source: 'explore',
    },
  }));

  const counts = findings.length ? summarize(findings) : emptyCounts();
  const summary = engine.completed
    ? `Goal met in ${engine.steps.length} steps; ${findings.length} finding(s). ${board.derivedFacts().length} facts on the graph.`
    : `Explored ${engine.steps.length} steps; ${findings.length} finding(s); ${board.derivedFacts().length} facts on the graph.`;

  const result: RunResult = {
    type: 'explore',
    target: `${name}`,
    findings,
    severity_summary: counts,
    summary,
    error: engine.errors > 0 && findings.length === 0 && engine.steps.length === 0 ? 'explore produced no steps (worker calls all failed)' : undefined,
  };

  return { result, engine, target };
}
