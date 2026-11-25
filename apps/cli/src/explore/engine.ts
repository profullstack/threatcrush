/**
 * The explore engine: the OODA scheduler loop over a {@link Board}.
 *
 * On each step it picks a task from the board's current shape — exactly the
 * stigmergic scheduling the blackboard model calls for — runs one worker turn,
 * and writes the result back as Facts/Intents. It is the sole writer to the
 * board. This MVP runs one worker at a time (a correct sequential subset of the
 * concurrent model); the task choice is:
 *
 *   1. initial board + bootstrap enabled  → bootstrap
 *   2. an unclaimed open intent exists      → explore it
 *   3. otherwise                            → reason (open intents or complete)
 *
 * The loop ends when the goal is declared met, the step budget is spent, or a
 * reason turn adds no new intents and none are open — a fixed point.
 */

import { Board, BOOTSTRAP_DESCRIPTION, ORIGIN } from './graph.js';
import type { Finding } from './tasks.js';
import { runBootstrap, runExplore, runReason, type WorkerContext } from './worker.js';

/** Keep only ids that name a real fact; if none survive, use `fallback`. */
function knownFacts(board: Board, ids: string[] | undefined, fallback: string[]): string[] {
  const real = (ids ?? []).filter((id) => board.fact(id));
  return real.length > 0 ? real : fallback;
}

export interface EngineOptions {
  worker: string;
  /** Max scheduler steps before stopping. Default 12. */
  maxSteps?: number;
}

export type StepKind = 'bootstrap' | 'explore' | 'reason';

export interface EngineStep {
  step: number;
  kind: StepKind;
  /** The fact id produced, the intents opened, or a note. */
  outcome: string;
  findingSeverity?: Finding['severity'];
}

export interface EngineEvents {
  onStep?: (step: EngineStep) => void;
  onError?: (kind: StepKind, message: string) => void;
}

export interface EngineResult {
  board: Board;
  steps: EngineStep[];
  /** (factId, finding) pairs gathered from concluded facts. */
  findings: Array<{ factId: string; finding: Finding }>;
  completed: boolean;
  errors: number;
}

export async function runEngine(
  board: Board,
  ctx: Omit<WorkerContext, 'options'> & { options?: WorkerContext['options'] },
  opts: EngineOptions,
  events: EngineEvents = {},
): Promise<EngineResult> {
  const worker = opts.worker;
  const maxSteps = opts.maxSteps ?? 12;
  const steps: EngineStep[] = [];
  const findings: EngineResult['findings'] = [];
  let errors = 0;

  const record = (kind: StepKind, outcome: string, finding?: Finding): void => {
    const step: EngineStep = { step: steps.length + 1, kind, outcome, findingSeverity: finding?.severity };
    steps.push(step);
    events.onStep?.(step);
  };

  for (let i = 0; i < maxSteps && board.status === 'active'; i += 1) {
    const initial = board.derivedFacts().length === 0 && board.openIntents().length === 0 && !board.bootstrapIntent();

    try {
      if (initial && board.bootstrapEnabled) {
        const intent = board.declareIntent([ORIGIN], BOOTSTRAP_DESCRIPTION, worker, worker);
        const r = await runBootstrap(ctx, board.render());
        const { fact } = board.concludeIntent(intent.id, worker, r.fact);
        if (r.finding) findings.push({ factId: fact.id, finding: r.finding });
        record('bootstrap', `${fact.id}${r.complete ? ' (claims goal met)' : ''}`, r.finding);
        // Small models sometimes cite an intent id where a fact id belongs;
        // keep only real facts, and fall back to the fact we just concluded.
        if (r.complete) board.complete(knownFacts(board, r.supporting, [fact.id]), worker);
        continue;
      }

      const open = board.openIntents(true);
      if (open.length > 0) {
        const intent = board.claimIntent(open[0].id, worker);
        const r = await runExplore(ctx, board.render(), intent.description, intent.from);
        const { fact } = board.concludeIntent(intent.id, worker, r.fact);
        if (r.finding) findings.push({ factId: fact.id, finding: r.finding });
        record('explore', `${intent.id} → ${fact.id}`, r.finding);
        continue;
      }

      const r = await runReason(ctx, board.render());
      const support = knownFacts(board, r.supporting, []);
      if (r.complete && support.length > 0) {
        board.complete(support, worker);
        record('reason', `complete via ${support.join(', ')}`);
        break;
      }
      // Keep only intents whose source facts actually exist on the board.
      const grounded = (r.intents ?? []).map((it) => ({ ...it, from: knownFacts(board, it.from, []) })).filter((it) => it.from.length > 0);
      if (grounded.length > 0) {
        const ids = grounded.map((it) => board.declareIntent(it.from, it.description, worker).id);
        record('reason', `opened ${ids.join(', ')}`);
        continue;
      }
      record('reason', 'no new directions — fixed point');
      break;
    } catch (e) {
      errors += 1;
      const kind: StepKind = initial && board.bootstrapEnabled ? 'bootstrap' : board.openIntents(true).length ? 'explore' : 'reason';
      events.onError?.(kind, (e as Error).message);
      // A worker/parse failure on one step shouldn't abort the whole run; but a
      // provider that fails every call (auth, dead endpoint) would spin, so bail
      // once errors outnumber useful steps.
      if (errors > Math.max(2, steps.length)) break;
    }
  }

  return { board, steps, findings, completed: board.status === 'completed', errors };
}
