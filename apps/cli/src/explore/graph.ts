/**
 * Blackboard graph for `threatcrush explore`.
 *
 * A clean-room reimplementation of the Fact/Intent/Hint model: a goal-directed
 * search is a directed graph that grows from a known `origin` toward a `goal`.
 * Nothing here is copied from any other project — this is our own TypeScript
 * built from the published behavioural contract, and it drives source-code
 * vulnerability research rather than live network attack.
 *
 *   Fact   — a confirmed, objective finding. Append-only; never edited. State
 *            changes are expressed by appending a *new* Fact, never by mutating
 *            an old one, so the graph doubles as an audit log.
 *   Intent — an edge: one or more source Facts (a hyperedge) pointing at an
 *            exploration direction. Open (`to === null`) until it concludes into
 *            a result Fact. Claimed by one worker at a time.
 *   Hint   — off-graph human/strategy input. Not a Fact, not causal; read by
 *            workers for guidance. Allowed even when the project is done.
 *
 * Coordination is stigmergic: workers never talk to each other, only read and
 * write this board. The engine ({@link ../engine}) is the sole writer.
 */

export type ProjectStatus = 'active' | 'stopped' | 'completed';

export interface Fact {
  id: string;
  description: string;
  createdAt: string;
}

export interface Intent {
  id: string;
  /** Source Fact ids — at least one; several makes this a hyperedge. */
  from: string[];
  /** Result Fact id, or null while the intent is still open. */
  to: string | null;
  description: string;
  /** Who declared the direction. Immutable. */
  creator: string;
  /** Current claimant while open; the concluder once closed; null if unclaimed. */
  worker: string | null;
  createdAt: string;
  concludedAt: string | null;
}

export interface Hint {
  id: string;
  content: string;
  creator: string;
  createdAt: string;
}

/** A reserved intent `from: ["origin"]`, `description: "bootstrap"`. */
export const BOOTSTRAP_DESCRIPTION = 'bootstrap';
export const ORIGIN = 'origin';
export const GOAL = 'goal';

export class GraphError extends Error {}

/** Deterministic clock seam so tests don't depend on wall time. */
export type Clock = () => string;
const systemClock: Clock = () => new Date().toISOString();

export class Board {
  status: ProjectStatus = 'active';
  readonly bootstrapEnabled: boolean;
  readonly facts: Fact[] = [];
  readonly intents: Intent[] = [];
  readonly hints: Hint[] = [];

  private readonly clock: Clock;
  private factSeq = 0;
  private intentSeq = 0;
  private hintSeq = 0;

  constructor(opts: {
    origin: string;
    goal: string;
    bootstrapEnabled?: boolean;
    hints?: Array<{ content: string; creator: string }>;
    clock?: Clock;
  }) {
    this.clock = opts.clock ?? systemClock;
    this.bootstrapEnabled = opts.bootstrapEnabled ?? true;
    const now = this.clock();
    this.facts.push({ id: ORIGIN, description: opts.origin.trim(), createdAt: now });
    this.facts.push({ id: GOAL, description: opts.goal.trim(), createdAt: now });
    for (const h of opts.hints ?? []) this.addHint(h.content, h.creator);
  }

  // ─── reads ───

  fact(id: string): Fact | undefined {
    return this.facts.find((f) => f.id === id);
  }

  /** Open intents (no conclusion yet), optionally only the unclaimed ones. */
  openIntents(onlyUnclaimed = false): Intent[] {
    return this.intents.filter((i) => i.to === null && (!onlyUnclaimed || i.worker === null));
  }

  bootstrapIntent(): Intent | undefined {
    return this.intents.find(
      (i) => i.description === BOOTSTRAP_DESCRIPTION && i.from.length === 1 && i.from[0] === ORIGIN,
    );
  }

  /** Facts added by exploration (everything but origin/goal). */
  derivedFacts(): Fact[] {
    return this.facts.filter((f) => f.id !== ORIGIN && f.id !== GOAL);
  }

  // ─── writes (engine only) ───

  addHint(content: string, creator: string): Hint {
    const c = content.trim();
    const who = creator.trim();
    if (!c || !who) throw new GraphError('hint content and creator are required');
    const hint: Hint = { id: `h${++this.hintSeq}`, content: c, creator: who, createdAt: this.clock() };
    this.hints.push(hint);
    return hint;
  }

  private requireActive(): void {
    if (this.status !== 'active') throw new GraphError(`project is ${this.status}, not active`);
  }

  private newFact(description: string): Fact {
    const d = description.trim();
    if (!d) throw new GraphError('fact description is required');
    const fact: Fact = { id: `f${String(++this.factSeq).padStart(3, '0')}`, description: d, createdAt: this.clock() };
    this.facts.push(fact);
    return fact;
  }

  /** Declare an exploration direction. `worker` may claim it immediately. */
  declareIntent(from: string[], description: string, creator: string, worker: string | null = null): Intent {
    this.requireActive();
    const src = from.map((s) => s.trim()).filter(Boolean);
    if (src.length === 0) throw new GraphError('intent needs at least one source fact');
    for (const id of src) if (!this.fact(id)) throw new GraphError(`unknown source fact: ${id}`);
    const who = creator.trim();
    if (!who) throw new GraphError('intent creator is required');
    if (worker !== null && worker !== who) throw new GraphError('a claiming creator must be its own worker');
    const now = this.clock();
    const intent: Intent = {
      id: `i${String(++this.intentSeq).padStart(3, '0')}`,
      from: src,
      to: null,
      description: description.trim() || '(no description)',
      creator: who,
      worker: worker ? who : null,
      createdAt: now,
      concludedAt: null,
    };
    this.intents.push(intent);
    return intent;
  }

  /** Claim or renew an open intent. Unclaimed → anyone; claimed → only the holder. */
  claimIntent(id: string, worker: string): Intent {
    this.requireActive();
    const intent = this.mustOpen(id);
    const who = worker.trim();
    if (!who) throw new GraphError('worker is required');
    if (intent.worker !== null && intent.worker !== who) throw new GraphError(`intent ${id} is held by ${intent.worker}`);
    intent.worker = who;
    return intent;
  }

  /** Give up an open intent so another worker can take it. */
  releaseIntent(id: string, worker: string): Intent {
    this.requireActive();
    const intent = this.mustOpen(id);
    if (intent.worker !== null && intent.worker !== worker.trim()) {
      throw new GraphError(`intent ${id} is held by ${intent.worker}`);
    }
    intent.worker = null;
    return intent;
  }

  /** Close an open intent atomically, producing one result Fact. */
  concludeIntent(id: string, worker: string, resultDescription: string): { intent: Intent; fact: Fact } {
    this.requireActive();
    const intent = this.mustOpen(id);
    const who = worker.trim();
    if (intent.worker !== null && intent.worker !== who) throw new GraphError(`intent ${id} is held by ${intent.worker}`);
    const fact = this.newFact(resultDescription);
    intent.to = fact.id;
    intent.worker = who || intent.worker || intent.creator;
    intent.concludedAt = this.clock();
    return { intent, fact };
  }

  /** Declare the goal met: a concluded intent from `supporting` facts to `goal`. */
  complete(supporting: string[], worker: string): Intent {
    this.requireActive();
    const src = supporting.map((s) => s.trim()).filter(Boolean);
    if (src.length === 0) throw new GraphError('complete needs at least one supporting fact');
    for (const id of src) if (!this.fact(id)) throw new GraphError(`unknown supporting fact: ${id}`);
    const who = worker.trim() || 'engine';
    const now = this.clock();
    const intent: Intent = {
      id: `i${String(++this.intentSeq).padStart(3, '0')}`,
      from: src,
      to: GOAL,
      description: 'complete',
      creator: who,
      worker: who,
      createdAt: now,
      concludedAt: now,
    };
    this.intents.push(intent);
    this.status = 'completed';
    return intent;
  }

  /** Undo a completion: drop the goal edge, record a correction Fact, go active. */
  reopen(correction: string, creator: string): Fact {
    if (this.status !== 'completed') throw new GraphError('only a completed project can be reopened');
    const edgeIdx = this.intents.findIndex((i) => i.to === GOAL);
    const inherited = edgeIdx >= 0 ? this.intents[edgeIdx].from : [ORIGIN];
    if (edgeIdx >= 0) this.intents.splice(edgeIdx, 1);
    this.status = 'active';
    const fact = this.newFact(correction);
    const now = this.clock();
    this.intents.push({
      id: `i${String(++this.intentSeq).padStart(3, '0')}`,
      from: inherited,
      to: fact.id,
      description: 'external_feedback',
      creator: creator.trim() || 'human',
      worker: creator.trim() || 'human',
      createdAt: now,
      concludedAt: now,
    });
    return fact;
  }

  setStatus(status: 'active' | 'stopped'): void {
    if (this.status === 'completed') throw new GraphError('completed project must be reopened, not set');
    if (status === 'stopped') {
      for (const i of this.openIntents()) i.worker = null;
    }
    this.status = status;
  }

  private mustOpen(id: string): Intent {
    const intent = this.intents.find((i) => i.id === id);
    if (!intent) throw new GraphError(`unknown intent: ${id}`);
    if (intent.to !== null) throw new GraphError(`intent ${id} is already concluded`);
    return intent;
  }

  /** A compact, human- and model-readable snapshot of the whole board. */
  render(): string {
    const lines: string[] = [];
    for (const f of this.facts) lines.push(`${f.id}: ${f.description}`);
    for (const i of this.intents) {
      const arrow = i.to ? `→ ${i.to}` : '→ (open)';
      const held = i.worker ? ` [${i.worker}]` : '';
      lines.push(`${i.id}: {${i.from.join(',')}} ${arrow} ${i.description}${held}`);
    }
    for (const h of this.hints) lines.push(`${h.id} (hint/${h.creator}): ${h.content}`);
    return lines.join('\n');
  }
}
