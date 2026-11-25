# `threatcrush explore` — blackboard state-space code audit

`threatcrush redteam` walks a fixed recon → probe → report line against a URL.
`threatcrush explore` is the other shape: a **non-linear, graph-driven search**
over a codebase you own. It is a clean-room implementation of the Fact / Intent /
Hint blackboard model — our own TypeScript, workers driven by
[`@profullstack/ai-providers`](https://profullstack.com) (c0mpute by default, or
a local model), scoped to **read-only** local source analysis. No network, no
shell, no writes: it is a vulnerability-research aid over code you are authorized
to review, not an exploit runner.

## The model

A goal-directed audit is a directed graph that grows from an **origin** (the
repo) toward a **goal** (find the most serious exploitable weakness):

| Primitive | Meaning |
|-----------|---------|
| **Fact** | A confirmed, objective finding. Append-only — a change in state is a *new* fact, so the graph is also an audit log. |
| **Intent** | An edge: one or more source Facts (a hyperedge) pointing at a direction to investigate. Open until it concludes into a result Fact. |
| **Hint** | Off-graph guidance you inject with `--hint`; read by workers, never causal. |

Workers never talk to each other. They read the board and write Facts back —
coordination is stigmergic. Each worker turn is one OODA loop: observe the board,
orient in the code with read-only tools, decide, and conclude a Fact.

## The loop

The engine picks a task from the board's current shape (there are no fixed
roles), runs one worker turn, writes the result back, and repeats until the goal
is met, the step budget is spent, or a reason turn adds nothing new:

1. **Bootstrap** (first step only) — try to find the single most important
   weakness directly and land the key Fact.
2. **Explore** — take one open Intent, investigate it in the code, conclude one
   Fact.
3. **Reason** — read the whole board: is the goal met (complete), what new
   Intents should open, or neither?

A worker may call read-only tools before answering: `list`, `read` (a line
window), `grep` — all confined to the target directory, with `..` and
out-of-root symlinks refused.

## Usage

```bash
threatcrush explore ./src                     # audit a codebase you own
threatcrush explore . --goal "auth bypass in the API" --hint "start at routes/"
threatcrush explore . --graph                 # also print the Fact/Intent graph
threatcrush explore . --ai-url http://localhost:11434/v1 --ai-model qwen2.5-coder:7b
threatcrush explore . --json                  # result + steps + graph
```

| Flag | Default |
|------|---------|
| `--goal <text>` | find the most serious exploitable vulnerability |
| `--hint <text>` (repeatable) | — |
| `--ai-url <url>` / `THREATCRUSH_AI_URL` | c0mpute |
| `--ai-model <models>` / `THREATCRUSH_AI_MODEL` | qwen2.5-coder:7b → uncensored 9B → free 4B |
| `--max-steps <n>` | 12 |
| `--max-tool-calls <n>` | 6 |
| `--graph`, `--json` | off |

## Where the code goes

By default each worker turn sends code excerpts to a c0mpute peer node
(end-to-end encrypted to the one worker that runs it). To keep everything on the
machine, point `--ai-url` at a local Ollama / llama.cpp / vLLM endpoint. The CLI
prints which one it is using. Without a key, c0mpute allows 10 free calls a day
on the small model; set `C0MPUTE_API_KEY` for real runs, or use `--ai-url`.

## Limits

- It is a small-model search, not a proof. Treat concluded Facts as leads.
- Workers only see the window around what they read, so cross-file taint over
  many hops is hard; those directions tend to conclude as dead ends.
- This increment runs one worker at a time (a correct sequential subset of the
  concurrent model) and keeps the whole run local. A hosted/scheduled tier with
  an ownership-proof gate is the next increment.
