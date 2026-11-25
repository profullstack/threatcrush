/**
 * The three task types a worker can run, and how their output is parsed.
 *
 * Every task is executed by the same worker; there are no fixed roles. The
 * task to run is chosen by the engine from the board's current shape:
 *
 *   bootstrap — only at the very start: try to solve the whole problem directly
 *               and land the key proving Fact.
 *   explore   — execute one claimed Intent and return exactly one result Fact.
 *   reason    — read the whole board and decide: is the goal met (complete), or
 *               what new directions (Intents) should be opened, or neither.
 *
 * Prompts are plain strings here (our own wording). A worker answers in JSON; a
 * small model is held to a strict shape by {@link parseWorkerResult}.
 */

import { extractJson } from '@profullstack/ai-providers';

export type TaskType = 'bootstrap' | 'explore' | 'reason';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** A vulnerability a Fact can carry, so the engine can emit it as a finding. */
export interface Finding {
  severity: Severity;
  title: string;
  file?: string;
  line?: number;
  cwe?: string;
  evidence?: string;
}

export interface BootstrapResult {
  /** The key objective fact learned (always recorded, even on partial progress). */
  fact: string;
  /** True only if `fact` already satisfies the goal. */
  complete: boolean;
  supporting?: string[];
  finding?: Finding;
}

export interface ExploreResult {
  /** The single concluding fact for the claimed intent. */
  fact: string;
  finding?: Finding;
}

export interface ReasonResult {
  complete: boolean;
  /** Supporting fact ids when complete. */
  supporting?: string[];
  /** New directions to open when not complete. */
  intents?: Array<{ from: string[]; description: string }>;
}

export const SYSTEM = `You are a methodical application-security researcher auditing a codebase the operator owns and has authorized you to review. You work only from the source you are shown; you never execute code, open network connections, or modify files. You reason about real, exploitable weaknesses — injection, auth bypass, SSRF, path traversal, deserialization, secrets, unsafe sinks reached by attacker-controlled input — and you are precise about whether attacker input actually reaches a sink. You answer strictly in the JSON shape requested, with no prose outside it.`;

/** Preamble letting the worker gather evidence before answering. */
export const TOOL_PROTOCOL = `You may inspect the code before answering. Reply with ONE json object per turn:
- to look first: {"tool":"list","path":"."} or {"tool":"read","path":"src/x.ts","from":1,"to":80} or {"tool":"grep","needle":"exec("}
- when ready: the final answer object described below.
Keep tool use to a few focused calls. Paths are relative to the project root.`;

export function bootstrapPrompt(board: string): string {
  return `${TOOL_PROTOCOL}

The board so far:
${board}

Task: BOOTSTRAP. Try to find the single most important, concrete security weakness in this codebase that moves toward the goal. Investigate, then answer:
{"fact":"<one precise objective finding, with file:line if known>","complete":<true only if this already satisfies the goal>,"supporting":["<fact ids if complete>"],"finding":{"severity":"critical|high|medium|low|info","title":"<short>","file":"<path>","line":<n>,"cwe":"CWE-..","evidence":"<the line>"}}
Omit "finding" if what you found is not itself a vulnerability. Always include "fact".`;
}

export function explorePrompt(board: string, intentDescription: string, intentFrom: string[]): string {
  return `${TOOL_PROTOCOL}

The board so far:
${board}

Task: EXPLORE one direction. Starting from fact(s) [${intentFrom.join(', ')}], carry out this investigation:
"${intentDescription}"
Investigate in the code, then conclude with exactly one new objective fact:
{"fact":"<what you confirmed, with file:line>","finding":{"severity":"..","title":"..","file":"..","line":<n>,"cwe":"..","evidence":".."}}
Omit "finding" if the conclusion is not itself a vulnerability (e.g. a dead end — say so in "fact"). Always include "fact".`;
}

export function reasonPrompt(board: string): string {
  return `${TOOL_PROTOCOL}

The board so far:
${board}

Task: REASON over the whole board. Decide ONE of:
1. The goal is met — {"complete":true,"supporting":["<fact ids that prove it>"]}
2. More to explore — {"complete":false,"intents":[{"from":["<fact id>"],"description":"<a concrete next investigation>"}]}
3. Nothing useful to add right now — {"complete":false,"intents":[]}
Propose at most 3 intents, each a specific, actionable next step grounded in facts already on the board.`;
}

// ─── parsing ───

function obj(text: string): Record<string, unknown> {
  const raw = extractJson(text);
  if (!raw || typeof raw !== 'object') throw new Error(`worker did not return a JSON object: ${text.slice(0, 120)}`);
  return raw as Record<string, unknown>;
}

function cleanSeverity(v: unknown): Severity {
  const s = String(v ?? '').toLowerCase().trim();
  return (SEVERITIES as string[]).includes(s) ? (s as Severity) : 'info';
}

function cleanFinding(v: unknown): Finding | undefined {
  if (!v || typeof v !== 'object') return undefined;
  const o = v as Record<string, unknown>;
  const title = String(o.title ?? '').trim();
  if (!title) return undefined;
  const line = Number(o.line);
  return {
    severity: cleanSeverity(o.severity),
    title: title.slice(0, 200),
    file: o.file ? String(o.file).trim().slice(0, 300) : undefined,
    line: Number.isFinite(line) && line > 0 ? Math.floor(line) : undefined,
    cwe: o.cwe ? String(o.cwe).trim().slice(0, 20) : undefined,
    evidence: o.evidence ? String(o.evidence).trim().slice(0, 300) : undefined,
  };
}

/** A tool request the worker may make mid-turn, or null if this is a final answer. */
export interface ToolCall {
  tool: 'list' | 'read' | 'grep';
  path?: string;
  needle?: string;
  from?: number;
  to?: number;
}

export function parseToolCall(text: string): ToolCall | null {
  let o: Record<string, unknown>;
  try {
    o = obj(text);
  } catch {
    return null;
  }
  const tool = String(o.tool ?? '').toLowerCase();
  if (tool === 'list' || tool === 'read' || tool === 'grep') {
    return {
      tool,
      path: o.path ? String(o.path) : undefined,
      needle: o.needle ? String(o.needle) : undefined,
      from: Number.isFinite(Number(o.from)) ? Number(o.from) : undefined,
      to: Number.isFinite(Number(o.to)) ? Number(o.to) : undefined,
    };
  }
  return null;
}

function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.map((x) => String(x).trim()).filter(Boolean) : [];
}

export function parseBootstrap(text: string): BootstrapResult {
  const o = obj(text);
  const fact = String(o.fact ?? '').trim();
  if (!fact) throw new Error('bootstrap result missing "fact"');
  return { fact, complete: o.complete === true, supporting: strList(o.supporting), finding: cleanFinding(o.finding) };
}

export function parseExplore(text: string): ExploreResult {
  const o = obj(text);
  const fact = String(o.fact ?? '').trim();
  if (!fact) throw new Error('explore result missing "fact"');
  return { fact, finding: cleanFinding(o.finding) };
}

export function parseReason(text: string): ReasonResult {
  const o = obj(text);
  const complete = o.complete === true;
  const intents = Array.isArray(o.intents)
    ? o.intents
        .map((x) => {
          const io = (x ?? {}) as Record<string, unknown>;
          return { from: strList(io.from), description: String(io.description ?? '').trim() };
        })
        .filter((i) => i.from.length > 0 && i.description)
        .slice(0, 3)
    : [];
  return { complete, supporting: strList(o.supporting), intents };
}
