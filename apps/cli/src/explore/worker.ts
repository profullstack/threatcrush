/**
 * An explore worker: one OODA turn over the board for a single task.
 *
 * The worker observes the board, may make a few read-only tool calls to orient
 * itself in the code, then decides and returns a structured result the engine
 * writes back as Facts/Intents. The model is any `TextProvider` from
 * `@profullstack/ai-providers` — c0mpute by default, or a local OpenAI-compatible
 * endpoint. The worker never acts on anything but {@link Workspace}'s read tools.
 */

import type { TextProvider } from '@profullstack/ai-providers';
import type { Workspace } from './tools.js';
import {
  bootstrapPrompt,
  explorePrompt,
  reasonPrompt,
  parseBootstrap,
  parseExplore,
  parseReason,
  parseToolCall,
  stripThinking,
  SYSTEM,
  type BootstrapResult,
  type ExploreResult,
  type ReasonResult,
  type ToolCall,
} from './tasks.js';

export interface WorkerOptions {
  /** Max read-tool calls before the worker must answer. Default 6. */
  maxToolCalls?: number;
  maxTokens?: number;
  temperature?: number;
  /** Per-call model override, forwarded to ai-providers. */
  model?: string;
}

export interface WorkerContext {
  provider: TextProvider;
  workspace: Workspace;
  options?: WorkerOptions;
  onTool?: (call: ToolCall, resultChars: number) => void;
}

function runTool(ws: Workspace, call: ToolCall): string {
  try {
    if (call.tool === 'list') return ws.list(call.path ?? '.').join('\n') || '(empty)';
    if (call.tool === 'read') return ws.read(call.path ?? '', call.from, call.to);
    if (call.tool === 'grep') return ws.grep(call.needle ?? '', call.path ?? '.').join('\n') || '(no matches)';
  } catch (e) {
    return `(tool error: ${(e as Error).message})`;
  }
  return '(unknown tool)';
}

/**
 * Drive a task to a final answer: send the prompt, service tool calls up to the
 * cap, then hand the last non-tool reply to `parse`. The transcript grows as an
 * assistant/user message pair per tool round, so the model sees what it asked.
 */
async function drive<T>(ctx: WorkerContext, prompt: string, parse: (text: string) => T, feature: string): Promise<T> {
  const opts = ctx.options ?? {};
  const maxTools = opts.maxToolCalls ?? 6;
  const messages: Array<{ role: 'system' | 'user' | 'assistant'; content: string }> = [
    { role: 'system', content: SYSTEM },
    { role: 'user', content: prompt },
  ];
  let lastText = '';
  for (let step = 0; step <= maxTools; step += 1) {
    const out = await ctx.provider.generate({
      messages,
      json: true,
      temperature: opts.temperature ?? 0.2,
      maxTokens: opts.maxTokens ?? 1200,
      models: opts.model ? { c0mpute: opts.model, openai: opts.model } : undefined,
      feature,
    });
    lastText = stripThinking(out.text);
    const call = step < maxTools ? parseToolCall(lastText) : null;
    if (!call) break;
    const result = runTool(ctx.workspace, call);
    ctx.onTool?.(call, result.length);
    messages.push({ role: 'assistant', content: lastText });
    messages.push({ role: 'user', content: `tool result (${call.tool}):\n${result.slice(0, 8000)}\n\nContinue, or give the final answer.` });
  }
  try {
    return parse(lastText);
  } catch (first) {
    // A small/thinking model often spends its budget reasoning and never emits
    // the JSON. Re-ask once, forcefully, for only the object.
    messages.push({ role: 'assistant', content: lastText.slice(0, 2000) });
    messages.push({
      role: 'user',
      content: 'Output ONLY the final JSON object now — no explanation, no reasoning, no <think>. Just the JSON. /no_think',
    });
    const retry = await ctx.provider.generate({
      messages,
      json: true,
      temperature: 0,
      maxTokens: opts.maxTokens ?? 1200,
      models: opts.model ? { c0mpute: opts.model, openai: opts.model } : undefined,
      feature: `${feature}-retry`,
    });
    try {
      return parse(stripThinking(retry.text));
    } catch {
      throw first;
    }
  }
}

export function runBootstrap(ctx: WorkerContext, board: string): Promise<BootstrapResult> {
  return drive(ctx, bootstrapPrompt(board), parseBootstrap, 'explore-bootstrap');
}

export function runExplore(ctx: WorkerContext, board: string, description: string, from: string[]): Promise<ExploreResult> {
  return drive(ctx, explorePrompt(board, description, from), parseExplore, 'explore-explore');
}

export function runReason(ctx: WorkerContext, board: string): Promise<ReasonResult> {
  return drive(ctx, reasonPrompt(board), parseReason, 'explore-reason');
}
