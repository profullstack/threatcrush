/**
 * Planning — turn a surface map into an ordered list of benign probe actions.
 *
 * The default planner is fully DETERMINISTIC: it ranks routes by risk signals
 * (auth/admin/API paths, write methods, user-input forms) and needs no model,
 * no key, nothing to stand up. That is the whole "simpler than ARTEX" point — a
 * red-team run works out of the box.
 *
 * An OPTIONAL c0mpute-backed ranker (`aiPrioritize`) can reorder the queue when
 * the operator explicitly turns it on. Per house policy it only ever calls
 * c0mpute.com; it never falls back to a paid AI provider, and any failure falls
 * back to the deterministic order.
 */

import type { Route, Surface } from './recon.js';

export interface Action {
  method: string;
  path: string;
  url: string;
  reason: string;
  /** 0–100 risk priority; higher is probed first. */
  priority: number;
}

const HIGH_RISK_PATH = /(?:^|\/)(?:admin|login|signin|signup|register|auth|oauth|token|session|password|reset|account|user|users|api|graphql|upload|file|files|download|export|import|config|setting|secret|key|billing|payment|checkout|webhook|internal|debug|actuator|\.env|\.git)(?:\/|$|\?)/i;
const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function scoreRoute(r: Route): { priority: number; reason: string } {
  let score = 10;
  const reasons: string[] = [];
  if (HIGH_RISK_PATH.test(r.path)) { score += 45; reasons.push('sensitive path'); }
  if (WRITE_METHODS.has(r.method)) { score += 25; reasons.push(`${r.method} (write)`); }
  if (r.source === 'openapi') { score += 20; reasons.push('declared API route'); }
  if (r.source === 'form') { score += 15; reasons.push('takes user input'); }
  if (r.source === 'robots') { score += 10; reasons.push('hidden by robots'); }
  return { priority: Math.min(100, score), reason: reasons.join(', ') || 'surface route' };
}

export function planActions(surface: Surface): Action[] {
  const actions = surface.routes.map((r): Action => {
    const { priority, reason } = scoreRoute(r);
    let url = surface.origin + (r.path.startsWith('/') ? r.path : `/${r.path}`);
    try { url = new URL(r.path, surface.origin).toString(); } catch { /* keep */ }
    return { method: r.method, path: r.path, url, reason, priority };
  });
  // Stable sort: priority desc, then path for determinism.
  return actions.sort((a, b) => b.priority - a.priority || a.path.localeCompare(b.path));
}

export interface AiPrioritizeConfig {
  /** c0mpute gateway base, e.g. https://gateway.c0mpute.com. Required to enable. */
  computeUrl: string;
  model?: string;
  apiKey?: string;
  fetchFn?: typeof fetch;
}

/**
 * Optional: ask a c0mpute model to reorder the top candidate paths by likely
 * impact. Returns a new ordering of the SAME actions (never invents routes).
 * On any error or malformed reply, returns the input unchanged. c0mpute only —
 * no paid-provider fallback.
 */
export async function aiPrioritize(actions: Action[], cfg: AiPrioritizeConfig): Promise<Action[]> {
  if (!cfg.computeUrl || actions.length === 0) return actions;
  const f = cfg.fetchFn ?? fetch;
  const list = actions.map((a, i) => `${i}: ${a.method} ${a.path}`).join('\n');
  const prompt =
    `You are a security triage assistant. Given these HTTP routes of a site the operator OWNS, ` +
    `return a JSON array of the indices in the order they should be probed first for likely security ` +
    `impact (most impactful first). Only output the JSON array of integers.\n\n${list}`;
  try {
    const resp = await f(`${cfg.computeUrl.replace(/\/$/, '')}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(cfg.apiKey ? { authorization: `Bearer ${cfg.apiKey}` } : {}),
      },
      body: JSON.stringify({
        model: cfg.model ?? 'default',
        messages: [{ role: 'user', content: prompt }],
        temperature: 0,
      }),
      signal: AbortSignal.timeout(20000),
    });
    if (!resp.ok) return actions;
    const data = (await resp.json()) as { choices?: { message?: { content?: string } }[] };
    const content = data.choices?.[0]?.message?.content ?? '';
    const match = content.match(/\[[\s\S]*?\]/);
    if (!match) return actions;
    const order = JSON.parse(match[0]) as number[];
    const seen = new Set<number>();
    const reordered: Action[] = [];
    for (const i of order) if (Number.isInteger(i) && actions[i] && !seen.has(i)) { seen.add(i); reordered.push(actions[i]); }
    for (let i = 0; i < actions.length; i++) if (!seen.has(i)) reordered.push(actions[i]);
    return reordered;
  } catch {
    return actions;
  }
}
