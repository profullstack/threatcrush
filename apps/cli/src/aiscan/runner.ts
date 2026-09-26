/**
 * Runs AI red-team probes against an endpoint the operator owns and scores the
 * results into the standard RunResult, mapped to the OWASP LLM Top 10.
 *
 * The transport is injected (`send`), so the scoring logic is pure and testable
 * and the same runner drives a real HTTP endpoint, a local model, or a fake.
 */

import type { RunResult, StructuredFinding, Severity } from '../core/run-result.js';
import { summarize } from '../core/run-result.js';
import { BUILTIN_PROBES, makeCanary, selectProbes, type Probe, type ProbeCategory } from './probes.js';

/** Sends one probe input to the target and returns the model's text reply. */
export type Sender = (input: string) => Promise<string>;

export interface AiScanOptions {
  categories?: ProbeCategory[];
  probes?: Probe[];
  /** Stop after this many probes (0 = all). */
  limit?: number;
  /** ms between probes, to respect a target's rate limits. */
  delayMs?: number;
  onProbe?: (p: Probe, ok: boolean) => void;
}

export interface ProbeResult {
  probe: Probe;
  /** True when the guardrail FAILED (the probe succeeded). */
  vulnerable: boolean;
  response: string;
  error?: string;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export async function runAiScan(
  target: string,
  send: Sender,
  opts: AiScanOptions = {},
): Promise<RunResult> {
  const probes = (opts.probes ?? selectProbes(opts.categories)).slice(
    0,
    opts.limit && opts.limit > 0 ? opts.limit : undefined,
  );

  const results: ProbeResult[] = [];
  for (const probe of probes) {
    const canary = makeCanary();
    let response = '';
    let error: string | undefined;
    let vulnerable = false;
    try {
      response = await send(probe.build(canary));
      vulnerable = probe.detect(response ?? '', canary);
    } catch (err) {
      error = (err as Error).message;
    }
    results.push({ probe, vulnerable, response, error });
    opts.onProbe?.(probe, vulnerable);
    if (opts.delayMs && opts.delayMs > 0) await sleep(opts.delayMs);
  }

  const findings: StructuredFinding[] = results
    .filter((r) => r.vulnerable)
    .map((r) => ({
      type: r.probe.id,
      severity: r.probe.severity as Severity,
      message: `${r.probe.owasp} ${r.probe.title}`,
      location: target,
      details: {
        category: r.probe.category,
        owasp: r.probe.owasp,
        remediation: r.probe.remediation,
        // A short, redacted evidence slice — never the full model output.
        evidence: r.response.slice(0, 200),
      },
    }));

  const counts = summarize(findings);
  const tested = results.length;
  const errored = results.filter((r) => r.error).length;
  const summary =
    findings.length === 0
      ? `No guardrail failures across ${tested} probe(s)${errored ? ` (${errored} errored)` : ''}`
      : `${findings.length}/${tested} probe(s) breached a guardrail: ${counts.critical}C ${counts.high}H ${counts.medium}M ${counts.low}L`;

  return { type: 'scan', target, findings, severity_summary: counts, summary };
}

export { BUILTIN_PROBES };

/**
 * Build a Sender for an HTTP chat/completions-style endpoint.
 *
 * `template` is JSON with a literal `{{PROMPT}}` marker where the probe text
 * goes (JSON-escaped). `responsePath` is a dotted path into the JSON reply
 * (default tries the common shapes) or "text" for a plain-text body.
 */
export function httpSender(cfg: {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  template?: string;
  responsePath?: string;
  timeoutMs?: number;
}): Sender {
  const template = cfg.template ?? '{"input":"{{PROMPT}}"}';
  return async (input: string): Promise<string> => {
    const body = template.replace('{{PROMPT}}', JSON.stringify(input).slice(1, -1));
    const resp = await fetch(cfg.url, {
      method: cfg.method ?? 'POST',
      headers: { 'content-type': 'application/json', ...(cfg.headers ?? {}) },
      body,
      signal: AbortSignal.timeout(cfg.timeoutMs ?? 30_000),
    });
    const raw = await resp.text();
    if (cfg.responsePath === 'text') return raw;
    let json: unknown;
    try { json = JSON.parse(raw); } catch { return raw; }
    if (cfg.responsePath) return String(dig(json, cfg.responsePath) ?? '');
    // Common reply shapes, in order.
    return String(
      dig(json, 'choices.0.message.content') ??
      dig(json, 'choices.0.text') ??
      dig(json, 'message.content') ??
      dig(json, 'content') ??
      dig(json, 'output') ??
      dig(json, 'response') ??
      dig(json, 'text') ??
      raw,
    );
  };
}

function dig(obj: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc == null) return undefined;
    return (acc as Record<string, unknown>)[key];
  }, obj);
}
