/**
 * `threatcrush scan --verify`: a model second-reads every rule hit.
 *
 * The rule engine is a set of regexes. On mature repositories it has scored
 * zero true positives in dozens of findings (Go, C, Rust and our own JS), and
 * almost all of those were obvious to a person reading ten lines around the
 * match: a test fixture, a flag name that looks like a secret, a shell call
 * with constant arguments. That reading is what this module automates.
 *
 * For each finding the model gets the rule, the claim, and the surrounding
 * code, and answers true_positive / false_positive / uncertain with a
 * confidence and one sentence of reasoning. A confident false_positive is
 * dismissed from the report (still listed in JSON output, never silently
 * lost); everything else stays, annotated.
 *
 * Where the code goes:
 *   - default: c0mpute (Infernet) peer nodes. Jobs are end-to-end encrypted to
 *     the winning worker, but that worker reads the excerpt in plaintext, so
 *     the CLI says so before sending anything.
 *   - `--ai-url` / THREATCRUSH_AI_URL: any OpenAI-compatible endpoint, e.g. a
 *     local Ollama at http://localhost:11434/v1. Nothing leaves the machine.
 *
 * High-entropy string literals are masked before any excerpt is sent, so a
 * real credential the scan found is described to the model ("a 40-char
 * high-entropy string"), never handed to it.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ScanFinding, Severity } from '@threatcrush/scan';
import { severityRank } from '@threatcrush/scan';
import {
  C0mputeProvider,
  OpenAIProvider,
  extractJson,
  type TextProvider,
} from '@profullstack/ai-providers';

export type Verdict = 'true_positive' | 'false_positive' | 'uncertain' | 'unverified';

export interface Verification {
  verdict: Verdict;
  /** 0..1, the model's own estimate. 0 for unverified. */
  confidence: number;
  reason: string;
  model?: string;
  provider?: string;
}

export interface VerifiedFinding extends ScanFinding {
  verification: Verification;
}

export interface VerifyOptions {
  /** OpenAI-compatible base URL (`http://localhost:11434/v1`). Unset = c0mpute. */
  aiUrl?: string;
  /** Bearer token for `aiUrl`. */
  aiKey?: string;
  /** Model(s), comma-separated; tried in order on c0mpute. */
  model?: string;
  /** Verify at most this many findings, highest severity first. */
  max?: number;
  /** Dismiss a false_positive only at or above this confidence. */
  threshold?: number;
  /** Lines of context either side of the finding. */
  contextLines?: number;
  /** Calls in flight. */
  concurrency?: number;
  env?: NodeJS.ProcessEnv;
  /** Test seam: replaces the provider built from the options above. */
  provider?: TextProvider;
  onProgress?: (done: number, total: number) => void;
}

export interface VerifyReport {
  kept: VerifiedFinding[];
  dismissed: VerifiedFinding[];
  provider: string;
  models: string[];
  /** Findings that went to the model (excludes dependency advisories and over-cap). */
  checked: number;
  /** Calls that failed (transport, refusal, unparseable answer). */
  errors: number;
  /** First failure message, for the operator. */
  firstError?: string;
}

/**
 * Coder model first: triage is reading code. The uncensored 9B is the
 * fallback because a stock model occasionally refuses to discuss whether
 * an injection is exploitable at all, which is the whole question here.
 */
export const DEFAULT_VERIFY_MODELS = [
  'qwen2.5-coder:7b',
  'eriktonon/qwen3.8-uncensored:9b',
  'huihui_ai/qwen3.5-abliterated:9b',
  // Over 4B is GPU and paid on c0mpute. This one is free for keyless runs: slow, but it answers.
  'huihui_ai/qwen3.5-abliterated:4b',
];

export const DEFAULT_THRESHOLD = 0.7;
export const DEFAULT_MAX = 50;

/** Dependency advisories are facts from OSV, not pattern matches: nothing to second-read. */
export function isVerifiable(finding: ScanFinding): boolean {
  return finding.category !== 'dependency';
}

export function describeTarget(opts: VerifyOptions): { local: boolean; label: string } {
  const env = opts.env ?? process.env;
  const url = opts.aiUrl || env.THREATCRUSH_AI_URL;
  if (opts.provider) return { local: false, label: opts.provider.name };
  if (url) return { local: true, label: url };
  return { local: false, label: 'c0mpute peer network (infernetprotocol.com)' };
}

export function buildProvider(opts: VerifyOptions): { provider: TextProvider; models: string[] } {
  const env = opts.env ?? process.env;
  const models = (opts.model || env.THREATCRUSH_AI_MODEL || '')
    .split(',')
    .map((m) => m.trim())
    .filter(Boolean);
  if (opts.provider) return { provider: opts.provider, models };

  const url = opts.aiUrl || env.THREATCRUSH_AI_URL;
  if (url) {
    const model = models[0] || 'qwen2.5-coder:7b';
    return {
      provider: new OpenAIProvider({
        baseUrl: url,
        // Ollama and llama.cpp ignore the token but OpenAIProvider always sends one.
        apiKey: opts.aiKey || env.THREATCRUSH_AI_KEY || 'local',
        model,
        timeoutMs: 180_000,
      }),
      models: [model],
    };
  }

  const chain = models.length ? models : DEFAULT_VERIFY_MODELS;
  return {
    provider: new ModelChain(
      chain.map(
        (model) =>
          new C0mputeProvider({
            apiKey: env.C0MPUTE_API_KEY || env.INFERNET_API_KEY,
            baseUrl: env.C0MPUTE_URL,
            models: [model],
            concurrency: opts.concurrency ?? 4,
            // The free 4B runs on CPU nodes: ~150 s for a short answer.
            timeoutMs: 300_000,
            stallMs: 200_000,
          }),
      ),
      chain,
    ),
    models: chain,
  };
}

/** A model this key cannot use at all, as opposed to one call failing. */
const MODEL_UNAVAILABLE = /paid only|no live node|no node|capacity|not serve/i;

/**
 * C0mputeProvider moves to its next model only on a 503. A model that is
 * "paid only" for a key without balance comes back as a 402-style error and
 * ends the call, so a keyless run never reached the free fallback. This walks
 * the chain itself and remembers which models are out for the whole run.
 */
export class ModelChain implements TextProvider {
  readonly name = 'c0mpute';
  private start = 0;

  constructor(
    private readonly providers: TextProvider[],
    private readonly labels: string[],
  ) {}

  async generate(req: Parameters<TextProvider['generate']>[0]) {
    let last: unknown;
    for (let i = this.start; i < this.providers.length; i += 1) {
      try {
        return await this.providers[i].generate(req);
      } catch (err) {
        last = err;
        if (!MODEL_UNAVAILABLE.test((err as Error).message)) throw err;
        // Skip it for later findings too; concurrent calls may race, harmlessly.
        if (i >= this.start) this.start = i + 1;
      }
    }
    throw last instanceof Error
      ? new Error(`no usable model (${this.labels.join(', ')}): ${last.message}`)
      : new Error('no usable model');
  }
}

// ─── Context + masking ──────────────────────────────────────────────────────

function shannon(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** True for strings that could be key material: long, no spaces, mixed, high entropy. */
export function looksSecret(value: string): boolean {
  if (value.length < 16 || /\s/.test(value)) return false;
  // Paths, URLs without credentials, and dotted identifiers are not secrets.
  if (/^(\.{0,2}\/|https?:\/\/[^:@/]+(\/|$))/.test(value)) return false;
  if (/^[a-z][a-z0-9]*([._-][a-z0-9]+)*$/.test(value)) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(value)).length;
  return classes >= 2 && shannon(value) >= 3.5;
}

function mask(value: string): string {
  return `<masked ${value.length}-char high-entropy string>`;
}

/**
 * Replace anything that could be a credential before the text leaves the box:
 * quoted literals, `KEY=value` assignments, PEM bodies and long base64/hex runs.
 */
export function maskSecrets(text: string): string {
  return text
    .replace(/-----BEGIN [A-Z ]+-----[\s\S]*?(-----END [A-Z ]+-----|$)/g, '<masked PEM block>')
    .replace(/(["'`])((?:\\.|(?!\1)[^\\\n]){16,})\1/g, (all, q: string, body: string) =>
      looksSecret(body) ? `${q}${mask(body)}${q}` : all,
    )
    .replace(/([=:]\s*)([^\s"'`,;)]{16,})/g, (all, sep: string, body: string) =>
      looksSecret(body) ? `${sep}${mask(body)}` : all,
    )
    .replace(/\b[A-Za-z0-9+/_-]{40,}={0,2}/g, (run) => (looksSecret(run) ? mask(run) : run));
}

const fileCache = new Map<string, string[] | null>();

export function contextFor(root: string, finding: ScanFinding, radius: number): string {
  const path = join(root, finding.file);
  let lines = fileCache.get(path);
  if (lines === undefined) {
    try {
      lines = readFileSync(path, 'utf-8').split('\n');
    } catch {
      lines = null;
    }
    fileCache.set(path, lines);
  }
  if (!lines) return maskSecrets(finding.excerpt);
  const at = Math.max(1, finding.line);
  const from = Math.max(1, at - radius);
  const to = Math.min(lines.length, at + radius);
  const out: string[] = [];
  for (let n = from; n <= to; n += 1) {
    const marker = n === at ? '>>' : '  ';
    // Long minified lines blow the context window for nothing.
    out.push(`${marker}${String(n).padStart(5)} | ${lines[n - 1].slice(0, 300)}`);
  }
  return maskSecrets(out.join('\n'));
}

// ─── Prompt + parse ─────────────────────────────────────────────────────────

const SYSTEM = `You are a senior application security engineer triaging static-analysis findings.
A regex-based scanner flagged a line of code. Decide whether it is a REAL, exploitable security issue in this project's own code.

Mark false_positive when, for example:
- the file is a test, fixture, example, mock, benchmark or documentation and the code never ships to production;
- the "secret" is an identifier, flag name, placeholder, env var name, resource name or test value, not a real credential;
- the dangerous call only receives constants or values the attacker cannot control;
- the input is already validated, escaped, parameterised or allow-listed in the visible code;
- the rule matched the wrong construct (a comment, a string, another language's syntax).
- the value comes from this application's own backend (a fetch to its own /api route, a server response field such as checkout_url or redirectUrl, a config constant): that is not attacker input.
Mark true_positive only when you can point at the exact expression in the shown code where attacker data enters (request params/body/headers/query, URL search params, user-supplied file contents, event payloads in CI such as github.event.*.title) AND it reaches the flagged sink, or a real credential is committed.
"Could be attacker-controlled" is NOT evidence. If you cannot quote the source, the verdict is uncertain or false_positive.
Strings shown as <masked ...> were redacted by the tool; a masked high-entropy value in a credential position is evidence of a real secret.

Examples:
- Flagged line: { pattern: /eval\\s*\\(/i, rule: "no-eval" } -> the match is inside a regex literal in a rule table: {"match_is_code":false,"attacker_source":"none","verdict":"false_positive","confidence":0.95,"reason":"eval( appears inside a regex literal, nothing is executed"}
- Flagged line: new Function("specifier", "return import(specifier)") called with "puppeteer" -> constant input: {"match_is_code":true,"attacker_source":"none","verdict":"false_positive","confidence":0.9,"reason":"Function body is a constant and is only called with a literal module name"}
- Flagged line: window.location.href = data.checkout_url where data = await (await fetch('/api/subscribe')).json() -> own backend: {"match_is_code":true,"attacker_source":"none","verdict":"false_positive","confidence":0.85,"reason":"redirect target comes from the app's own API response, not from the user"}
- Flagged line: db.query("SELECT * FROM users WHERE id=" + req.query.id) -> {"match_is_code":true,"attacker_source":"req.query.id","verdict":"true_positive","confidence":0.9,"reason":"query string value is concatenated into SQL"}

Answer with ONLY a JSON object, no prose, keys in this order:
{"match_is_code":true|false,"attacker_source":"exact expression copied from the code, or none","verdict":"true_positive|false_positive|uncertain","confidence":0.0-1.0,"reason":"one sentence"}`;

/** Categories where a real finding needs attacker input to reach a sink. */
function needsSource(finding: ScanFinding): boolean {
  return finding.category === 'code' && !finding.ruleId.startsWith('gha-ssh');
}

/** Reasoning that argues against the verdict it came with. */
const SELF_CONTRADICTION =
  /\bnot (?:attacker[- ]controlled|attacker[- ]influenced|user[- ]supplied|user[- ]controlled|from the user|controlled by (?:the )?(?:user|attacker))\b|\b(?:app(?:lication)?'s|its) own (?:backend|api|server|constants?)\b|\bnever ships?\b|\btest (?:value|file|fixture)\b/i;

function norm(s: string): string {
  return s.replace(/\s+/g, '').replace(/[`'"]/g, '');
}

/**
 * Hold the model to its own evidence. A small model happily says "confirmed"
 * while citing nothing; a true_positive whose quoted source is missing or not
 * in the excerpt it was shown drops to uncertain (kept, never dismissed).
 */
export function enforceEvidence(
  finding: ScanFinding,
  context: string,
  text: string,
  parsed: Omit<Verification, 'model' | 'provider'>,
): Omit<Verification, 'model' | 'provider'> {
  if (parsed.verdict !== 'true_positive') return parsed;
  // Measured on ugig.net: 5 of 11 7B "confirmations" said in the same breath
  // that the value comes from the app's own API and not from the user.
  if (SELF_CONTRADICTION.test(parsed.reason)) {
    return {
      verdict: 'uncertain',
      confidence: Math.min(parsed.confidence, 0.5),
      reason: `model's verdict contradicts its own reasoning: ${parsed.reason}`,
    };
  }
  if (!needsSource(finding)) return parsed;
  let source = '';
  try {
    const obj = extractJson(text) as Record<string, unknown>;
    source = String(obj?.attacker_source ?? '').trim();
  } catch {
    /* fall through: no source */
  }
  const cited = source && !/^(none|n\/a|unknown|null|-)$/i.test(source) && norm(context).includes(norm(source));
  if (cited) return { ...parsed, reason: `${parsed.reason} [source: ${source.slice(0, 80)}]` };
  return {
    verdict: 'uncertain',
    confidence: Math.min(parsed.confidence, 0.5),
    reason: `model claimed a real issue but cited no attacker source in the shown code (${source || 'none'}): ${parsed.reason}`,
  };
}

export function buildPrompt(finding: ScanFinding, context: string): string {
  return [
    `Rule: ${finding.ruleId}${finding.cwe ? ` (${finding.cwe})` : ''}`,
    `Title: ${finding.title}`,
    `Scanner claim: ${finding.message}`,
    `Scanner confidence: ${finding.confidence}; severity: ${finding.severity}`,
    `File: ${finding.file} (flagged line marked >>)`,
    '',
    '```',
    context,
    '```',
  ].join('\n');
}

const VERDICTS = new Set(['true_positive', 'false_positive', 'uncertain']);

export function parseVerdict(text: string): Omit<Verification, 'model' | 'provider'> {
  let raw: unknown;
  try {
    raw = extractJson(text);
  } catch {
    raw = undefined;
  }
  const obj = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  let verdict = String(obj.verdict ?? '')
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
  if (!VERDICTS.has(verdict)) {
    // Small models sometimes answer in words. Read the words, conservatively.
    const t = text.toLowerCase();
    if (/false[\s_-]?positive/.test(t)) verdict = 'false_positive';
    else if (/true[\s_-]?positive/.test(t)) verdict = 'true_positive';
    else throw new Error(`unparseable verdict: ${text.slice(0, 120)}`);
    // An answer we had to guess at never carries enough weight to dismiss.
    return { verdict: verdict as Verdict, confidence: 0.5, reason: text.trim().slice(0, 200) };
  }
  let confidence = Number(obj.confidence);
  if (!Number.isFinite(confidence)) confidence = 0.5;
  if (confidence > 1 && confidence <= 100) confidence /= 100;
  confidence = Math.min(1, Math.max(0, confidence));
  const reason = String(obj.reason ?? '').trim().slice(0, 300) || '(no reason given)';
  return { verdict: verdict as Verdict, confidence, reason };
}

// ─── Driver ─────────────────────────────────────────────────────────────────

async function pool<T>(items: T[], size: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(size, items.length)) }, async () => {
    while (next < items.length) {
      const item = items[next++];
      await fn(item);
    }
  });
  await Promise.all(workers);
}

export async function verifyFindings(
  root: string,
  findings: readonly ScanFinding[],
  opts: VerifyOptions = {},
): Promise<VerifyReport> {
  const { provider, models } = buildProvider(opts);
  const threshold = opts.threshold ?? DEFAULT_THRESHOLD;
  const max = opts.max ?? DEFAULT_MAX;
  const radius = opts.contextLines ?? 20;

  const results = new Map<ScanFinding, Verification>();
  const candidates = findings
    .filter(isVerifiable)
    .sort((a, b) => severityRank(b.severity as Severity) - severityRank(a.severity as Severity))
    .slice(0, max);

  let done = 0;
  let errors = 0;
  let firstError: string | undefined;
  let stop = false;

  await pool(candidates, opts.concurrency ?? 4, async (finding) => {
    if (stop) return;
    try {
      const context = contextFor(root, finding, radius);
      const out = await provider.generate({
        system: SYSTEM,
        user: buildPrompt(finding, context),
        json: true,
        temperature: 0.1,
        maxTokens: 300,
        feature: 'threatcrush-scan-verify',
      });
      const verdict = enforceEvidence(finding, context, out.text, parseVerdict(out.text));
      results.set(finding, { ...verdict, model: out.model, provider: provider.name });
    } catch (err) {
      errors += 1;
      const message = (err as Error).message;
      firstError ??= message;
      // A spent free tier or a dead endpoint fails every call the same way:
      // stop instead of burning the rest of the list on identical errors.
      if (/429|daily limit|ECONNREFUSED|ENOTFOUND|401|403|no usable model/i.test(message)) stop = true;
    } finally {
      done += 1;
      opts.onProgress?.(done, candidates.length);
    }
  });

  const kept: VerifiedFinding[] = [];
  const dismissed: VerifiedFinding[] = [];
  for (const finding of findings) {
    const verification = results.get(finding) ?? {
      verdict: 'unverified' as const,
      confidence: 0,
      reason: isVerifiable(finding)
        ? 'not checked (over --verify-max, or the model call failed)'
        : 'dependency advisory: reported by OSV, not a pattern match',
    };
    const entry = { ...finding, verification };
    if (verification.verdict === 'false_positive' && verification.confidence >= threshold) {
      dismissed.push(entry);
    } else {
      kept.push(entry);
    }
  }

  return {
    kept,
    dismissed,
    provider: provider.name,
    models,
    checked: results.size,
    errors,
    firstError,
  };
}
