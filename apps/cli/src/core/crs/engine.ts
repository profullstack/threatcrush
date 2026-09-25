// Evaluates the ported OWASP CRS rules (rules.generated.ts) against a request
// reconstructed from an access-log line, with CRS anomaly scoring: every rule
// that matches adds its severity's points, and the request is an attack when
// the total reaches the inbound threshold (CRS default 5, one CRITICAL rule).
// ThreatCrush's own rules (THREATCRUSH_RULES, ids 10000-10999) are scored the
// same way, alongside CRS but not counted as CRS.
//
// Semantics follow ModSecurity v2: ARGS are the query-string arguments split on
// `&` and URL-decoded; REQUEST_FILENAME, QUERY_STRING and REQUEST_URI_RAW are
// as sent; operators see byte strings. One deliberate difference: ModSecurity
// adds a rule's score once per matching variable, this adds it once per rule —
// the score decides bans, so it errs low.

import { CRS_RULES, THREATCRUSH_RULES } from './rules.generated.js';
import { TRANSFORMS, lowercase } from './transforms.js';
import type { CrsChainLink, CrsOperator, CrsRule, CrsSeverity, CrsTarget } from './types.js';

export const SEVERITY_POINTS: Record<CrsSeverity, number> = { CRITICAL: 5, ERROR: 4, WARNING: 3, NOTICE: 2 };

/** CRS's default inbound anomaly score threshold. */
export const DEFAULT_ANOMALY_THRESHOLD = 5;

/**
 * Ported rules that are off unless re-enabled (`[detection] include_rules`):
 * faithful CRS, but with bans automatic they would ban ordinary visitors.
 *
 * - 941130: matches `xhtml` in REQUEST_FILENAME, so every request for a
 *   `*.xhtml` page (JSF and other Java sites) scores as XSS.
 */
export const DEFAULT_EXCLUDED_RULE_IDS: readonly number[] = [941130];

/** What callers see as the attack type, from a rule's first recognised `attack-*` tag. */
const ATTACK_TYPES: Record<string, string> = {
  'attack-sqli': 'sqli',
  'attack-xss': 'xss',
  'attack-lfi': 'path_traversal',
  'attack-rfi': 'rfi',
  'attack-rce': 'rce',
  'attack-injection-php': 'php_injection',
  'attack-ssrf': 'ssrf',
  'attack-ssti': 'ssti',
  'attack-reputation-scanner': 'scanner',
  'attack-injection-generic': 'injection',
};

/** The attack type a matching rule credits its points to, or null for none. */
export function crsAttackType(rule: Pick<CrsRule, 'tags'>): string | null {
  return rule.tags.map((t) => ATTACK_TYPES[t]).find((t) => t !== undefined) ?? null;
}

/** The parts of an HTTP request an access log records. Strings are bytes, one char per byte. */
export interface HttpRequestView {
  method?: string;
  /** The request target exactly as sent, e.g. `/search?q=1`. */
  uri: string;
  protocol?: string;
  userAgent?: string;
  referer?: string;
}

export interface CrsMatch {
  id: number;
  msg: string;
  severity: CrsSeverity;
  tags: string[];
}

export interface CrsAssessment {
  score: number;
  threshold: number;
  /** The attack type carrying the most points, or null when nothing matched. */
  attackType: string | null;
  matches: CrsMatch[];
}

export interface CrsEngineOptions {
  /** Inbound anomaly threshold. Defaults to CRS's 5. */
  threshold?: number;
  /** Rule ids (CRS or ThreatCrush) to leave out, as SecRuleRemoveById would. Defaults to DEFAULT_EXCLUDED_RULE_IDS. */
  excludeRuleIds?: Iterable<number>;
}

// ------------------------------------------------------------ phrase matching

/** Aho-Corasick over ASCII-lowercased bytes: @pm's case-insensitive substring match. */
class PhraseMatcher {
  private readonly next: Array<Map<number, number>> = [new Map()];
  private readonly fail: number[] = [0];
  private readonly terminal: boolean[] = [false];

  constructor(phrases: readonly string[]) {
    for (const phrase of phrases) {
      const p = lowercase(phrase);
      let node = 0;
      for (let i = 0; i < p.length; i++) {
        const c = p.charCodeAt(i);
        let child = this.next[node].get(c);
        if (child === undefined) {
          child = this.next.length;
          this.next.push(new Map());
          this.fail.push(0);
          this.terminal.push(false);
          this.next[node].set(c, child);
        }
        node = child;
      }
      this.terminal[node] = true;
    }
    const queue: number[] = [...this.next[0].values()];
    for (let q = 0; q < queue.length; q++) {
      const node = queue[q];
      for (const [c, child] of this.next[node]) {
        let f = this.fail[node];
        while (f !== 0 && !this.next[f].has(c)) f = this.fail[f];
        const target = this.next[f].get(c);
        this.fail[child] = target !== undefined && target !== child ? target : 0;
        if (this.terminal[this.fail[child]]) this.terminal[child] = true;
        queue.push(child);
      }
    }
  }

  test(value: string): boolean {
    let node = 0;
    for (let i = 0; i < value.length; i++) {
      let c = value.charCodeAt(i);
      if (c >= 0x41 && c <= 0x5a) c += 0x20; // tolower, C locale
      let child = this.next[node].get(c);
      while (child === undefined && node !== 0) {
        node = this.fail[node];
        child = this.next[node].get(c);
      }
      node = child ?? 0;
      if (this.terminal[node]) return true;
    }
    return false;
  }
}

function compileOperator(op: CrsOperator): (value: string) => boolean {
  let test: (value: string) => boolean;
  switch (op.type) {
    case 'rx': {
      const re = new RegExp(op.source, op.flags);
      test = (v) => re.test(v);
      break;
    }
    case 'pm': {
      const matcher = new PhraseMatcher(op.phrases);
      test = (v) => matcher.test(v);
      break;
    }
    case 'contains': test = (v) => v.includes(op.arg); break;
    case 'streq': test = (v) => v === op.arg; break;
    case 'beginsWith': test = (v) => v.startsWith(op.arg); break;
    case 'endsWith': test = (v) => v.endsWith(op.arg); break;
    case 'within': test = (v) => op.arg.includes(v); break;
  }
  return op.negated ? (v) => !test(v) : test;
}

// ------------------------------------------------------------ the request

/** One variable's value and the transformation results computed for it so far. */
interface Slot {
  value: string;
  cache: Map<string, string>;
}

/** Port of ModSecurity's parse_arguments + urldecode_nonstrict for a query string. */
function parseArguments(query: string): Array<{ name: string; value: string }> {
  const args: Array<{ name: string; value: string }> = [];
  if (query.length === 0) return args;
  for (const piece of query.split('&')) {
    const eq = piece.indexOf('=');
    const name = eq === -1 ? piece : piece.slice(0, eq);
    const value = eq === -1 ? '' : piece.slice(eq + 1);
    args.push({ name: urlDecode(name), value: urlDecode(value) });
  }
  // `a&` ends on a separator: ModSecurity adds no trailing empty argument.
  if (query.endsWith('&')) args.pop();
  return args;
}

/** urldecode_nonstrict_inplace_ex: %XX and `+`, leaving invalid escapes as they are. */
function urlDecode(s: string): string {
  if (!s.includes('%') && !s.includes('+')) return s;
  return s.replace(/\+|%([0-9A-Fa-f]{2})/g, (m, hex: string | undefined) => (hex ? String.fromCharCode(parseInt(hex, 16)) : ' '));
}

const ABSOLUTE_FORM = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*/;

class RequestContext {
  private readonly slots = new Map<CrsTarget, Slot[]>();

  constructor(private readonly req: HttpRequestView) {}

  values(target: CrsTarget): Slot[] {
    let slots = this.slots.get(target);
    if (!slots) {
      slots = this.derive(target).map((value) => ({ value, cache: new Map() }));
      this.slots.set(target, slots);
    }
    return slots;
  }

  private derive(target: CrsTarget): string[] {
    const { uri } = this.req;
    // apr_uri_parse: path up to ? or #, query up to #, authority dropped.
    const relative = uri.replace(ABSOLUTE_FORM, '');
    const q = relative.search(/[?#]/);
    const path = q === -1 ? relative : relative.slice(0, q);
    const hasQuery = q !== -1 && relative[q] === '?';
    const query = hasQuery ? relative.slice(q + 1).split('#')[0] : undefined;
    switch (target) {
      case 'REQUEST_LINE':
        return this.req.method && this.req.protocol ? [`${this.req.method} ${uri} ${this.req.protocol}`] : [];
      case 'REQUEST_URI_RAW':
        return [uri];
      case 'REQUEST_FILENAME':
        return [path];
      case 'QUERY_STRING':
        return query === undefined ? [] : [query];
      case 'ARGS':
        return query === undefined ? [] : parseArguments(query).map((a) => a.value);
      case 'ARGS_NAMES':
        return query === undefined ? [] : parseArguments(query).map((a) => a.name);
      case 'REQUEST_HEADERS:User-Agent':
        return this.req.userAgent === undefined ? [] : [this.req.userAgent];
      case 'REQUEST_HEADERS:Referer':
        return this.req.referer === undefined ? [] : [this.req.referer];
    }
  }
}

// ------------------------------------------------------------ rules

interface CompiledLink {
  link: CrsChainLink;
  test: (value: string) => boolean;
}

interface CompiledRule {
  index: number;
  rule: CrsRule;
  test: (value: string) => boolean;
  /** Cache key for the value after each transformation step. */
  stepKeys: string[];
  chain: CompiledLink[];
  attackType: string | null;
}

function transformed(slot: Slot, rule: CompiledRule, step: number): string {
  if (step < 0) return slot.value;
  const key = rule.stepKeys[step];
  let v = slot.cache.get(key);
  if (v === undefined) {
    v = TRANSFORMS[rule.rule.transforms[step]](transformed(slot, rule, step - 1));
    slot.cache.set(key, v);
  }
  return v;
}

/**
 * Runs a rule's operator on one variable, pushing each value it matched. With
 * multiMatch the operator runs on the original value and again after every
 * transformation that changed it; otherwise once, on the fully transformed value.
 */
function matchSlot(rule: CompiledRule, slot: Slot, matched: string[], firstOnly: boolean): void {
  const last = rule.rule.transforms.length - 1;
  if (!rule.rule.multiMatch) {
    const v = transformed(slot, rule, last);
    if (rule.test(v)) matched.push(v);
    return;
  }
  let prev: string | undefined;
  for (let step = -1; step <= last; step++) {
    const v = transformed(slot, rule, step);
    if (v === prev) continue;
    prev = v;
    if (rule.test(v)) {
      matched.push(v);
      if (firstOnly) return;
    }
  }
}

/** A chained rule: its head's matches (MATCHED_VARS) feed each link in turn. */
function chainMatches(rule: CompiledRule, ctx: RequestContext): boolean {
  const matched: string[] = [];
  for (const target of rule.rule.targets) {
    for (const slot of ctx.values(target)) matchSlot(rule, slot, matched, false);
  }
  if (matched.length === 0) return false;
  for (const { link, test } of rule.chain) {
    const candidates = link.target === 'MATCHED_VAR' ? [matched[matched.length - 1]] : [...matched];
    let any = false;
    for (const candidate of candidates) {
      let v = candidate;
      for (const t of link.transforms) v = TRANSFORMS[t](v);
      if (test(v)) {
        matched.push(v);
        any = true;
      }
    }
    if (!any) return false;
  }
  return true;
}

/** Bytes, one char per byte: anything above U+00FF is re-encoded as its UTF-8. */
function asBytes(s: string): string;
function asBytes(s: string | undefined): string | undefined;
function asBytes(s: string | undefined): string | undefined {
  if (s === undefined || !/[^\x00-\xff]/.test(s)) return s;
  return Buffer.from(s, 'utf8').toString('latin1');
}

// Whether an unchained rule matches depends on nothing but the value it looks
// at, and log traffic repeats values endlessly (the same User-Agent, the same
// paths). So the rules a value matches are remembered per target and value.
// Values longer than MEMO_MAX_VALUE are evaluated every time.
const MEMO_ENTRIES = 10_000;
const MEMO_MAX_VALUE = 512;

export class CrsEngine {
  readonly threshold: number;
  /** How many rules are loaded, by origin: ported OWASP CRS, and ThreatCrush's own. */
  readonly ruleCounts: { crs: number; threatcrush: number };
  private readonly rules: CompiledRule[];
  /** Unchained rules by the targets they read. */
  private readonly byTarget = new Map<CrsTarget, CompiledRule[]>();
  private readonly chained: CompiledRule[] = [];
  /** Per target: value -> indexes into `rules` that the value matches. */
  private readonly memo = new Map<CrsTarget, Map<string, number[]>>();
  private memoSize = 0;

  constructor(options: CrsEngineOptions = {}) {
    this.threshold = options.threshold ?? DEFAULT_ANOMALY_THRESHOLD;
    const excluded = new Set(options.excludeRuleIds ?? DEFAULT_EXCLUDED_RULE_IDS);
    const crs = CRS_RULES.filter((r) => !excluded.has(r.id));
    const threatcrush = THREATCRUSH_RULES.filter((r) => !excluded.has(r.id));
    this.ruleCounts = { crs: crs.length, threatcrush: threatcrush.length };
    this.rules = [...crs, ...threatcrush].map((rule, index) => ({
      index,
      rule,
      test: compileOperator(rule.op),
      stepKeys: rule.transforms.map((_, k) => rule.transforms.slice(0, k + 1).join(',')),
      chain: (rule.chain ?? []).map((link) => ({ link, test: compileOperator(link.op) })),
      attackType: crsAttackType(rule),
    }));
    for (const compiled of this.rules) {
      if (compiled.chain.length > 0) {
        this.chained.push(compiled);
        continue;
      }
      for (const target of compiled.rule.targets) {
        const list = this.byTarget.get(target) ?? [];
        list.push(compiled);
        this.byTarget.set(target, list);
      }
    }
  }

  private slotMatches(target: CrsTarget, rules: CompiledRule[], slot: Slot): number[] {
    const memoize = slot.value.length <= MEMO_MAX_VALUE;
    let memo = this.memo.get(target);
    if (!memo) {
      memo = new Map();
      this.memo.set(target, memo);
    }
    const known = memoize ? memo.get(slot.value) : undefined;
    if (known) return known;
    const hits: number[] = [];
    const matched: string[] = [];
    for (const rule of rules) {
      matchSlot(rule, slot, matched, true);
      if (matched.length > 0) {
        hits.push(rule.index);
        matched.length = 0;
      }
    }
    if (memoize) {
      // Past the cap, start over: cheaper than LRU bookkeeping, and the hot
      // values are back within a few lines.
      if (this.memoSize >= MEMO_ENTRIES) {
        for (const m of this.memo.values()) m.clear();
        this.memoSize = 0;
      }
      memo.set(slot.value, hits);
      this.memoSize++;
    }
    return hits;
  }

  assess(request: HttpRequestView): CrsAssessment {
    const ctx = new RequestContext({
      method: request.method,
      uri: asBytes(request.uri),
      protocol: request.protocol,
      userAgent: asBytes(request.userAgent),
      referer: asBytes(request.referer),
    });
    const hit = new Uint8Array(this.rules.length);
    for (const [target, rules] of this.byTarget) {
      for (const slot of ctx.values(target)) {
        for (const index of this.slotMatches(target, rules, slot)) hit[index] = 1;
      }
    }
    for (const compiled of this.chained) {
      if (chainMatches(compiled, ctx)) hit[compiled.index] = 1;
    }

    const matches: CrsMatch[] = [];
    const byType = new Map<string, number>();
    let score = 0;
    for (const compiled of this.rules) {
      if (!hit[compiled.index]) continue;
      const { id, msg, severity, tags } = compiled.rule;
      const points = SEVERITY_POINTS[severity];
      score += points;
      matches.push({ id, msg, severity, tags });
      if (compiled.attackType) byType.set(compiled.attackType, (byType.get(compiled.attackType) ?? 0) + points);
    }
    let attackType: string | null = null;
    let best = 0;
    for (const [type, points] of byType) {
      if (points > best) {
        best = points;
        attackType = type;
      }
    }
    return { score, threshold: this.threshold, attackType, matches };
  }
}
