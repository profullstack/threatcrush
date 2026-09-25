#!/usr/bin/env node
// Generates src/core/crs/rules.generated.ts from the vendored OWASP Core Rule
// Set (vendor/coreruleset, Apache-2.0).
//
//   node scripts/build-crs-rules.mjs          write the table, print the counts
//   node scripts/build-crs-rules.mjs --check  fail if the checked-in table is stale
//
// Only what an access log can see is ported. A combined-format line carries the
// request line and the User-Agent and Referer headers — no body, no cookies, no
// other headers, no response. So a rule is ported when it is paranoia level 1,
// at least one of its targets can be derived from those, every operator and
// transformation it uses is implemented here, and its regex converts to an
// equivalent JavaScript one. Anything else is skipped and counted by reason.
// A rule is ported faithfully or not at all: nothing is rewritten by hand.
//
// Tuning is by rule id only (the CRS-sanctioned SecRuleRemoveById), listed in
// EXCLUDED below with the reason, so the table holds exactly what is loaded.
//
// The table also carries ThreatCrush's own rules (THREATCRUSH_RULES, see
// "ThreatCrush rules" below): not CRS, never counted as CRS, built here only
// because they read CRS's vendored data files.

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI_ROOT = join(HERE, '..');
// coreruleset-4.29.0-minimal.tar.gz from github.com/coreruleset/coreruleset
// releases, sha256 1aa1c5c8fc29e532d35293bcea36bf72de61db8f6ed4716a0f91ab14552b7fed;
// only the rule files below and the phrase files they read are vendored.
const VENDOR = join(CLI_ROOT, 'vendor', 'coreruleset');
const RULES_DIR = join(VENDOR, 'rules');
const OUT = join(CLI_ROOT, 'src', 'core', 'crs', 'rules.generated.ts');

export const CRS_VERSION = '4.29.0';
const FILES = /^REQUEST-9(13|30|31|32|33|34|41|42|44)-.*\.conf$/;

/**
 * Rules removed after measuring against real traffic, SecRuleRemoveById-style.
 * Each needs a reason a reviewer can check.
 */
export const EXCLUDED = {};

/** Transformations implemented in src/core/crs/transforms.ts. */
const TRANSFORMS = new Set([
  'lowercase', 'urlDecodeUni', 'htmlEntityDecode', 'jsDecode', 'cssDecode', 'removeNulls',
  'removeWhitespace', 'compressWhitespace', 'replaceComments', 'removeCommentsChar', 'cmdLine',
  'normalizePath', 'normalizePathWin', 'utf8toUnicode', 'base64Decode',
]);

/** Operators implemented in src/core/crs/engine.ts. */
const OPERATORS = new Set(['rx', 'pm', 'pmFromFile', 'contains', 'streq', 'beginsWith', 'endsWith', 'within']);

const SEVERITIES = new Set(['CRITICAL', 'ERROR', 'WARNING', 'NOTICE']);

class Skip extends Error {
  constructor(reason) { super(reason); this.reason = reason; }
}

// ---------------------------------------------------------------- .conf parsing

function logicalLines(text) {
  return text.replace(/\\\r?\n/g, ' ').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
}

/** Split a directive into its whitespace-separated, double-quote-aware arguments. */
function tokenize(line) {
  const out = [];
  let i = 0;
  while (i < line.length) {
    while (line[i] === ' ' || line[i] === '\t') i++;
    if (i >= line.length) break;
    if (line[i] === '"') {
      let j = i + 1;
      let s = '';
      while (j < line.length && line[j] !== '"') {
        if (line[j] === '\\' && line[j + 1] === '"') { s += '"'; j += 2; continue; }
        s += line[j++];
      }
      out.push(s);
      i = j + 1;
    } else {
      let j = i;
      while (j < line.length && line[j] !== ' ' && line[j] !== '\t') j++;
      out.push(line.slice(i, j));
      i = j;
    }
  }
  return out;
}

/** Split an action list on commas that are not inside single quotes. */
function splitActions(actions) {
  const out = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < actions.length; i++) {
    const c = actions[i];
    if (c === '\\' && quoted && actions[i + 1] === "'") { cur += "'"; i++; continue; }
    if (c === "'") { quoted = !quoted; continue; }
    if (c === ',' && !quoted) { out.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out.map((a) => {
    const k = a.indexOf(':');
    return k === -1 ? { name: a, value: '' } : { name: a.slice(0, k).trim(), value: a.slice(k + 1).trim() };
  });
}

function parseRule(tokens, file) {
  const [, variables, operator, actionText = ''] = tokens;
  const actions = splitActions(actionText);
  const get = (n) => actions.filter((a) => a.name === n).map((a) => a.value);
  return {
    file,
    variables,
    operator,
    actions,
    id: get('id')[0] ? Number(get('id')[0]) : undefined,
    msg: get('msg')[0],
    severity: get('severity')[0],
    tags: get('tag'),
    transforms: get('t'),
    chain: actions.some((a) => a.name === 'chain'),
    multiMatch: actions.some((a) => a.name === 'multiMatch'),
    setvars: get('setvar'),
  };
}

/** Every SecRule in the file, chained links attached to their head. */
function readRules(file) {
  const heads = [];
  let open = null;
  for (const line of logicalLines(readFileSync(join(RULES_DIR, file), 'latin1'))) {
    const tokens = tokenize(line);
    if (tokens[0] !== 'SecRule') continue;
    const rule = parseRule(tokens, file);
    if (open) {
      open.links.push(rule);
      if (!rule.chain) open = null;
      continue;
    }
    const head = { ...rule, links: [] };
    heads.push(head);
    if (rule.chain) open = head;
  }
  return heads;
}

// ------------------------------------------------------------------- targets

// What an access log line lets us reconstruct. REQUEST_HEADERS is reduced to
// the two headers the combined format records.
const LOGGED_HEADERS = ['User-Agent', 'Referer'];
const DIRECT_TARGETS = new Set(['ARGS', 'ARGS_GET', 'ARGS_NAMES', 'ARGS_GET_NAMES', 'QUERY_STRING', 'REQUEST_FILENAME', 'REQUEST_URI_RAW', 'REQUEST_LINE']);

function parseTargets(variables) {
  const include = [];
  const exclude = [];
  for (const raw of variables.split('|')) {
    const neg = raw.startsWith('!');
    const spec = neg ? raw.slice(1) : raw;
    const k = spec.indexOf(':');
    const collection = k === -1 ? spec : spec.slice(0, k);
    const key = k === -1 ? undefined : spec.slice(k + 1);
    (neg ? exclude : include).push({ collection, key });
  }

  const visible = [];
  const dropped = [];
  for (const t of include) {
    if (t.collection === 'REQUEST_HEADERS') {
      const names = t.key === undefined ? LOGGED_HEADERS : LOGGED_HEADERS.filter((h) => h.toLowerCase() === t.key.toLowerCase());
      if (t.key !== undefined && t.key.startsWith('/')) throw new Skip('regex header selector');
      for (const h of names) {
        const excluded = exclude.some((e) => e.collection === 'REQUEST_HEADERS' && e.key?.toLowerCase() === h.toLowerCase());
        if (!excluded) visible.push(`REQUEST_HEADERS:${h}`);
      }
      if (names.length === 0 || t.key === undefined) dropped.push(t.key === undefined ? 'REQUEST_HEADERS(other)' : `REQUEST_HEADERS:${t.key}`);
      continue;
    }
    if (DIRECT_TARGETS.has(t.collection)) {
      if (t.key !== undefined) throw new Skip('keyed argument selector');
      const name = t.collection === 'ARGS_GET' ? 'ARGS' : t.collection === 'ARGS_GET_NAMES' ? 'ARGS_NAMES' : t.collection;
      visible.push(name);
      continue;
    }
    dropped.push(t.key === undefined ? t.collection : `${t.collection}:${t.key}`);
  }
  for (const e of exclude) {
    if (e.collection === 'REQUEST_HEADERS' || !DIRECT_TARGETS.has(e.collection)) continue;
    throw new Skip('target exclusion on a visible collection');
  }
  return { visible: [...new Set(visible)], dropped };
}

// ----------------------------------------------------------------- operators

function parseOperator(text) {
  let s = text;
  let negated = false;
  if (s.startsWith('!')) { negated = true; s = s.slice(1); }
  if (!s.startsWith('@')) return { name: 'rx', arg: s, negated };
  const k = s.search(/\s/);
  const name = k === -1 ? s.slice(1) : s.slice(1, k);
  const arg = k === -1 ? '' : s.slice(k + 1);
  return { name, arg, negated };
}

/** ModSecurity reads a phrase file line by line: trimmed, blank and # lines skipped. */
function readPhraseFile(name) {
  const phrases = [];
  for (const line of readFileSync(join(RULES_DIR, name), 'latin1').split('\n')) {
    const p = line.replace(/^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$/g, '');
    if (!p || p.startsWith('#')) continue;
    phrases.push(p);
  }
  return phrases;
}

function buildOperator(text) {
  const op = parseOperator(text);
  if (!OPERATORS.has(op.name)) throw new Skip(`operator @${op.name}`);
  if (op.arg.includes('%{')) throw new Skip('macro in operator argument');
  switch (op.name) {
    case 'rx':
      return { type: 'rx', ...convertRegex(op.arg), negated: op.negated };
    case 'pm':
      return { type: 'pm', phrases: op.arg.split(/[\t\n\v\f\r ]+/).filter(Boolean), negated: op.negated };
    case 'pmFromFile': {
      const phrases = [];
      for (const f of op.arg.split(/\s+/).filter(Boolean)) phrases.push(...readPhraseFile(f));
      return { type: 'pm', phrases, negated: op.negated };
    }
    default:
      return { type: op.name, arg: op.arg, negated: op.negated };
  }
}

// ------------------------------------------------------------ PCRE -> JS

// ModSecurity compiles @rx with PCRE_DOTALL | PCRE_DOLLAR_ENDONLY and matches
// bytes. The engine hands JavaScript a one-char-per-byte string, and the `s`
// flag with a non-multiline `$` gives the same dot and anchor semantics. The
// rest is converted token by token, or the rule is skipped:
//  - `\s` / `\S` become explicit PCRE whitespace, since JavaScript's also
//    matches U+00A0, which PCRE (non-UTF) does not.
//  - `(?i)` becomes the `i` flag; a scoped `(?i:...)` is only accepted when the
//    rest of the pattern is case-neutral, so the flag can cover all of it.
//  - JavaScript's `i` also folds Latin-1 letters; PCRE in the C locale does
//    not. That can only differ when the pattern names a byte >= 0x80, so such
//    case-insensitive patterns are skipped.
const PCRE_SPACE = '\\t-\\r ';
const NON_SPACE = Symbol('\\S in a class');

export function convertRegex(pcre) {
  let src = pcre;
  let globalI = false;
  const lead = /^\(\?([a-zA-Z]+)\)/.exec(src);
  if (lead) {
    for (const f of lead[1]) {
      if (f === 'i') globalI = true;
      else if (f !== 's') throw new Skip(`inline flag (?${f})`);
    }
    src = src.slice(lead[0].length);
  }

  let out = '';
  let caseSensitiveLetters = false; // a letter outside any (?i:...) scope
  let scopedI = false;
  let highByte = false;
  const stack = []; // per open group: is it case-insensitive?
  const ciNow = () => globalI || (stack.length > 0 && stack[stack.length - 1]);
  let i = 0;

  const hexEscape = (at) => {
    // at points just past "\x"
    if (src[at] === '{') {
      const end = src.indexOf('}', at);
      if (end === -1) throw new Skip('malformed \\x{}');
      const v = parseInt(src.slice(at + 1, end), 16);
      if (!(v >= 0 && v <= 0xff)) throw new Skip('code point above 0xFF');
      return { value: v, next: end + 1 };
    }
    const m = /^[0-9a-fA-F]{1,2}/.exec(src.slice(at));
    const v = m ? parseInt(m[0], 16) : 0;
    return { value: v, next: at + (m ? m[0].length : 0) };
  };
  const hex2 = (v) => `\\x${v.toString(16).padStart(2, '0')}`;
  const noteLiteral = (code) => {
    if (code >= 0x80) highByte = true;
    const isLetter = (code >= 0x41 && code <= 0x5a) || (code >= 0x61 && code <= 0x7a);
    if (isLetter && !ciNow()) caseSensitiveLetters = true;
  };

  /** Escape outside or inside a class. Returns [js, nextIndex]. */
  const escape = (at, inClass) => {
    const c = src[at + 1];
    if (c === undefined) throw new Skip('trailing backslash');
    switch (c) {
      case 'x': {
        const { value, next } = hexEscape(at + 2);
        noteLiteral(value);
        return [hex2(value), next];
      }
      case 's': return [inClass ? PCRE_SPACE : `[${PCRE_SPACE}]`, at + 2];
      case 'S':
        // Inside a class the caller splits it out; see NON_SPACE below.
        return [inClass ? NON_SPACE : `[^${PCRE_SPACE}]`, at + 2];
      case 'z': if (inClass) throw new Skip('\\z in class'); return ['$', at + 2];
      case 'A': if (inClass) throw new Skip('\\A in class'); return ['^', at + 2];
      case 'Z': if (inClass) throw new Skip('\\Z in class'); return ['(?=\\n?$)', at + 2];
      case 'a': return ['\\x07', at + 2];
      case 'e': return ['\\x1b', at + 2];
      case 'h': case 'H': case 'v': case 'V': case 'R': case 'p': case 'P': case 'X': case 'K':
      case 'G': case 'Q': case 'E': case 'C': case 'N': case 'g': case 'k': case 'o': case 'L': case 'l':
      case 'U': case 'u':
        throw new Skip(`PCRE escape \\${c}`);
      case 'd': case 'D': case 'w': case 'W': case 'b': case 'B': case 'n': case 'r': case 't': case 'f':
        return [`\\${c}`, at + 2];
      default:
        if (/[0-9]/.test(c)) throw new Skip('octal escape or backreference');
        if (/[a-zA-Z]/.test(c)) throw new Skip(`unknown escape \\${c}`);
        noteLiteral(c.charCodeAt(0));
        return [`\\${c}`, at + 2];
    }
  };

  while (i < src.length) {
    const c = src[i];
    if (c === '\\') {
      const [js, next] = escape(i, false);
      out += js;
      i = next;
    } else if (c === '[') {
      let cls = '[';
      i++;
      const negated = src[i] === '^';
      if (negated) { cls += '^'; i++; }
      if (src[i] === ']') { cls += '\\]'; i++; }
      let closed = false;
      let nonSpace = false;
      while (i < src.length) {
        const d = src[i];
        if (d === ']') { closed = true; i++; break; }
        if (d === '\\') {
          const [js, next] = escape(i, true);
          if (js === NON_SPACE) nonSpace = true;
          else cls += js;
          i = next;
          continue;
        }
        if (d === '[') {
          if (src[i + 1] === ':' || src[i + 1] === '=' || src[i + 1] === '.') throw new Skip('POSIX character class');
          cls += '\\[';
          i++;
          continue;
        }
        noteLiteral(d.charCodeAt(0));
        cls += d;
        i++;
      }
      if (!closed) throw new Skip('unterminated character class');
      if (!nonSpace) {
        out += `${cls}]`;
      } else {
        // [x\S] is "x, or anything PCRE does not call whitespace": an
        // alternation of the remaining class and the explicit complement.
        if (negated) throw new Skip('\\S inside a negated character class');
        out += cls === '[' ? `[^${PCRE_SPACE}]` : `(?:${cls}]|[^${PCRE_SPACE}])`;
      }
    } else if (c === '(') {
      if (src[i + 1] !== '?') {
        stack.push(ciNow());
        out += '(';
        i++;
        continue;
      }
      const rest = src.slice(i + 2);
      if (rest.startsWith(':')) { stack.push(ciNow()); out += '(?:'; i += 3; continue; }
      if (rest.startsWith('=') || rest.startsWith('!')) { stack.push(ciNow()); out += `(?${rest[0]}`; i += 3; continue; }
      if (rest.startsWith('<=') || rest.startsWith('<!')) { stack.push(ciNow()); out += `(?${rest.slice(0, 2)}`; i += 4; continue; }
      const scoped = /^([a-zA-Z]+):/.exec(rest);
      if (scoped) {
        let ci = ciNow();
        for (const f of scoped[1]) {
          if (f === 'i') { ci = true; scopedI = true; } else if (f !== 's') throw new Skip(`scoped flag (?${f}:`);
        }
        stack.push(ci);
        out += '(?:';
        i += 2 + scoped[0].length;
        continue;
      }
      throw new Skip(`group construct (?${rest.slice(0, 2)}`);
    } else if (c === ')') {
      stack.pop();
      out += ')';
      i++;
    } else if (c === '*' || c === '+' || c === '?') {
      out += c;
      i++;
      if (src[i] === '+') throw new Skip('possessive quantifier');
      if (src[i] === '?') { out += '?'; i++; if (src[i] === '+') throw new Skip('possessive quantifier'); }
    } else if (c === '{') {
      const q = /^\{\d+(?:,\d*)?\}/.exec(src.slice(i));
      if (q) {
        out += q[0];
        i += q[0].length;
        if (src[i] === '+') throw new Skip('possessive quantifier');
        if (src[i] === '?') { out += '?'; i++; }
      } else {
        out += '\\{';
        i++;
      }
    } else if (c === '}') {
      out += '\\}';
      i++;
    } else {
      noteLiteral(c.charCodeAt(0));
      out += c;
      i++;
    }
  }

  // A scoped (?i:...) with case-sensitive letters elsewhere cannot be one flag.
  if (scopedI && !globalI && caseSensitiveLetters) throw new Skip('scoped (?i:) beside case-sensitive text');
  const caseInsensitive = globalI || scopedI;
  if (caseInsensitive && highByte) throw new Skip('case-insensitive pattern naming bytes >= 0x80');

  const flags = caseInsensitive ? 'is' : 's';
  try {
    new RegExp(out, flags);
  } catch (err) {
    throw new Skip(`JavaScript RegExp rejects it (${err.message.split(':').pop().trim()})`);
  }
  return { source: out, flags };
}

// ----------------------------------------------------------------- building

function checkTransforms(list) {
  const out = [];
  for (const t of list) {
    if (t === 'none') { out.length = 0; continue; }
    if (!TRANSFORMS.has(t)) throw new Skip(`transformation t:${t}`);
    out.push(t);
  }
  return out;
}

function paranoiaLevel(rule) {
  const tag = rule.tags.find((t) => t.startsWith('paranoia-level/'));
  return tag ? Number(tag.split('/')[1]) : undefined;
}

function scoreVar(rule) {
  // The anomaly score may be set on the head or on the last link of a chain.
  const all = [rule, ...rule.links].flatMap((r) => r.setvars);
  return all.find((s) => /inbound_anomaly_score_pl\d/.test(s));
}

function buildLink(link) {
  const target = link.variables.split('|').filter((v) => !v.startsWith('XML:'));
  if (target.length !== 1 || (target[0] !== 'MATCHED_VARS' && target[0] !== 'MATCHED_VAR')) {
    throw new Skip('chain link on a variable other than MATCHED_VAR(S)');
  }
  return {
    target: target[0],
    transforms: checkTransforms(link.transforms),
    op: buildOperator(link.operator),
  };
}

function buildRule(rule) {
  const pl = paranoiaLevel(rule);
  if (pl === undefined) throw new Skip('control rule (no paranoia-level tag)');
  if (pl > 1) throw new Skip('paranoia level > 1');
  if (!SEVERITIES.has(rule.severity)) throw new Skip(`severity ${rule.severity}`);
  if (!scoreVar(rule)) throw new Skip('does not add to the inbound anomaly score');
  const { visible, dropped } = parseTargets(rule.variables);
  if (visible.length === 0) throw new Skip('no target visible in an access log');
  const transforms = checkTransforms(rule.transforms);
  const op = buildOperator(rule.operator);
  const chain = rule.links.map(buildLink);
  const attack = rule.tags.filter((t) => t.startsWith('attack-'));
  return {
    id: rule.id,
    msg: rule.msg,
    severity: rule.severity,
    tags: attack,
    targets: visible,
    transforms,
    ...(rule.multiMatch ? { multiMatch: true } : {}),
    op,
    ...(chain.length ? { chain } : {}),
    droppedTargets: dropped,
  };
}

export function build() {
  const files = readdirSync(RULES_DIR).filter((f) => FILES.test(f)).sort();
  const ported = [];
  const skipped = new Map(); // reason -> ids
  const excluded = [];
  for (const file of files) {
    for (const rule of readRules(file)) {
      if (rule.id === undefined) continue;
      // Engine plumbing (paranoia-level skips) is not a detection.
      if (/^TX:/.test(rule.variables) && !rule.tags.some((t) => t.startsWith('paranoia-level/'))) continue;
      const ver = rule.actions.find((a) => a.name === 'ver')?.value;
      if (ver && ver !== `OWASP_CRS/${CRS_VERSION}`) throw new Error(`${file}: rule ${rule.id} is ${ver}, expected ${CRS_VERSION}`);
      try {
        const built = buildRule(rule);
        if (Object.hasOwn(EXCLUDED, built.id)) { excluded.push(built.id); continue; }
        ported.push(built);
      } catch (err) {
        if (!(err instanceof Skip)) throw err;
        const ids = skipped.get(err.reason) ?? [];
        ids.push(rule.id);
        skipped.set(err.reason, ids);
      }
    }
  }
  for (const id of Object.keys(EXCLUDED)) {
    if (!excluded.includes(Number(id))) throw new Error(`EXCLUDED lists ${id}, which is not a ported rule`);
  }
  return { files, ported, skipped, excluded, threatcrush: buildThreatcrush(ported) };
}

// --------------------------------------------------------- ThreatCrush rules
//
// Rules of ThreatCrush's own, scored by the same engine but not CRS. They take
// ids 10000-10999 (ModSecurity leaves 1-99,999 to local rules, clear of CRS's
// 900,000-999,999) and carry the `threatcrush` tag.

/** A phrase as a path from the root: lowercase, leading slashes dropped. */
const rootless = (p) => p.toLowerCase().replace(/^\/+/, '');

/**
 * 10001, an OS file named by the request path. CRS matches lfi-os-files.data
 * against arguments only (930120); on the path it matches its curated
 * restricted-files.data (930130), which leaves out the operating system's own
 * files, so a bare `GET /etc/passwd` scores nothing. This applies
 * lfi-os-files.data to REQUEST_FILENAME with 930120's transformations,
 * severity and attack tag, and differs from 930120 only so that ordinary pages
 * are not banned:
 *  - The phrase must begin the path, after an optional drive letter: the
 *    request names that file from the root. `/etc/hosts` is a probe,
 *    `/blog/etc/hosts` a page. normalizePathWin has already resolved
 *    traversal, so `/a/../../etc/passwd` begins with it too.
 *  - A phrase ending in a letter or digit must end there: `etc/init` matches
 *    `/etc/init.d/x` and `/etc/init`, not `/etc/initial-thoughts`.
 *  - A phrase that restricted-files.data contains, or narrows for paths
 *    (`node_modules/` there is `node_modules/.bin/`), is left to 930130: CRS has
 *    decided how far to trust it in a path, and no probe scores twice.
 */
function osFileInPathRule(ported) {
  const crs = ported.find((r) => r.id === 930120);
  if (!crs) throw new Error('10001 copies 930120, which is not ported');
  const restricted = readPhraseFile('restricted-files.data').map(rootless);
  const kept = new Set();
  for (const phrase of readPhraseFile('lfi-os-files.data')) {
    // ASCII only, so the `i` flag folds exactly what @pm's lowercasing does.
    if (/[^\x20-\x7e]/.test(phrase)) throw new Error(`lfi-os-files.data: non-ASCII phrase ${JSON.stringify(phrase)}`);
    const p = rootless(phrase);
    if (!restricted.some((r) => r.includes(p) || p.includes(r))) kept.add(p);
  }
  const alternatives = [...kept].sort().map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + (/[0-9a-z]$/.test(p) ? '(?![0-9a-z])' : ''));
  return {
    id: 10001,
    msg: 'OS File Access Attempt in the request path',
    severity: crs.severity,
    tags: [...crs.tags, 'threatcrush'],
    targets: ['REQUEST_FILENAME'],
    transforms: crs.transforms,
    op: { type: 'rx', source: `^/?(?:[a-z]:/)?(?:${alternatives.join('|')})`, flags: 'i', negated: false },
  };
}

function buildThreatcrush(ported) {
  return [osFileInPathRule(ported)];
}

// Byte strings (one char per byte) go through JSON with \u escapes, which the
// TS reads back byte-for-byte.
function render({ files, ported, skipped, excluded, threatcrush }) {
  const skippedSummary = [...skipped.entries()]
    .sort((a, b) => b[1].length - a[1].length)
    .map(([reason, ids]) => ({ reason, ids }));
  const rules = ported.map(({ droppedTargets, ...r }) => r);
  return `// GENERATED by scripts/build-crs-rules.mjs from OWASP CRS v${CRS_VERSION} — do not edit.
// THREATCRUSH_RULES at the end are ThreatCrush's own, not CRS.
// Source: vendor/coreruleset (${files.join(', ')}).
// OWASP CRS is Apache-2.0; see ./LICENSE and ./NOTICE. Regenerate with
// \`pnpm --filter @profullstack/threatcrush crs:build\`.
/* eslint-disable */
import type { CrsRule } from './types.js';

export const CRS_VERSION = ${JSON.stringify(CRS_VERSION)};

/** Rules removed by id after measurement (reason in the generator's EXCLUDED). */
export const CRS_EXCLUDED_IDS: readonly number[] = ${JSON.stringify(excluded)};

/** PL1 rules not ported, grouped by the reason. */
export const CRS_SKIPPED: ReadonlyArray<{ reason: string; ids: number[] }> = ${JSON.stringify(skippedSummary, null, 2)};

export const CRS_RULES: readonly CrsRule[] = ${JSON.stringify(rules, null, 2)};

/** ThreatCrush's own rules (ids 10000-10999, tag \`threatcrush\`): not CRS, never counted as CRS. */
export const THREATCRUSH_RULES: readonly CrsRule[] = ${JSON.stringify(threatcrush, null, 2)};
`;
}

function main() {
  const result = build();
  const text = render(result);
  const check = process.argv.includes('--check');
  const pl1Skipped = [...result.skipped.entries()].filter(([r]) => r !== 'paranoia level > 1' && r !== 'control rule (no paranoia-level tag)');

  const pl1 = result.ported.length + result.excluded.length + pl1Skipped.reduce((n, [, ids]) => n + ids.length, 0);
  console.log(`OWASP CRS v${CRS_VERSION}: ${result.files.length} rule files, ${pl1} paranoia-level-1 rules`);
  console.log(`ported: ${result.ported.length}`);
  console.log(`excluded after measurement: ${result.excluded.length}${result.excluded.length ? ` (${result.excluded.join(', ')})` : ''}`);
  console.log(`skipped (paranoia level > 1): ${result.skipped.get('paranoia level > 1')?.length ?? 0}`);
  console.log('skipped at PL1, by reason:');
  for (const [reason, ids] of pl1Skipped.sort((a, b) => b[1].length - a[1].length)) {
    console.log(`  ${String(ids.length).padStart(3)}  ${reason}: ${ids.join(', ')}`);
  }
  const partial = result.ported.filter((r) => r.droppedTargets.length);
  console.log(`ported with targets an access log cannot see dropped: ${partial.length}`);
  console.log(`ThreatCrush rules: ${result.threatcrush.length} (${result.threatcrush.map((r) => r.id).join(', ')})`);

  if (check) {
    let current = '';
    try { current = readFileSync(OUT, 'utf8'); } catch { /* missing */ }
    if (current !== text) {
      console.error(`${OUT} is stale — run scripts/build-crs-rules.mjs`);
      process.exit(1);
    }
    return;
  }
  writeFileSync(OUT, text);
  console.log(`wrote ${OUT}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
