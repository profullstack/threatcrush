/**
 * Template-file rules: unescaped output, per engine.
 *
 * Why this is a separate engine
 * -----------------------------
 * `code-rules.ts` reasons about source code — it knows what a call looks like,
 * what a string literal looks like, and which identifiers carry request data.
 * A Handlebars file has none of that. It is markup with holes in it, and the
 * only security question worth asking is which holes skip escaping.
 *
 * That question is answered by *syntax*, and every engine spells it
 * differently: Handlebars has a triple-stache, Pug prefixes with `!`, EJS uses
 * a different tag character from the one that escapes, Dust hangs an `|s`
 * filter on the end. So a template rule is selected by file extension rather
 * than by language — the extension is what identifies the engine, and nothing
 * inside the file reliably does.
 *
 * Extension, not language, for a second reason: `.vue` and `.ejs` are already
 * mapped to `javascript` so their `<script>` halves get the full code rule
 * set. Remapping them to a `template` language to reach these rules would take
 * that away. Running the two engines over the same file, keyed differently, is
 * what njsscan does as well, and for the same reason.
 *
 * What these rules claim
 * ----------------------
 * Only that the interpolation does not escape. Not that the value is
 * attacker-controlled — a template cannot show that, and the variable is very
 * often a CMS body that was sanitised on the way in, which is the legitimate
 * reason to reach for unescaped output at all.
 *
 * So every rule here reports at confidence `pattern`, which the shared cap in
 * `types.ts` holds at `medium` however high the rule declares itself. That is
 * the honest ceiling for "this line opts out of the engine's escaping" with no
 * further evidence, and it keeps a template-heavy repository from filling a
 * report with `high` findings that nobody can triage.
 *
 * Provenance: the set of engines covered was chosen by looking at what njsscan
 * (LGPL-3.0) reports on, so this MIT package would not have a blind spot an
 * established Node scanner covers. The patterns, guards and prose are written
 * from scratch — see the note at the top of `node-rules.ts`.
 */

import type { Severity } from './types';
import { severityFor } from './types';

export interface TemplateRule {
  id: string;
  title: string;
  consequence: string;
  cwe: string;
  severity: Severity;
  /** Extensions this engine owns, lowercase and dot-prefixed. */
  extensions: readonly string[];
  pattern: RegExp;
  /** Evidence on the matched line that this occurrence is not user data. */
  lineGuard?: RegExp;
}

/**
 * The layout slot, which is not a variable.
 *
 * `{{{body}}}` in a Handlebars layout is where the rendered child template is
 * spliced in — it is unescaped because it is already HTML, by design, and
 * every project using layouts has exactly one. Reporting it means every
 * express-handlebars app opens its report with a false positive.
 */
const LAYOUT_SLOT = /\{\{\{\s*(?:body|content|outlet|children)\s*\}\}\}/;

const XSS_CONSEQUENCE =
  'The value is written into the page as markup rather than as text, so a `<script>` or an `onerror=` attribute in it executes in the visitor’s session — with their cookies, and their privileges.';

export const TEMPLATE_RULES: readonly TemplateRule[] = [
  {
    id: 'tpl-handlebars-unescaped',
    title: 'Handlebars/Mustache interpolation that skips escaping',
    consequence: XSS_CONSEQUENCE,
    cwe: 'CWE-79',
    severity: 'high',
    extensions: ['.hbs', '.handlebars', '.hdbs', '.mustache', '.ms'],
    // Two spellings of the same opt-out: the triple-stache and the `&` prefix.
    pattern: /\{\{\{(?!\{)[^}]*\}\}\}|\{\{\s*&\s*[^}]+\}\}/,
    lineGuard: LAYOUT_SLOT,
  },
  {
    id: 'tpl-vue-v-html',
    title: '`v-html` binding',
    consequence: XSS_CONSEQUENCE,
    cwe: 'CWE-79',
    severity: 'high',
    extensions: ['.vue', '.html', '.htm'],
    pattern: /\bv-html\s*=|\s:inner-html\.prop\s*=/,
  },
  {
    id: 'tpl-pug-unescaped',
    title: 'Pug/Jade unescaped interpolation',
    consequence: XSS_CONSEQUENCE,
    cwe: 'CWE-79',
    severity: 'high',
    extensions: ['.pug', '.jade'],
    // `!{…}` is unescaped interpolation anywhere on the line. `!=` is
    // unescaped buffered code, but only in the tag position — anchored to the
    // start of the line and preceded by nothing but tag, class and id
    // characters, so the `!==` inside `- if (a !== b)` cannot reach it.
    pattern: /!\{[^}\n]*\}|^\s*[\w.#%-]*!=(?!=)\s*\S/,
  },
  {
    id: 'tpl-ejs-raw-output',
    title: 'EJS/ECT raw output tag',
    consequence: XSS_CONSEQUENCE,
    cwe: 'CWE-79',
    severity: 'high',
    extensions: ['.ejs', '.ect'],
    // In EJS `<%= %>` escapes and `<%-` does not, which is the reverse of
    // Underscore's convention — see KNOWN_GAPS.
    pattern: /<%-(?!\s*(?:include|-))/,
    // `<%- include('partial') %>` splices another template, not user data.
    lineGuard: /<%-\s*(?:include|partial)\s*\(/,
  },
  {
    id: 'tpl-dust-escape-filter-off',
    title: 'Dust reference with escaping suppressed',
    consequence: XSS_CONSEQUENCE,
    cwe: 'CWE-79',
    severity: 'high',
    extensions: ['.dust', '.tl'],
    // The `|s` filter means "suppress the default HTML escape".
    pattern: /\{[^{}\n]+\|\s*s\s*\}/,
  },
  {
    id: 'tpl-jinja-safe-filter',
    title: 'Nunjucks/Twig/Jinja `safe` filter or autoescape block off',
    consequence: XSS_CONSEQUENCE,
    cwe: 'CWE-79',
    severity: 'high',
    extensions: ['.njk', '.nunjucks', '.twig', '.jinja', '.jinja2', '.j2'],
    pattern: /\|\s*(?:safe|raw)\s*(?:\}\}|\|)|\{%\s*autoescape\s+(?:false|off)\s*%\}/,
  },
  {
    id: 'tpl-haml-unescaped',
    title: 'Haml unescaped output',
    consequence: XSS_CONSEQUENCE,
    cwe: 'CWE-79',
    severity: 'high',
    extensions: ['.haml'],
    pattern: /^\s*[\w.#%-]*!=(?!=)\s*\S/,
  },
];

/** Extensions any template rule owns. Folded into `SCAN_EXTENSIONS`. */
export const TEMPLATE_EXTENSIONS: ReadonlySet<string> = new Set(
  TEMPLATE_RULES.flatMap((rule) => rule.extensions),
);

export interface TemplateMatch {
  rule: TemplateRule;
  severity: Severity;
  line: number;
}

/**
 * Run the rules that own this extension over the file's lines.
 *
 * Returns matches rather than findings so the caller keeps sole ownership of
 * how a finding is shaped — the same split the code rules use.
 */
export function evaluateTemplateRules(
  extension: string,
  lines: readonly string[],
): TemplateMatch[] {
  const ext = extension.toLowerCase();
  const applicable = TEMPLATE_RULES.filter((rule) => rule.extensions.includes(ext));
  if (applicable.length === 0) return [];

  const matches: TemplateMatch[] = [];
  lines.forEach((line, index) => {
    for (const rule of applicable) {
      if (!rule.pattern.test(line)) continue;
      if (rule.lineGuard?.test(line)) continue;
      matches.push({
        rule,
        // A template cannot show that the value is untrusted, so the claim
        // never rises above `pattern` and the shared cap holds it at medium.
        severity: severityFor(rule.severity, 'pattern'),
        line: index + 1,
      });
    }
  });
  return matches;
}

/**
 * KNOWN_GAPS — template classes deliberately not covered.
 *
 *   Underscore / Lodash templates
 *     `<%= %>` is *unescaped* in Underscore and *escaped* in EJS, and the two
 *     share the `.html` and `.tpl` extensions. Since the engine is what
 *     decides which meaning applies, and nothing in the file says which engine
 *     will render it, a rule for either convention is wrong half the time.
 *
 *   Liquid
 *     Liquid does not escape by default at all, so every interpolation would
 *     match. A rule that fires on every line of every template is a rule
 *     nobody leaves switched on.
 *
 *   Whether the interpolated value is attacker-controlled
 *     Needs the controller that renders the template, which is a different
 *     file. This is the reason for the confidence ceiling, not an oversight.
 */
