import { describe, expect, it } from 'vitest';
import { SCAN_EXTENSIONS, scanText } from '../text';
import { TEMPLATE_EXTENSIONS } from '../template-rules';

/**
 * Each engine is tested as a pair: the syntax that skips escaping, and the
 * neighbouring syntax that does not. Getting the second half wrong is how a
 * template rule ends up reporting every line of every view.
 */
const ruleIds = (path: string, source: string): string[] =>
  scanText(path, source).map((finding) => finding.ruleId);

describe('Handlebars and Mustache', () => {
  it('flags a triple-stache', () => {
    expect(ruleIds('v.hbs', '<div>{{{ comment.body }}}</div>')).toContain('tpl-handlebars-unescaped');
  });

  it('flags the ampersand form', () => {
    expect(ruleIds('v.mustache', '<div>{{& comment.body }}</div>')).toContain(
      'tpl-handlebars-unescaped',
    );
  });

  it('stays silent on an escaped interpolation', () => {
    expect(ruleIds('v.hbs', '<div>{{ comment.body }}</div>')).not.toContain('tpl-handlebars-unescaped');
  });

  it('stays silent on the layout slot', () => {
    // Every project using layouts has exactly one of these, and it is not a
    // variable — it is where the rendered child template is spliced in.
    expect(ruleIds('layout.hbs', '<body>{{{body}}}</body>')).not.toContain('tpl-handlebars-unescaped');
  });
});

describe('Vue', () => {
  it('flags a v-html binding', () => {
    expect(ruleIds('C.vue', '<div v-html="post.html"></div>')).toContain('tpl-vue-v-html');
  });

  it('stays silent on a moustache interpolation', () => {
    expect(ruleIds('C.vue', '<div>{{ post.title }}</div>')).not.toContain('tpl-vue-v-html');
  });
});

describe('Pug', () => {
  it('flags unescaped buffered output', () => {
    expect(ruleIds('v.pug', 'p!= user.bio')).toContain('tpl-pug-unescaped');
  });

  it('flags unescaped interpolation', () => {
    expect(ruleIds('v.pug', 'p Hello !{user.name}')).toContain('tpl-pug-unescaped');
  });

  it('stays silent on escaped output', () => {
    expect(ruleIds('v.pug', 'p= user.bio')).not.toContain('tpl-pug-unescaped');
  });

  it('stays silent on a strict-inequality comparison', () => {
    // `!==` contains `!=`. Anchoring to the tag position is what keeps inline
    // JavaScript in a Pug file from reading as unescaped output.
    expect(ruleIds('v.pug', '- if (a !== b)')).not.toContain('tpl-pug-unescaped');
  });
});

describe('EJS', () => {
  it('flags the raw output tag', () => {
    expect(ruleIds('v.ejs', '<div><%- comment.body %></div>')).toContain('tpl-ejs-raw-output');
  });

  it('stays silent on the escaping tag', () => {
    // In EJS `<%= %>` escapes — the reverse of Underscore's convention, which
    // is why that engine is in KNOWN_GAPS rather than covered here.
    expect(ruleIds('v.ejs', '<div><%= comment.body %></div>')).not.toContain('tpl-ejs-raw-output');
  });

  it('stays silent on a partial include', () => {
    expect(ruleIds('v.ejs', `<%- include('partials/header') %>`)).not.toContain('tpl-ejs-raw-output');
  });
});

describe('Dust', () => {
  it('flags a suppressed escape filter', () => {
    expect(ruleIds('v.dust', '<div>{body|s}</div>')).toContain('tpl-dust-escape-filter-off');
  });

  it('stays silent on a plain reference', () => {
    expect(ruleIds('v.dust', '<div>{body}</div>')).not.toContain('tpl-dust-escape-filter-off');
  });
});

describe('Nunjucks, Twig and Jinja', () => {
  it('flags the safe filter', () => {
    expect(ruleIds('v.njk', '<div>{{ post.body | safe }}</div>')).toContain('tpl-jinja-safe-filter');
  });

  it('flags an autoescape block turned off', () => {
    expect(ruleIds('v.njk', '{% autoescape false %}')).toContain('tpl-jinja-safe-filter');
  });

  it('stays silent on a plain interpolation', () => {
    expect(ruleIds('v.njk', '<div>{{ post.body }}</div>')).not.toContain('tpl-jinja-safe-filter');
  });
});

describe('Haml', () => {
  it('flags unescaped output from a tag', () => {
    expect(ruleIds('v.haml', '%p!= user.bio')).toContain('tpl-haml-unescaped');
  });

  it('stays silent on escaped output', () => {
    expect(ruleIds('v.haml', '%p= user.bio')).not.toContain('tpl-haml-unescaped');
  });
});

describe('engine wiring', () => {
  it('makes every template extension scannable', () => {
    // A rule whose files the walker skips is a rule that silently never fires.
    for (const extension of TEMPLATE_EXTENSIONS) {
      expect(SCAN_EXTENSIONS.has(extension)).toBe(true);
    }
  });

  it('caps a template finding at medium', () => {
    // A template cannot show that the value is attacker-controlled. Reporting
    // these as high would fill a report with claims nobody can triage.
    const finding = scanText('v.hbs', '<div>{{{ comment.body }}}</div>')[0];
    expect(finding?.confidence).toBe('pattern');
    expect(finding?.severity).toBe('medium');
  });

  it('still applies the JavaScript rules to a Vue file', () => {
    // `.vue` is both a template and a script. Reaching the template rules must
    // not cost it the code rules.
    const source = ['<script>', 'const el = document.querySelector("#a");', 'el.innerHTML = req.query.q;', '</script>'].join('\n');
    expect(ruleIds('C.vue', source)).toContain('js-unescaped-html-sink');
  });

  it('honours an inline suppression on a template line', () => {
    const source = ['{{!-- threatcrush-disable-next-line tpl-handlebars-unescaped --}}', '{{{ trusted.html }}}'].join('\n');
    expect(ruleIds('v.hbs', source)).not.toContain('tpl-handlebars-unescaped');
  });
});
