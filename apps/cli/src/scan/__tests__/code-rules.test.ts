import { describe, expect, it } from 'vitest';
import { proseLines } from '../code-rules.js';
import { scanText } from '../engine.js';

/**
 * Every case here is a pair: the vulnerable shape and the *corrected* shape
 * standing next to it, taken from `profullstack/malware-test-prs`. Testing
 * only the first half measures nothing — a rule that flags everything passes
 * it. The second half is the one that fails when a rule goes back to matching
 * on syntax instead of on what the code does.
 */

const ruleIds = (path: string, source: string): string[] =>
  scanText(path, source).map((finding) => finding.ruleId);

describe('SQL injection', () => {
  it('flags concatenation where the SQL string contains the other quote', () => {
    // The inner `'` is what a naive `["'][^"']*` class chokes on, silently
    // dropping the most common injection shape in every language at once.
    const source = `const sql = "SELECT id, email FROM users WHERE id = '" + id + "'";`;
    expect(ruleIds('a.js', source)).toContain('sql-string-concatenation');
  });

  it('stays silent on a parameterised query', () => {
    const source = `return db.query('SELECT id, email FROM users WHERE id = $1', [req.params.id]);`;
    expect(ruleIds('a.js', source)).toHaveLength(0);
  });

  it('flags a template literal and an f-string', () => {
    expect(ruleIds('a.js', 'return db.query(`SELECT * FROM p WHERE n LIKE \'%${term}%\'`);')).toContain(
      'sql-template-interpolation',
    );
    expect(
      ruleIds('a.py', `cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")`),
    ).toContain('sql-template-interpolation');
  });

  it('flags %-formatting and .format(), not a bound %s', () => {
    expect(ruleIds('a.py', `cursor.execute("SELECT id FROM users WHERE id = '%s'" % user_id)`)).toContain(
      'sql-string-concatenation',
    );
    expect(
      ruleIds('a.py', `cursor.execute("SELECT id FROM users WHERE id = %s", (request.args["id"],))`),
    ).toHaveLength(0);
  });

  it('flags Sprintf and String.format', () => {
    expect(ruleIds('a.go', 'query := fmt.Sprintf("SELECT id FROM users WHERE id = \'%s\'", id)')).toContain(
      'sql-format-call',
    );
    expect(
      ruleIds('a.java', '.executeUpdate(String.format("DELETE FROM sessions WHERE token = \'%s\'", t));'),
    ).toContain('sql-format-call');
  });

  it('flags Ruby interpolation but not a bound placeholder', () => {
    expect(ruleIds('a.rb', `User.where("id = '#{id}'")`)).toContain('rb-sql-interpolation');
    expect(ruleIds('a.rb', `User.where('id = ?', params[:id])`)).toHaveLength(0);
  });
});

describe('command injection', () => {
  it('flags an interpolated shell string, not an argv array', () => {
    expect(ruleIds('a.js', 'exec(`ping -c 1 ${host}`);')).toContain('js-shell-exec-interpolation');
    expect(ruleIds('a.js', "execFile('ping', ['-c', '1', '--', req.query.host], cb);")).toHaveLength(0);
  });

  it('flags shell=True and os.system concatenation', () => {
    expect(ruleIds('a.py', 'os.system("ping -c 1 " + host)')).toContain('py-shell-command-string');
    expect(
      ruleIds('a.py', 'subprocess.run(["ping", "-c", "1", "--", host], shell=False, check=False)'),
    ).toHaveLength(0);
  });

  it('flags exec.Command with a shell, not with argv', () => {
    expect(ruleIds('a.go', 'exec.Command("sh", "-c", "ping -c 1 "+host).Output()')).toContain(
      'go-shell-exec-command',
    );
    expect(ruleIds('a.go', 'exec.Command("ping", "-c", "1", "--", host).Output()')).toHaveLength(0);
  });
});

describe('guard windows', () => {
  it('exonerates an allow-list two lines above the sink', () => {
    const guarded = [
      'def fetch_safe(request):',
      '    target_url = request.get("url")',
      '    allowed_hosts = {"api.example.invalid"}',
      '    if urlparse(target_url).hostname not in allowed_hosts:',
      '        return None',
      '    resp = requests.get(target_url, timeout=5)',
    ].join('\n');
    expect(ruleIds('a.py', guarded)).toHaveLength(0);
  });

  it('still flags the same sink without the allow-list', () => {
    const bare = [
      'def fetch_vulnerable(request):',
      '    target_url = request.get("url")',
      '    resp = requests.get(target_url, timeout=5)',
    ].join('\n');
    expect(ruleIds('a.py', bare)).toContain('py-ssrf-outbound-request');
  });

  it('does not read a comment as evidence of a guard', () => {
    // The corpus's vulnerable cases are commented "no allow-list validation".
    // Treating prose as a guard silences exactly what we are measuring.
    const source = [
      'def fetch_vulnerable(request):',
      '    # no allow-list, no scheme restriction, nothing sanitized',
      '    target_url = request.get("url")',
      '    resp = requests.get(target_url, timeout=5)',
    ].join('\n');
    expect(ruleIds('a.py', source)).toContain('py-ssrf-outbound-request');
  });

  it('does not read a function name as evidence of a guard', () => {
    // `def sanitize_path_vulnerable` is a name, not a sanitiser.
    const source = [
      'def sanitize_path_vulnerable(path):',
      "    pattern = re.compile(r'^(/?[^/]+)+$')",
    ].join('\n');
    expect(ruleIds('a.py', source)).toContain('redos-nested-quantifier');
  });

  it('looks forward for XML hardening, which is configured after construction', () => {
    const hardened = [
      'DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();',
      'factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);',
      'factory.setExpandEntityReferences(false);',
      'DocumentBuilder builder = factory.newDocumentBuilder();',
    ].join('\n');
    expect(ruleIds('a.java', hardened)).toHaveLength(0);

    const bare = [
      'DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();',
      'DocumentBuilder builder = factory.newDocumentBuilder();',
    ].join('\n');
    expect(ruleIds('a.java', bare)).toContain('java-xxe-parser-defaults');
  });

  it('flags an unhardened parse in a file that parses XML', () => {
    const source = [
      'import javax.xml.parsers.DocumentBuilder;',
      'import javax.xml.parsers.DocumentBuilderFactory;',
      '',
      'public Document read(InputStream is) throws Exception {',
      '    return builder.parse(is);',
      '}',
    ].join('\n');
    expect(ruleIds('a.java', source)).toContain('java-xxe-parse-call');
  });

  // The receiver suffix alone matched any `.parse()` on anything named Builder,
  // Parser or Reader. A hostname-mask parser is not an XML parser.
  it('stays silent on a parser that has nothing to do with XML', () => {
    const source = [
      'package com.getcapacitor;',
      '',
      'public void setAllowedOrigins(String[] origins) {',
      '    this.mask = HostMask.Parser.parse(origins);',
      '}',
    ].join('\n');
    expect(ruleIds('a.java', source)).toHaveLength(0);
  });

  it('stays silent on a date parser and a JSON reader', () => {
    const source = [
      'LocalDate when = dateParser.parse(raw);',
      'Config cfg = jsonReader.parse(body);',
    ].join('\n');
    expect(ruleIds('a.java', source)).toHaveLength(0);
  });

  it('looks forward for an ObjectInputFilter installed after the stream', () => {
    const filtered = [
      'ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(blob));',
      'ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("a.B;!*"));',
      'return ois.readObject();',
    ].join('\n');
    expect(ruleIds('a.java', filtered)).toHaveLength(0);
  });
});

describe('prose is not code', () => {
  it('identifies triple-quoted blocks', () => {
    const lines = ['"""', 'pickle.loads is dangerous', '"""', 'x = 1'];
    expect([...proseLines(lines)]).toEqual([0, 1, 2]);
  });

  it('does not treat a single-line docstring as an open block', () => {
    expect([...proseLines(['"""one liner"""', 'x = 1'])]).toEqual([]);
  });

  it('does not report findings about a module docstring', () => {
    // A Python file whose header describes the vulnerability it contains must
    // not produce findings against that description.
    const source = [
      '"""',
      '@description Uses pickle.loads on request data and yaml.load with',
      '             a full Loader, which is remote code execution.',
      '"""',
      'import pickle',
    ].join('\n');
    expect(ruleIds('a.py', source)).toHaveLength(0);
  });
});

describe('confidence', () => {
  it('caps a bare construct at medium and escalates with untrusted input', () => {
    const bare = scanText('a.js', 'const out = yaml.load(text);');
    expect(bare[0]?.confidence).toBe('pattern');
    expect(bare[0]?.severity).toBe('medium');

    const contextual = scanText('a.js', 'const out = yaml.load(req.body.doc);');
    expect(contextual[0]?.confidence).toBe('contextual');
    expect(contextual[0]?.severity).toBe('high');
  });
});

/**
 * Accuracy fixes from the 0.4.0 triage. Every case below was a real finding
 * reported against a real repository where the code was correct; each keeps a
 * genuinely vulnerable counterpart beside it, because a rule that stops
 * reporting the safe shape by also missing the dangerous one is worse than the
 * noise it replaced.
 */
describe('unescaped HTML rendering: static assignments', () => {
  it('stays silent on an assignment with no interpolation', () => {
    // A UI built with innerHTML reports every static heading and spinner. That
    // was the largest single source of noise in the corpus.
    // threatcrush-disable-next-line js-unescaped-html-sink
    expect(ruleIds('a.js', `el.innerHTML = '<div class="spinner"></div>';`)).toHaveLength(0);
    // threatcrush-disable-next-line js-unescaped-html-sink
    expect(ruleIds('a.js', 'el.innerHTML = `<h2>Verifying your email…</h2>`;')).toHaveLength(0);
    // threatcrush-disable-next-line js-unescaped-html-sink
    expect(ruleIds('a.js', 'body.innerHTML = "<p>done</p>"')).toHaveLength(0);
  });

  it('still flags interpolation and concatenation', () => {
    // threatcrush-disable-next-line js-unescaped-html-sink
    expect(ruleIds('a.js', 'el.innerHTML = `<b>Results for ${q}</b>`;')).toContain(
      'js-unescaped-html-sink',
    );
    // threatcrush-disable-next-line js-unescaped-html-sink
    expect(ruleIds('a.js', 'el.innerHTML = "<b>Results for " + q + "</b>";')).toContain(
      'js-unescaped-html-sink',
    );
  });

  it('does not let a static line silence a dynamic one beside it', () => {
    // The reason this is a line guard and not a context guard.
    // threatcrush-disable-next-line js-unescaped-html-sink
    const source = ['el.innerHTML = "<hr>";', 'out.innerHTML = `<b>${req.query.q}</b>`;'].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-unescaped-html-sink');
  });
});

describe('unescaped HTML rendering: escaper aliases', () => {
  it('recognises a short escaper alias', () => {
    // Real code aliases the escaper because it is called on every value;
    // matching only `escapeHtml(` reported the codebases that escape most.
    expect(ruleIds('a.js', 'el.innerHTML = `<b>${esc(name)}</b>`;')).toHaveLength(0);
    expect(ruleIds('a.js', 'el.innerHTML = `<b>${aEsc(name)}</b>`;')).toHaveLength(0);
    expect(ruleIds('a.js', 'el.innerHTML = `<b>${htmlEscape(name)}</b>`;')).toHaveLength(0);
  });

  it('still flags an unescaped interpolation', () => {
    expect(ruleIds('a.js', 'el.innerHTML = `<b>${name}</b>`;')).toContain('js-unescaped-html-sink');
  });
});

describe('SSRF: building a URL is not reading one', () => {
  it('stays silent when the host is constant and only query values are set', () => {
    const source = [
      "const url = new URL('https://api.example.com/v1/bars');",
      "url.searchParams.set('symbols', symbols.join(','));",
      'const res = await fetch(url, { headers });',
    ].join('\n');
    expect(ruleIds('a.ts', source)).not.toContain('js-ssrf-outbound-request');
  });

  it('still flags a request whose URL comes from the caller', () => {
    const source = [
      'const target = req.query.url;',
      // threatcrush-disable-next-line js-ssrf-outbound-request
      'const res = await fetch(target);',
    ].join('\n');
    expect(ruleIds('a.ts', source)).toContain('js-ssrf-outbound-request');
  });

  it('treats reading searchParams as untrusted input', () => {
    const source = [
      'const target = new URL(req.url).searchParams.get("next");',
      // threatcrush-disable-next-line js-ssrf-outbound-request
      'const res = await fetch(target);',
    ].join('\n');
    expect(ruleIds('a.ts', source)).toContain('js-ssrf-outbound-request');
  });
});

describe('credentials in tests', () => {
  // Deliberately vendor-less. An earlier version of this fixture used a
  // well-formed Stripe `sk_live_` string and GitHub push protection rejected
  // the commit — correctly, which is a decent argument for the rule this file
  // is testing.
  const secret =
    'const client = new Client({ apiKey: "' + 'a1b2c3d4' + 'e5f6a7b8c9d0e1f2a3b4c5d6" });';

  it('reports a key in application code at full severity', () => {
    const [finding] = scanText('src/client.ts', secret);
    expect(finding).toBeDefined();
    expect(finding?.severity).not.toBe('low');
  });

  it('reports the same key in a test, but not at a blocking severity', () => {
    // Fixtures are the overwhelming majority, and a deliberately real-looking
    // one is sometimes the point of the test. Still reported: a genuine key
    // does get pasted into a test, and dropping it would hide that entirely.
    const [finding] = scanText('test/client.test.ts', secret);
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('low');
    expect(finding?.message).toContain('test file');
  });

  it('recognises the usual test layouts', () => {
    for (const path of [
      'test/a.test.ts',
      'tests/a.spec.js',
      'src/__tests__/a.ts',
      'spec/models/a_spec.rb',
      'pkg/thing_test.go',
      'tests/fixtures/seed.ts',
      'app/test_views.py',
    ]) {
      expect(scanText(path, secret)[0]?.severity, path).toBe('low');
    }
    expect(scanText('src/attestation.ts', secret)[0]?.severity).not.toBe('low');
  });
});

describe('escaper matching does not over-reach', () => {
  it('does not treat describe() as an escaper', () => {
    // A looser form of the alias pattern matched `describe(`, which would have
    // silenced every finding inside every test file in every repository.
    // threatcrush-disable-next-line js-unescaped-html-sink
    const source = ['describe("thing", () => {', '  el.innerHTML = `<b>${name}</b>`;'].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-unescaped-html-sink');
  });

  it('does not treat an arbitrary identifier ending in -esc- as one', () => {
    // threatcrush-disable-next-line js-unescaped-html-sink
    expect(ruleIds('a.js', 'el.innerHTML = `<b>${rescale(name)}</b>`;')).toContain(
      'js-unescaped-html-sink',
    );
  });
});
