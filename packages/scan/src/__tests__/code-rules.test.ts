import { describe, expect, it } from 'vitest';
import { CODE_RULES, proseLines } from '../code-rules';
import { languageOf, scanText } from '../text';
import type { ScanLanguage } from '../types';

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

  // A SQL verb is not SQL until it has the clause that makes it a statement.
  // These are template literals whose only SQL-ness is an English word that
  // happens to be a verb — real findings from ShortsStudio and capacitor.
  it('does not read a verb-shaped English word as SQL', () => {
    // `insert` in a React key; `INSERT` alone no longer qualifies — it needs INTO.
    expect(ruleIds('a.jsx', 'key={`insert-${insertIndex}`}')).toHaveLength(0);
    // `Update`/`Delete`/`drop` as prose or identifiers.
    expect(ruleIds('a.js', 'log.info(`Update finished in ${ms}ms`);')).toHaveLength(0);
    expect(ruleIds('a.js', 'const cls = `dropdown-${open ? "open" : "shut"}`;')).toHaveLength(0);
    expect(ruleIds('a.ts', 'const label = `Delete ${count} items?`;')).toHaveLength(0);
  });

  it('still flags a genuine INSERT INTO and DROP TABLE built by interpolation', () => {
    // The structured forms must survive — the fix narrows, it does not disable.
    expect(ruleIds('a.js', 'db.query(`INSERT INTO users (name) VALUES (\'${name}\')`);')).toContain(
      'sql-template-interpolation',
    );
    expect(ruleIds('a.js', 'db.query(`DROP TABLE ${table}`);')).toContain(
      'sql-template-interpolation',
    );
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

  it('does not read a C pointer cast as a nested quantifier', () => {
    // `(void *)*memptr64` is a cast followed by a dereference, and it matches
    // the quantifier pattern character for character: `(`, text, `*`, `)`, `*`.
    // Unscoped, the rule turned every one of these into a ReDoS finding — its
    // only hit across inspektor-gadget's 1186 files was this line of eBPF C.
    const source = 'if (bpf_probe_read_user(&addr, sizeof(void *), (void *)*memptr64))';
    expect(ruleIds('program.bpf.c', source)).toHaveLength(0);
    expect(ruleIds('deref.c', 'x = *(char *)*p;')).toHaveLength(0);
  });

  it('only detects nested quantifiers in regex construction', () => {
    // Build the fixture at runtime so CodeQL does not correctly report the
    // deliberately unsafe regex embedded in this scanner regression test.
    const nestedRegex = ['const pattern = /^(', 'a', '+)+$/;'].join('');
    expect(ruleIds('a.ts', nestedRegex)).toContain('redos-nested-quantifier');
    expect(ruleIds('a.ts', 'const count = (a + b) * c;')).not.toContain('redos-nested-quantifier');
    expect(ruleIds('a.java', 'File.createTempFile("report", ".tmp");')).not.toContain(
      'insecure-temp-file',
    );
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

describe('shell', () => {
  it('flags network output piped into a shell', () => {
    expect(ruleIds('i.sh', 'curl -fsSL https://example.invalid/i.sh | bash')).toContain(
      'sh-remote-script-execution',
    );
    expect(ruleIds('i.sh', 'wget -qO- https://example.invalid/i.sh | su' + 'do sh')).toContain(
      'sh-remote-script-execution',
    );
  });

  it('does not flag a download piped to something other than a shell', () => {
    expect(ruleIds('i.sh', 'curl -fsSL https://example.invalid/v.json | jq -r .version')).toEqual(
      [],
    );
    expect(ruleIds('i.sh', 'curl -fsSL https://example.invalid/f.tgz | sha256sum -c -')).toEqual([]);
  });

  it('flags eval handed an expansion', () => {
    expect(ruleIds('i.sh', 'eval "$cmd"')).toContain('sh-eval-expansion');
    expect(ruleIds('i.sh', 'eval $USER_SUPPLIED')).toContain('sh-eval-expansion');
    expect(ruleIds('i.sh', 'eval "$(build_command "$1")"')).toContain('sh-eval-expansion');
  });

  // Bash's ordinary way to build a numeric range. Every expansion sits inside
  // `$((…))`, where a `;` is a syntax error rather than a second command — and
  // a line-wide `\beval\b.*\$` reported this 355 times in one real script.
  it('does not flag the dynamic brace-range idiom', () => {
    expect(ruleIds('i.sh', 'for r in $(eval echo {$(($k + 1))..$(($k + $n - 1))}); do')).toEqual([]);
    expect(ruleIds('i.sh', 'for q in $(eval echo {1..$(($k + $l - 2))}); do')).toEqual([]);
  });

  it('does not flag the documented shell-init idiom', () => {
    expect(ruleIds('i.sh', 'eval "$(dircolors -b)"')).toEqual([]);
    expect(ruleIds('i.sh', 'eval "$(pyenv init -)"')).toEqual([]);
  });

  it('flags an unquoted expansion in a recursive remove, and not a quoted one', () => {
    expect(ruleIds('i.sh', 'rm -rf $BUILD_DIR/output')).toContain(
      'sh-unquoted-expansion-destructive',
    );
    // The correct form. `[^"'\n]*?` cannot cross the quote, so the match never
    // reaches the expansion.
    expect(ruleIds('i.sh', 'rm -rf "$BUILD_DIR/output"')).toEqual([]);
    expect(ruleIds('i.sh', 'rm -rf "${BUILD_DIR:?}/output"')).toEqual([]);
  });

  it('flags disabled certificate verification over TLS', () => {
    expect(ruleIds('i.sh', 'curl -k -L https://example.invalid/a.tgz > a.tgz')).toContain(
      'sh-insecure-transport-flag',
    );
    expect(ruleIds('i.sh', 'wget --no-check-certificate https://example.invalid/a.tgz')).toContain(
      'sh-insecure-transport-flag',
    );
  });

  // `-k` skips a check that plain HTTP never performs. Reporting both put two
  // findings on one line, one recommending a fix that would change nothing.
  it('reports a plain-HTTP download once, as plaintext rather than a skipped check', () => {
    expect(ruleIds('i.sh', 'curl -k -f http://example.invalid/a.gz > a.gz')).toEqual([
      'sh-plaintext-download',
    ]);
  });

  it('does not flag plain HTTP to loopback', () => {
    expect(ruleIds('i.sh', 'curl -s http://127.0.0.1:8080/health')).toEqual([]);
    expect(ruleIds('i.sh', 'curl -s http://localhost:3000/ready')).toEqual([]);
  });

  it('flags world-writable permissions', () => {
    expect(ruleIds('i.sh', 'chmod 777 /var/cache/app')).toContain('sh-world-writable-permissions');
    expect(ruleIds('i.sh', 'chmod -R a+rwx /srv/data')).toContain('sh-world-writable-permissions');
    expect(ruleIds('i.sh', 'chmod 0755 /usr/local/bin/app')).toEqual([]);
  });

  it('flags a predictable temp path unless mktemp made it', () => {
    expect(ruleIds('i.sh', 'echo "$payload" > /tmp/app-build.log')).toContain(
      'sh-predictable-temp-path',
    );
    const guarded = ['tmp=$(mktemp -d)', 'echo "$payload" > /tmp/app-build.log'].join('\n');
    expect(ruleIds('i.sh', guarded)).toEqual([]);
  });

  it('does not apply shell rules to a language that merely mentions the same words', () => {
    expect(ruleIds('a.js', 'const cmd = "curl -k https://x.invalid | bash";')).not.toContain(
      'sh-remote-script-execution',
    );
  });
});

/**
 * Severity must not depend on what happens to sit near a finding.
 *
 * Both halves of this came out of one file. `ralyodio/debtap` reported the
 * same `curl -k` defect as `high` on some lines and `medium` on others,
 * decided by distance from a `gawk '{print $1}'` one-liner: the awk field
 * reference was read as a shell positional parameter, and the guard window
 * spread that escalation to its neighbours.
 */
describe('severity is not decided by neighbouring code', () => {
  const findings = (path: string, source: string) => scanText(path, source);

  it('does not read an awk field reference as a shell positional parameter', () => {
    // The shell expands nothing inside single quotes, so `$1` here is two
    // characters. A rule that is *not* inherent must stay capped at medium.
    const withAwk = [
      "version=$(curl -s https://x.invalid | gawk -F '=' '{print $2}' | gawk '{print $1}')",
      'eval "$cmd"',
    ].join('\n');
    const evalFinding = findings('a.sh', withAwk).find((f) => f.ruleId === 'sh-eval-expansion');
    expect(evalFinding?.confidence).toBe('pattern');
    expect(evalFinding?.severity).toBe('medium');
  });

  it('still escalates on a real positional parameter', () => {
    // The exemption is for quoted text only — it must not become a way to hide
    // genuine untrusted input.
    const real = ['target="$1"', 'eval "$target"'].join('\n');
    const evalFinding = findings('a.sh', real).find((f) => f.ruleId === 'sh-eval-expansion');
    expect(evalFinding?.confidence).toBe('contextual');
    expect(evalFinding?.severity).toBe('high');
  });

  it('reports an inherent rule at its declared severity either way', () => {
    // `curl -k` against HTTPS is interceptable whatever surrounds it.
    const bare = findings('a.sh', 'curl -k -L https://x.invalid/a.tgz > a.tgz')[0];
    const nearInput = findings(
      'a.sh',
      ['target="$1"', 'curl -k -L https://x.invalid/a.tgz > a.tgz'].join('\n'),
    ).find((f) => f.ruleId === 'sh-insecure-transport-flag');

    expect(bare?.confidence).toBe('evidence');
    expect(bare?.severity).toBe('high');
    expect(nearInput?.severity).toBe(bare?.severity);
  });

  it('applies the same treatment to a broken cipher', () => {
    const finding = findings('A.java', 'Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");')[0];
    expect(finding?.confidence).toBe('evidence');
    expect(finding?.severity).toBe('high');
  });

  it('leaves context-dependent rules capped, so this is not a blanket escalation', () => {
    // `js-unescaped-html-sink` is not inherent: a static assignment says
    // nothing about attacker data, and it must still cap at medium.
    const finding = findings('a.js', 'el.innerHTML = "<b>" + name + "</b>";')[0];
    expect(finding?.confidence).toBe('pattern');
    expect(finding?.severity).toBe('medium');
  });
});

describe('php', () => {
  it('flags SQL built by interpolation and not a prepared statement', () => {
    expect(ruleIds('a.php', '$r = mysqli_query($db, "SELECT * FROM users WHERE id = $id");')).toContain(
      'php-sql-interpolation',
    );
    expect(ruleIds('a.php', '$r = $db->query("SELECT * FROM users WHERE id = {$id}");')).toContain(
      'php-sql-interpolation',
    );
    // The correct form binds separately, so its query string holds no variable.
    expect(
      ruleIds('a.php', '$s = $db->prepare("SELECT * FROM users WHERE id = ?"); $s->execute([$id]);'),
    ).toEqual([]);
  });

  it('flags a shell command built from a variable, unless it is escaped', () => {
    expect(ruleIds('a.php', 'system("convert $file out.png");')).toContain(
      'php-shell-exec-interpolation',
    );
    expect(ruleIds('a.php', 'system("convert " . escapeshellarg($file) . " out.png");')).toEqual([]);
  });

  it('flags dynamic code execution', () => {
    // threatcrush-disable-next-line js-dynamic-code-execution  PHP fixture, not JS
    expect(ruleIds('a.php', 'eval($code);')).toContain('php-dynamic-code-execution');
    // threatcrush-disable-next-line js-dynamic-code-execution  PHP fixture, not JS
    expect(ruleIds('a.php', 'eval("return $expr;");')).toContain('php-dynamic-code-execution');
  });

  it('flags an include path built from a variable, unless basename bounds it', () => {
    expect(ruleIds('a.php', 'include $_GET["page"] . ".php";')).toContain(
      'php-dynamic-file-inclusion',
    );
    expect(ruleIds('a.php', 'include "pages/$page.php";')).toContain('php-dynamic-file-inclusion');
    expect(ruleIds('a.php', 'include "pages/" . basename($page) . ".php";')).toEqual([]);
  });

  it('flags unserialize on request data unless classes are disallowed', () => {
    expect(ruleIds('a.php', '$o = unserialize($_COOKIE["prefs"]);')).toContain(
      'php-unserialize-untrusted',
    );
    expect(
      ruleIds('a.php', '$o = unserialize($_COOKIE["prefs"], ["allowed_classes" => false]);'),
    ).toEqual([]);
  });

  it('flags request data echoed without escaping', () => {
    expect(ruleIds('a.php', 'echo "Hello " . $_GET["name"];')).toContain('php-unescaped-output');
    expect(ruleIds('a.php', 'echo htmlspecialchars($_GET["name"]);')).toEqual([]);
  });

  it('flags a file path taken straight from the request', () => {
    expect(ruleIds('a.php', 'readfile($_GET["f"]);')).toContain('php-request-path-traversal');
    expect(ruleIds('a.php', 'readfile("uploads/" . basename($_GET["f"]));')).toEqual([]);
  });

  it('flags request data expanded into locals', () => {
    expect(ruleIds('a.php', 'extract($_POST);')).toContain('php-variable-injection');
  });
});

describe('java', () => {
  it('flags Runtime.exec built by concatenation, and not the argv form', () => {
    // threatcrush-disable-next-line js-shell-exec-interpolation  Java fixture, not JS
    const vulnerable = 'Process p = Runtime.getRuntime().exec("git checkout " + branch);';
    expect(ruleIds('A.java', vulnerable)).toContain('java-runtime-exec-concatenation');
    // The array form passes argv and is the fix.
    expect(
      ruleIds('A.java', 'Process p = Runtime.getRuntime().exec(new String[]{"git", "checkout", branch});'),
    ).toEqual([]);
  });

  it('flags an outbound request to a computed URL, and not a constant one', () => {
    expect(
      ruleIds('A.java', 'URL u = new URL(request.getParameter("target")); u.openConnection();'),
    ).toContain('java-ssrf-outbound-request');
    expect(ruleIds('A.java', 'URL u = new URL("https://api.example.com/v1/status");')).toEqual([]);
  });

  it('flags a file path built from request data unless containment is checked', () => {
    expect(
      ruleIds('A.java', 'File f = new File(baseDir + request.getParameter("name"));'),
    ).toContain('java-request-path-traversal');
    const guarded = [
      'File f = new File(baseDir + request.getParameter("name"));',
      'if (!f.getCanonicalPath().startsWith(baseDir)) throw new IOException("outside");',
    ].join('\n');
    expect(ruleIds('A.java', guarded)).toEqual([]);
  });

  it('flags broken ciphers and ECB, including the bare AES default', () => {
    expect(ruleIds('A.java', 'Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");')).toContain(
      'java-broken-cipher',
    );
    expect(ruleIds('A.java', 'Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");')).toContain(
      'java-broken-cipher',
    );
    // The JCE resolves a bare "AES" to AES/ECB/PKCS5Padding.
    expect(ruleIds('A.java', 'Cipher c = Cipher.getInstance("AES");')).toContain(
      'java-broken-cipher',
    );
    expect(ruleIds('A.java', 'Cipher c = Cipher.getInstance("AES/GCM/NoPadding");')).toEqual([]);
  });
});

describe('go', () => {
  it('flags a file path built from request data unless containment is checked', () => {
    expect(ruleIds('a.go', 'f, err := os.Open(filepath.Join(root, r.URL.Query().Get("f")))')).toContain(
      'go-request-path-traversal',
    );
    const guarded = [
      'if !strings.HasPrefix(filepath.Clean(p), root) { return errBadPath }',
      'f, err := os.Open(filepath.Join(root, r.URL.Query().Get("f")))',
    ].join('\n');
    expect(ruleIds('a.go', guarded)).toEqual([]);
  });

  it('flags template.HTML on a variable but not on a literal', () => {
    expect(ruleIds('a.go', 'out := template.HTML(r.FormValue("bio"))')).toContain(
      'go-template-escaping-bypass',
    );
    // A constant the author wrote is not a finding.
    expect(ruleIds('a.go', 'out := template.HTML("<br>")')).toEqual([]);
    expect(ruleIds('a.go', 'out := template.HTML(`<hr>`)')).toEqual([]);
  });
});

/**
 * Every language the scanner claims to understand must have at least one rule
 * that targets it.
 *
 * This exists because the claim and the rules were never checked against each
 * other, and two languages silently had none. `shell` went first: `.sh` files
 * were read, matched against secret rules, and reported clean no matter what
 * the code did. `php` was still in that state afterwards. Both looked exactly
 * like a supported language from the outside — which is the failure mode, not
 * a missing feature.
 *
 * `config` and `other` are excluded deliberately: they are covered by the
 * secret and manifest rule sets, which are not in CODE_RULES.
 */
describe('language coverage', () => {
  const REPRESENTATIVE = [
    'a.js', 'a.ts', 'a.jsx', 'a.tsx', 'a.py', 'a.rb', 'a.go', 'a.java', 'a.kt', 'a.php', 'a.sh',
  ];
  const NOT_CODE_RULE_TERRITORY: readonly ScanLanguage[] = ['config', 'other'];

  const targeted = new Set<ScanLanguage>();
  for (const rule of CODE_RULES) for (const language of rule.languages ?? []) targeted.add(language);

  const claimed = [...new Set(REPRESENTATIVE.map(languageOf))].filter(
    (language) => !NOT_CODE_RULE_TERRITORY.includes(language),
  );

  it.each(claimed)('%s has at least one rule targeting it', (language) => {
    expect(targeted.has(language)).toBe(true);
  });

  it('covers every representative extension', () => {
    // Guards the guard: if `languageOf` stopped mapping these, `claimed` would
    // collapse to nothing and the assertions above would vacuously pass.
    expect(claimed.length).toBeGreaterThanOrEqual(7);
  });
});

describe('python weak crypto', () => {
  it('flags a broken cipher and ECB mode, not a safe AES mode', () => {
    expect(ruleIds('a.py', 'cipher = DES.new(DEMO_KEY_8, DES.MODE_ECB)')).toContain(
      'py-broken-cipher',
    );
    expect(ruleIds('a.py', 'cipher = ARC4.new(DEMO_KEY_16)')).toContain('py-broken-cipher');
    expect(ruleIds('a.py', 'cipher = AES.new(key, AES.MODE_ECB)')).toContain('py-broken-cipher');
    expect(ruleIds('a.py', 'cipher = AES.new(key, AES.MODE_GCM)')).toEqual([]);
  });

  it('flags MD5/SHA-1 unless marked non-security', () => {
    expect(ruleIds('a.py', 'digest = hashlib.md5(artifact).hexdigest()')).toContain('py-weak-hash');
    expect(ruleIds('a.py', 'digest = hashlib.sha1(artifact).hexdigest()')).toContain('py-weak-hash');
    // SHA-256 is fine; and `usedforsecurity=False` is Python's own opt-out.
    expect(ruleIds('a.py', 'digest = hashlib.sha256(artifact).hexdigest()')).toEqual([]);
    expect(ruleIds('a.py', 'key = hashlib.md5(url, usedforsecurity=False).hexdigest()')).toEqual([]);
  });

  it('flags a PRNG seeded from the clock, not a fixed reproducible seed', () => {
    expect(ruleIds('a.py', 'random.seed(int(time.time()))')).toContain('py-predictable-random-seed');
    expect(ruleIds('a.py', 'random.seed(datetime.now().timestamp())')).toContain(
      'py-predictable-random-seed',
    );
    // A constant seed is deliberate reproducibility (tests, simulations).
    expect(ruleIds('a.py', 'random.seed(42)')).toEqual([]);
  });

  it('still catches the same-line credential=random shape via the generic rule', () => {
    // The role on the line is what the engine can see without trusting a name.
    expect(ruleIds('a.py', 'token = "".join(random.choice(A) for _ in range(32))')).toContain(
      'insecure-randomness-for-secret',
    );
  });

  // Documented boundary, not an oversight: when the security role of a
  // `random`-drawn value lives only in the enclosing function's name
  // (`generate_session_id`, `generate_mfa_code`), it is out of reach. Guard
  // windows deliberately exclude definition lines — a name is not evidence,
  // the same reason a `def sanitize_…` does not count as sanitisation — so
  // there is no line-level signal left to key on.
  it('does not flag a bare random draw whose role is only in the function name', () => {
    expect(ruleIds('a.py', 'def generate_session_id():\n    return "%x" % random.getrandbits(128)')).toEqual(
      [],
    );
    expect(ruleIds('a.py', 'def pick_color():\n    return random.choice(PALETTE)')).toEqual([]);
  });

  it('does not flag the CSPRNG the fixture offers as the fix', () => {
    expect(ruleIds('a.py', 'def new_token():\n    return secrets.token_urlsafe(32)')).toEqual([]);
    expect(ruleIds('a.py', 'def new_id():\n    return secrets.token_hex(16)')).toEqual([]);
  });
});

describe('misconfiguration, weak crypto and injection', () => {
  it('flags debug mode enabled, not disabled', () => {
    expect(ruleIds('a.py', 'app.config["DEBUG"] = True')).toContain('py-framework-debug-enabled');
    expect(ruleIds('a.py', 'app.run(host="0.0.0.0", debug=True)')).toContain(
      'py-framework-debug-enabled',
    );
    expect(ruleIds('a.py', 'app.config["DEBUG"] = False')).toEqual([]);
  });

  it('flags a wildcard CORS origin with credentials, not an explicit origin', () => {
    expect(ruleIds('a.js', "app.use(cors({ origin: '*', credentials: true }));")).toContain(
      'js-cors-wildcard-credentials',
    );
    expect(
      ruleIds('a.js', "app.use(cors({ origin: 'https://app.example.com', credentials: true }));"),
    ).toEqual([]);
  });

  it('flags a cookie set with secure:false', () => {
    expect(ruleIds('a.js', "res.cookie('sid', v, { secure: false });")).toContain(
      'js-cookie-insecure-flag',
    );
    expect(ruleIds('a.js', "res.cookie('sid', v, { secure: true, httpOnly: true });")).toEqual([]);
  });

  it('flags a hardcoded key literal in crypto code, not a runtime key', () => {
    const vuln = ["const crypto = require('crypto');", "const key = Buffer.from('1111111111111111');"].join(
      '\n',
    );
    expect(ruleIds('a.js', vuln)).toContain('js-hardcoded-crypto-key');
    const safe = [
      "const crypto = require('crypto');",
      'const cipher = crypto.createCipheriv(alg, runtimeKey, iv);',
    ].join('\n');
    expect(ruleIds('a.js', safe)).not.toContain('js-hardcoded-crypto-key');
  });

  it('flags a hardcoded secret literal, not a provider call', () => {
    expect(ruleIds('a.py', 'app.config["SECRET_KEY"] = "hardcoded-signing-secret"')).toContain(
      'py-hardcoded-secret-key',
    );
    expect(ruleIds('a.py', 'app.config["SECRET_KEY"] = secret_provider("session-key")')).toEqual([]);
  });

  it('flags an LDAP filter built by interpolation unless the value is escaped', () => {
    expect(ruleIds('a.py', 'f = f"(&(objectClass=person)(uid={account_name}))"')).toContain(
      'py-ldap-injection',
    );
    const safe = [
      'escaped = escape_filter_chars(name)',
      'f = f"(&(objectClass=person)(uid={escaped}))"',
    ].join('\n');
    expect(ruleIds('a.py', safe)).not.toContain('py-ldap-injection');
  });

  it('flags an unescaped filter even when the module imports an escaper', () => {
    // The guard is an escaper *call*: a module-level `import escape_filter_chars`
    // must not exonerate a filter that never calls it. (An earlier `/escap/i`
    // guard was defeated exactly here.)
    const src = [
      'from ldap.filter import escape_filter_chars',
      'f = f"(&(objectClass=person)(uid={account_name}))"',
    ].join('\n');
    expect(ruleIds('a.py', src)).toContain('py-ldap-injection');
  });

  it('flags an XPath expression with an inner quote around the interpolation', () => {
    // The `"`-delimited f-string contains a `'`; a class that excluded both
    // quotes stopped before the interpolation and missed it.
    expect(ruleIds('a.py', "expr = f\"//user[name/text()='{username}']\"")).toContain(
      'py-xpath-injection',
    );
    expect(ruleIds('a.py', 'result = doc.xpath("//user[name=$n]", n=username)')).toEqual([]);
  });

  it('flags a NoSQL query built from request data', () => {
    expect(ruleIds('a.js', 'return users.find(req.body.filter);')).toContain('js-nosql-injection');
    expect(ruleIds('a.js', 'return users.find({ _id: sanitize(req.params.id) });')).toEqual([]);
  });

  it('flags a URL built from the Host header', () => {
    expect(ruleIds('a.js', 'return `https://${req.headers.host}/reset?token=${token}`;')).toContain(
      'js-host-header-trust',
    );
    expect(ruleIds('a.js', 'return `${config.baseUrl}/reset?token=${token}`;')).toEqual([]);
  });

  it('flags a fast hash on a password, not a slow KDF', () => {
    expect(ruleIds('a.py', 'digest = hashlib.sha256(password_bytes).hexdigest()')).toContain(
      'py-fast-password-hash',
    );
    const safe = [
      'import hashlib',
      'digest = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, 200000)',
    ].join('\n');
    expect(ruleIds('a.py', safe)).not.toContain('py-fast-password-hash');
  });

  it('flags a plaintext password kept in a record', () => {
    expect(
      ruleIds('a.py', 'record = {"email": form["email"], "password": form["password"]}'),
    ).toContain('py-plaintext-password-retained');
    expect(ruleIds('a.py', 'record = {"email": form["email"], "password_hash": derived}')).toEqual([]);
  });

  it('flags == on a signature, not a length check or timingSafeEqual', () => {
    expect(ruleIds('a.js', 'return expectedSignature === suppliedSignature;')).toContain(
      'js-timing-unsafe-mac-compare',
    );
    expect(ruleIds('a.js', 'const ok = a.length === b.length;')).toEqual([]);
    expect(
      ruleIds('a.js', 'return crypto.timingSafeEqual(expectedSignature, suppliedSignature);'),
    ).toEqual([]);
  });

  it('flags a static IV, not a random one', () => {
    const vuln = ["const crypto = require('crypto');", 'const fixedIv = Buffer.alloc(16, 0);'].join('\n');
    expect(ruleIds('a.js', vuln)).toContain('js-predictable-cipher-iv');
    const safe = ["const crypto = require('crypto');", 'const iv = crypto.randomBytes(16);'].join('\n');
    expect(ruleIds('a.js', safe)).not.toContain('js-predictable-cipher-iv');
  });

  it('flags mass assignment from the request body, not from an allow-list', () => {
    expect(ruleIds('a.js', 'Object.assign(account, req.body);')).toContain('js-mass-assignment');
    expect(ruleIds('a.js', 'Object.assign(account, allowed);')).toEqual([]);
  });

  it('flags a response header set straight from request input', () => {
    expect(ruleIds('a.js', "res.setHeader('X-Name', req.query.name);")).toContain('js-header-injection');
    expect(ruleIds('a.js', "res.setHeader('X-Name', sanitized);")).toEqual([]);
  });
});
