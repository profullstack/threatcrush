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
