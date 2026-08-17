import { describe, expect, it } from 'vitest';
import { scanText } from '../text';

/**
 * Same discipline as `code-rules.test.ts`: every class is tested as a *pair* —
 * the vulnerable shape and the corrected shape that sits next to it in real
 * code. A rule that only passes the first half has measured nothing, because a
 * rule matching every line passes it too.
 *
 * Positives assert with `toContain` and negatives with `not.toContain` rather
 * than on the length of the result. These sources deliberately look like real
 * server code, so unrelated rules fire on them; asserting emptiness would make
 * every test brittle to a rule it was not written about.
 */
const ruleIds = (path: string, source: string): string[] =>
  scanText(path, source).map((finding) => finding.ruleId);

describe('code execution', () => {
  it('flags a vm script whose source can be influenced', () => {
    const source = ['const script = req.body.script;', 'vm.runInNewContext(script, sandbox);'].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-vm-untrusted-execution');
  });

  it('stays silent on a vm script that is a constant', () => {
    // A plugin loader evaluating a fixed expression is not this class.
    expect(ruleIds('a.js', 'vm.runInNewContext("2 + 2", {});')).not.toContain(
      'js-vm-untrusted-execution',
    );
  });

  it('flags vm2 regardless of context', () => {
    const source = "const { NodeVM } = require('vm2');";
    expect(ruleIds('a.js', source)).toContain('js-vm2-sandbox');
  });

  it('flags a function-reconstructing deserialiser', () => {
    const source = [
      "const serialize = require('node-serialize');",
      'const data = serialize.unserialize(input);',
    ].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-function-deserialization');
  });

  it('stays silent on a project’s own deserialize helper', () => {
    // Without the import there is no reason to think this call executes
    // anything. `deserialize` is one of the most reused names in the ecosystem.
    const source = [
      'function deserialize(raw) { return JSON.parse(raw); }',
      'const data = deserialize(input);',
    ].join('\n');
    expect(ruleIds('a.js', source)).not.toContain('js-function-deserialization');
  });

  it('flags a template compiled from request data', () => {
    const source = [
      'const source = req.body.template;',
      'const render = handlebars.compile(source);',
    ].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-template-injection');
  });

  it('stays silent on a template read from disk', () => {
    const source = [
      "const source = fs.readFileSync('views/email.hbs', 'utf-8');",
      'const render = handlebars.compile(source);',
    ].join('\n');
    expect(ruleIds('a.js', source)).not.toContain('js-template-injection');
  });

  it('flags an interpolated shelljs command', () => {
    const source = ["const shell = require('shelljs');", 'shell.exec(`git checkout ${branch}`);'].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-shelljs-command-execution');
  });
});

describe('injection', () => {
  it('flags a $where predicate assembled by concatenation', () => {
    // The string holds the *other* quote character, which is the shape a
    // single combined quote class silently fails to match.
    const source = `const query = { $where: "this.name === '" + name + "'" };`;
    expect(ruleIds('a.js', source)).toContain('js-nosql-where-expression');
  });

  it('stays silent on an operator query with no $where', () => {
    const source = 'const query = { balance: { $gt: 100 } };';
    expect(ruleIds('a.js', source)).not.toContain('js-nosql-where-expression');
  });

  it('flags an XPath predicate built by concatenation', () => {
    // Backticks quote the fixture because the source line itself contains both
    // a double and a single quote — the shape the rule exists to catch.
    const source = [
      "const xpath = require('xpath');",
      `const nodes = xpath.select("//user[@name='" + name + "']", doc);`,
    ].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-xpath-injection');
  });

  it('stays silent on a constant XPath expression', () => {
    const source = ["const xpath = require('xpath');", `const nodes = xpath.select("//user[@id='42']", doc);`].join('\n');
    expect(ruleIds('a.js', source)).not.toContain('js-xpath-injection');
  });

  it('flags a regular expression compiled from request data', () => {
    const source = ['const pattern = req.query.filter;', 'const re = new RegExp(pattern);'].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-regex-from-input');
  });

  it('stays silent on a literal regular expression', () => {
    expect(ruleIds('a.js', `const re = new RegExp('^[a-z]+$');`)).not.toContain('js-regex-from-input');
  });
});

describe('XML', () => {
  it('flags a parser told to resolve entities', () => {
    expect(ruleIds('a.js', 'const doc = libxml.parseXml(body, { noent: true });')).toContain(
      'js-xml-external-entities',
    );
  });

  it('stays silent when entity resolution is left off', () => {
    expect(ruleIds('a.js', 'const doc = libxml.parseXml(body, { noent: false });')).not.toContain(
      'js-xml-external-entities',
    );
  });
});

describe('tokens', () => {
  it('flags the none algorithm', () => {
    expect(ruleIds('a.js', `const token = jwt.sign(claims, null, { algorithm: 'none' });`)).toContain(
      'js-jwt-none-algorithm',
    );
  });

  it('stays silent on a pinned real algorithm', () => {
    expect(
      ruleIds('a.js', `const claims = jwt.verify(token, pub, { algorithms: ['RS256'] });`),
    ).not.toContain('js-jwt-none-algorithm');
  });
});

describe('cryptography', () => {
  it('flags a broken cipher', () => {
    expect(ruleIds('a.js', `const c = crypto.createCipheriv('des-ede3-cbc', k, iv);`)).toContain(
      'js-broken-cipher-algorithm',
    );
  });

  it('stays silent on AES-GCM', () => {
    expect(ruleIds('a.js', `const c = crypto.createCipheriv('aes-256-gcm', k, iv);`)).not.toContain(
      'js-broken-cipher-algorithm',
    );
  });

  it('flags ECB mode', () => {
    expect(ruleIds('a.js', `const c = crypto.createCipheriv('aes-128-ecb', k, null);`)).toContain(
      'js-ecb-mode-cipher',
    );
  });

  it('flags the legacy passphrase-derived cipher API', () => {
    expect(ruleIds('a.js', `const c = crypto.createCipher('aes-256-cbc', pass);`)).toContain(
      'js-legacy-cipher-api',
    );
  });

  it('stays silent on the explicit-IV replacement', () => {
    // `createCipheriv` is the fix, and it shares a prefix with the defect.
    expect(ruleIds('a.js', `const c = crypto.createCipheriv('aes-256-cbc', k, iv);`)).not.toContain(
      'js-legacy-cipher-api',
    );
  });
});

describe('cross-site scripting', () => {
  it('flags auto-escaping turned off', () => {
    expect(ruleIds('a.js', `nunjucks.configure('views', { autoescape: false });`)).toContain(
      'js-template-autoescape-disabled',
    );
  });

  it('flags serialize-javascript in unsafe mode', () => {
    const source = [
      "const serialize = require('serialize-javascript');",
      'const payload = serialize(state, { unsafe: true });',
    ].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-serialize-javascript-unsafe');
  });

  it('flags an origin echoed back from the request', () => {
    const source = `res.setHeader('Access-Control-Allow-Origin', req.headers.origin);`;
    expect(ruleIds('a.js', source)).toContain('js-cors-origin-reflected');
  });

  it('stays silent on a constant allowed origin', () => {
    const source = `res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');`;
    expect(ruleIds('a.js', source)).not.toContain('js-cors-origin-reflected');
  });

  it('stays silent when the origin is checked against a list first', () => {
    // The one correct way to echo an origin, and the reason this rule needs a
    // guard of its own rather than the generic one.
    const source = [
      'if (allowedOrigins.includes(req.headers.origin)) {',
      `  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);`,
      '}',
    ].join('\n');
    expect(ruleIds('a.js', source)).not.toContain('js-cors-origin-reflected');
  });
});

describe('server-side request forgery', () => {
  it('flags a headless browser sent to a computed URL', () => {
    const source = [
      "const puppeteer = require('puppeteer');",
      'const target = req.query.url;',
      'await page.goto(target);',
    ].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-headless-browser-navigation');
  });

  it('stays silent on a constant URL', () => {
    const source = ["const puppeteer = require('puppeteer');", `await page.goto('https://example.com/r');`].join('\n');
    expect(ruleIds('a.js', source)).not.toContain('js-headless-browser-navigation');
  });
});

describe('archive extraction', () => {
  it('flags an entry name joined onto the destination', () => {
    const source = [
      "const unzipper = require('unzipper');",
      'const dest = path.join(outDir, entry.path);',
      'fs.writeFileSync(dest, await entry.buffer());',
    ].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-archive-entry-path');
  });

  it('stays silent when containment is checked after the join', () => {
    // The check necessarily comes *after* the path is built, which is why this
    // rule looks forward as well as back.
    const source = [
      "const unzipper = require('unzipper');",
      'const dest = path.join(outDir, entry.path);',
      "if (!dest.startsWith(outDir + path.sep)) throw new Error('unsafe entry');",
    ].join('\n');
    expect(ruleIds('a.js', source)).not.toContain('js-archive-entry-path');
  });
});

describe('Electron', () => {
  it('flags node access in the renderer', () => {
    expect(ruleIds('a.js', 'webPreferences: { nodeIntegration: true },')).toContain(
      'js-electron-node-integration',
    );
  });

  it('stays silent on the hardened defaults', () => {
    expect(
      ruleIds('a.js', 'webPreferences: { nodeIntegration: false, contextIsolation: true },'),
    ).not.toContain('js-electron-node-integration');
  });

  it('flags web security switched off', () => {
    expect(ruleIds('a.js', 'webPreferences: { webSecurity: false },')).toContain(
      'js-electron-web-security-disabled',
    );
  });

  it('flags openExternal with a computed target', () => {
    const source = ['const target = req.query.next;', 'shell.openExternal(target);'].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-electron-open-external');
  });
});

describe('hardening and resource limits', () => {
  it('flags a security header explicitly disabled', () => {
    expect(ruleIds('a.js', 'app.use(helmet({ frameguard: false }));')).toContain(
      'js-helmet-protection-disabled',
    );
  });

  it('flags a buffer write with bounds checking off', () => {
    expect(ruleIds('a.js', 'buf.writeUInt32BE(value, 0, true);')).toContain(
      'js-buffer-bounds-check-disabled',
    );
  });

  it('stays silent on a checked buffer write', () => {
    expect(ruleIds('a.js', 'buf.writeUInt32BE(value, 0);')).not.toContain(
      'js-buffer-bounds-check-disabled',
    );
  });

  it('flags an unzeroed allocation', () => {
    expect(ruleIds('a.js', 'const buf = Buffer.allocUnsafe(1024);')).toContain(
      'js-uninitialized-buffer',
    );
  });

  it('stays silent on the zeroing allocator', () => {
    expect(ruleIds('a.js', 'const buf = Buffer.alloc(1024);')).not.toContain('js-uninitialized-buffer');
  });

  it('stays silent when the allocation is copied into before it escapes', () => {
    // The shape this rule was reported wrong on: a ring-buffer read that
    // allocates at the exact length it is about to write, wrap-around and all.
    const source = [
      'function copy(fromAbsolute, length) {',
      '  const out = Buffer.allocUnsafe(length);',
      '  if (length === 0) return out;',
      '  const retained = Math.min(total, capacity);',
      '  const rel = fromAbsolute - (total - retained);',
      '  const start = (writePos - retained + rel + capacity * 2) % capacity;',
      '  const firstLen = Math.min(length, capacity - start);',
      '  buf.copy(out, 0, start, start + firstLen);',
      '  if (firstLen < length) buf.copy(out, firstLen, 0, length - firstLen);',
      '  return out;',
      '}',
    ].join('\n');
    expect(ruleIds('a.js', source)).not.toContain('js-uninitialized-buffer');
  });

  it('stays silent on an allocation filled in the same expression', () => {
    expect(ruleIds('a.js', 'const buf = Buffer.allocUnsafe(1024).fill(0);')).not.toContain(
      'js-uninitialized-buffer',
    );
  });

  it('stays silent on an allocation filled through its own methods', () => {
    const source = ['const header = Buffer.allocUnsafe(8);', 'header.writeUInt32BE(len, 0);', 'header.writeUInt32BE(crc, 4);'].join('\n');
    expect(ruleIds('a.js', source)).not.toContain('js-uninitialized-buffer');
  });

  it('still flags when the write lands in a different buffer', () => {
    // The guard is bound to the name that was allocated. A fill of something
    // else nearby is not evidence about this one, and reading it as evidence
    // is how a name-blind window guard exonerates the real defect.
    const source = [
      'const leaked = Buffer.allocUnsafe(1024);',
      'const other = Buffer.alloc(1024);',
      'other.fill(0);',
      'socket.write(leaked);',
    ].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-uninitialized-buffer');
  });

  it('still flags an allocation that escapes with nothing bound to fill', () => {
    // No binding to follow, so nothing can be shown to write into it — and
    // handing unzeroed heap straight to a caller is the defect itself.
    expect(ruleIds('a.js', 'return Buffer.allocUnsafe(size);')).toContain(
      'js-uninitialized-buffer',
    );
    expect(ruleIds('a.js', 'socket.write(Buffer.allocUnsafe(size));')).toContain(
      'js-uninitialized-buffer',
    );
  });

  it('still flags an allocation that is never written to', () => {
    const source = ['const buf = Buffer.allocUnsafe(1024);', 'res.end(buf);'].join('\n');
    expect(ruleIds('a.js', source)).toContain('js-uninitialized-buffer');
  });

  it('flags an ineffective body limit', () => {
    expect(ruleIds('a.js', `app.use(express.json({ limit: '50mb' }));`)).toContain(
      'js-oversized-request-body-limit',
    );
  });

  it('stays silent on a limit that actually limits', () => {
    expect(ruleIds('a.js', `app.use(express.json({ limit: '1mb' }));`)).not.toContain(
      'js-oversized-request-body-limit',
    );
  });
});

describe('information disclosure', () => {
  it('flags a stack trace returned through a status chain', () => {
    expect(ruleIds('a.js', 'res.status(500).send(err.stack);')).toContain('js-error-detail-returned');
  });

  it('stays silent on a generic error message', () => {
    expect(ruleIds('a.js', `res.status(500).json({ message: 'Internal server error' });`)).not.toContain(
      'js-error-detail-returned',
    );
  });
});

describe('the shared guard does not silence a whole neighbourhood', () => {
  it('keeps reporting near a CORS header line', () => {
    // Regression. `GENERIC_GUARD` is case-insensitive and its allow-list
    // heuristic matched the "Allow" inside `Access-Control-Allow-Origin`.
    // Since the guard is tested against an 8-line window, one header line
    // suppressed every guardable rule around it — silently, and
    // indistinguishably from having found nothing.
    const source = [
      "app.post('/restore', (req, res) => {",
      "  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);",
      "  const token = jwt.sign({ sub: req.query.id }, null, { algorithm: 'none' });",
      '  res.status(500).send(err.stack);',
      '});',
    ].join('\n');

    const ids = ruleIds('a.js', source);
    expect(ids).toContain('js-jwt-none-algorithm');
    expect(ids).toContain('js-error-detail-returned');
  });

  it('still guards on a real allow-list in code', () => {
    // The fix is scoped to the CORS header prefix, so an actual allow-list
    // must keep guarding exactly as before. Asserted with code rather than a
    // comment: comment lines are already excluded from the guard window on
    // purpose, since a comment mentioning an allow-list is not one.
    const source = ["const allowlist = ['a.example.com'];", 'const re = new RegExp(req.query.q);'].join('\n');
    expect(ruleIds('a.js', source)).not.toContain('js-regex-from-input');
  });
});

describe('confidence model', () => {
  it('caps a bare construct at medium and escalates only with visible input', () => {
    const bare = scanText('a.js', 'const re = new RegExp(pattern);').find(
      (f) => f.ruleId === 'js-regex-from-input',
    );
    // `needsContext` means the bare form is not reported at all, which is the
    // stronger version of the cap.
    expect(bare).toBeUndefined();

    const withInput = scanText(
      'a.js',
      ['const pattern = req.query.filter;', 'const re = new RegExp(pattern);'].join('\n'),
    ).find((f) => f.ruleId === 'js-regex-from-input');
    expect(withInput?.confidence).toBe('contextual');
  });

  it('reports an inherent rule as evidence at its declared severity', () => {
    const finding = scanText('a.js', "const { NodeVM } = require('vm2');").find(
      (f) => f.ruleId === 'js-vm2-sandbox',
    );
    expect(finding?.confidence).toBe('evidence');
    expect(finding?.severity).toBe('high');
  });
});
