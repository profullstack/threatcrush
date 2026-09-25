import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { detectSQLi, detectXSS } from '../libinjection.js';

// libinjection's own test vectors (vendor/libinjection, BSD-3-Clause), run
// against the checked-in libinjection.wasm the way upstream's harnesses run
// them against the C library.
const VENDOR = join(__dirname, '..', '..', '..', '..', 'vendor', 'libinjection');
const rtrim = (s: string) => s.replace(/[ \n\t\r]+$/, '');

describe('libinjection.wasm against libinjection tests/test-sqli-*.txt', () => {
  // src/testdriver.c, test type 2: the fingerprint when libinjection_sqli says
  // SQLi, else nothing.
  const files = readdirSync(join(VENDOR, 'tests')).filter((f) => f.startsWith('test-sqli-'));

  it.each(files)('%s', (file) => {
    const text = readFileSync(join(VENDOR, 'tests', file), 'latin1');
    const m = /^--TEST--\n[\s\S]*?--INPUT--\n([\s\S]*?)--EXPECTED--\n([\s\S]*)$/.exec(text);
    expect(m, 'test file layout').not.toBeNull();
    const { result, fingerprint } = detectSQLi(rtrim(m![1]));
    expect(result ? fingerprint : '').toBe(rtrim(m![2]));
  });
});

/** src/reader.c's modp_url_decode, including its `i + 2 < len` boundary. */
function readerUrlDecode(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; ) {
    const hex = s.slice(i + 1, i + 3);
    if (s[i] === '+') {
      out += ' ';
      i += 1;
    } else if (s[i] === '%' && i + 2 < s.length && /^[0-9A-Fa-f]{2}$/.test(hex)) {
      out += String.fromCharCode(parseInt(hex, 16));
      i += 3;
    } else {
      out += s[i];
      i += 1;
    }
  }
  return out;
}

/** The inputs of data/ sample files as src/reader.c reads them: blank and # lines skipped, URL-decoded. */
function samples(prefix: string): string[] {
  return readdirSync(join(VENDOR, 'data'))
    .filter((f) => f.startsWith(prefix))
    .flatMap((f) => readFileSync(join(VENDOR, 'data', f), 'latin1').split('\n'))
    .map(rtrim)
    .filter((l) => l && !l.startsWith('#'))
    .map(readerUrlDecode);
}

describe('libinjection.wasm against libinjection data/ samples', () => {
  // Upstream's src/test-samples-*.sh pass while at most that many inputs of
  // all their sample files are misjudged; a subset is vendored.
  it('finds SQLi in the SQLi samples (test-samples-sqli-positive.sh: -m 18)', () => {
    const inputs = samples('sqli-');
    expect(inputs.length).toBeGreaterThan(500);
    expect(inputs.filter((s) => detectSQLi(s).result === 0).length).toBeLessThanOrEqual(18);
  });

  it('leaves the known false positives alone (test-samples-sqli-negative.sh: -m 21)', () => {
    const inputs = samples('false_positives');
    expect(inputs.length).toBeGreaterThan(400);
    expect(inputs.filter((s) => detectSQLi(s).result !== 0).length).toBeLessThanOrEqual(21);
  });

  it('finds XSS in the XSS samples (test-samples-xss-positive.sh: -m 20)', () => {
    const inputs = samples('xss-');
    expect(inputs.length).toBeGreaterThan(500);
    expect(inputs.filter((s) => detectXSS(s) === 0).length).toBeLessThanOrEqual(20);
  });
});

describe('the libinjection wrappers', () => {
  it('read byte strings, one char per byte, of any length', () => {
    // Bytes above 0x7f pass through unchanged, and a long input grows the buffer.
    expect(detectSQLi("\xe9' OR 1=1--").result).toBe(1);
    expect(detectSQLi(`${'a'.repeat(100_000)}' OR 1=1--`).result).toBe(1);
    expect(detectSQLi('caf\xe9').result).toBe(0);
    expect(detectXSS(`${'x'.repeat(100_000)}<script>alert(1)</script>`)).toBe(1);
  });
});
