import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { CrsEngine } from '../engine.js';
import * as T from '../transforms.js';

const ids = (engine: CrsEngine, uri: string) => engine.assess({ uri }).matches.map((m) => m.id);

describe('ModSecurity transformations', () => {
  // Byte strings in, byte strings out, as ModSecurity v2 computes them.
  it('decodes the way ModSecurity does', () => {
    expect(T.urlDecodeUni('%u0041%uff21+%zz')).toBe('AA %zz'); // %u low byte, full-width ASCII, + is space, bad escape kept
    expect(T.htmlEntityDecode('&lt;&#x41;&#66&quot;&foo;')).toBe('<AB"&foo;');
    expect(T.jsDecode('\\x41\\u0042\\103\\n')).toBe('ABC\n');
    expect(T.cssDecode('\\41 \\000042x')).toBe('ABx');
    expect(T.utf8toUnicode('\xc3\xa9')).toBe('%u00e9');
    expect(T.base64Decode('YWJj!ignored')).toBe('abc');
  });

  it('normalises the way ModSecurity does', () => {
    expect(T.cmdLine('C:\\"Win"^dows, /c')).toBe('c:windows/c');
    expect(T.normalizePath('/a/b/../c/./d//e')).toBe('/a/c/d/e');
    expect(T.normalizePathWin('\\a\\..\\b')).toBe('/b');
    expect(T.replaceComments('a/*x*/b/*y')).toBe('a b ');
    expect(T.removeCommentsChar('a--b#c/*d')).toBe('abcd');
    expect(T.compressWhitespace('a \t\xa0b')).toBe('a b');
    expect(T.removeWhitespace('a \t\xa0b')).toBe('ab');
    expect(T.lowercase('AbC\xc0')).toBe('abc\xc0'); // C locale: ASCII only
  });
});

describe('CRS engine', () => {
  const engine = new CrsEngine();

  it('evaluates each query argument on its own, URL-decoded', () => {
    // 931100 is anchored at the start of an argument value.
    expect(ids(engine, '/?u=http%3A%2F%2F192.0.2.1%2F')).toContain(931100);
    expect(ids(engine, '/?x=1&u=http://192.0.2.1/')).toContain(931100);
    expect(ids(engine, '/?u=xhttp://192.0.2.1/')).not.toContain(931100);
  });

  it('matches whitespace as PCRE does, not as JavaScript does', () => {
    // JavaScript's \s includes U+00A0; PCRE's does not.
    expect(ids(engine, '/?q=sleep%20(1)')).toContain(942160);
    expect(ids(engine, '/?q=sleep%A0(1)')).not.toContain(942160);
  });

  it('requires every link of a chained rule', () => {
    // 933150: a listed PHP function name, and then a parenthesis.
    expect(ids(engine, '/?x=array_filter')).not.toContain(933150);
    expect(ids(engine, '/?x=array_filter(1)')).toContain(933150);
  });

  it('adds each matching rule once, at its severity', () => {
    const a = engine.assess({ uri: '/download?file=../../../../etc/passwd' });
    expect(a.score).toBe(a.matches.length * 5);
  });
});

describe('the generated rule table', () => {
  it('is what the generator produces from the vendored CRS', () => {
    const script = join(__dirname, '..', '..', '..', '..', 'scripts', 'build-crs-rules.mjs');
    expect(() => execFileSync(process.execPath, [script, '--check'], { stdio: 'pipe' })).not.toThrow();
  });
});
