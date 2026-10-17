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

  describe('PostgREST select (942100 exclusion)', () => {
    // smshub's own poll, as dev2 logged it every two seconds on 2026-10-09.
    const poll =
      '/rest/v1/messages?select=id%2Cconversation_id%2Cbody%2Ccreated_at%2Cconversations%21inner%28user_id%29' +
      '&conversations.user_id=eq.06226df4-ccb5-49d6-b182-11b5a5d59c7a&created_at=gt.2026-10-09T23%3A44%3A05.408Z&order=created_at.asc&limit=200';
    const embed = 'select=id%2Cconversations%21inner%28user_id%29';

    it('does not score an embedded resource in a Supabase select', () => {
      expect(engine.assess({ uri: poll }).score).toBe(0);
      expect(ids(engine, '/rest/v1/participants?select=user_id%2Cusers%21participants_user_id_fkey%28id%2Cname%29')).toEqual([]);
      expect(ids(engine, '/rest/v1/t?select=%2A%2Cb%3Aalias')).toEqual([]);
    });

    it('still scores the same value anywhere but /rest/v1/ select', () => {
      expect(ids(engine, `/api/messages?${embed}`)).toContain(942100);
      expect(ids(engine, `/rest/v1/messages?q=conversations%21inner%28user_id%29`)).toContain(942100);
    });

    it('still scores a select that is not PostgREST grammar', () => {
      expect(ids(engine, '/rest/v1/messages?select=id%2C%28select%20password%20from%20users%29')).toContain(942100);
      expect(ids(engine, "/rest/v1/messages?select=id%27%20or%201%3D1--")).toContain(942100);
    });

    it('still scores an injection in another argument of the same request', () => {
      const a = engine.assess({ uri: `/rest/v1/messages?${embed}&id=eq.1%27%20UNION%20SELECT%20password%20FROM%20users--` });
      expect(a.matches.map((m) => m.id)).toContain(942100);
      expect(a.score).toBeGreaterThanOrEqual(a.threshold);
    });
  });
});

describe('the generated rule table', () => {
  it('is what the generator produces from the vendored CRS', () => {
    const script = join(__dirname, '..', '..', '..', '..', 'scripts', 'build-crs-rules.mjs');
    expect(() => execFileSync(process.execPath, [script, '--check'], { stdio: 'pipe' })).not.toThrow();
  });
});
