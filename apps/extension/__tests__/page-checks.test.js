import { describe, expect, it } from 'vitest';

import {
  analyzeCsp,
  badgeFor,
  checkCookies,
  checkCsp,
  checkForms,
  checkFraming,
  checkHsts,
  checkHttps,
  checkMixedContent,
  checkNosniff,
  checkPermissionsPolicy,
  checkReferrerPolicy,
  headerMap,
  isLikelySessionCookie,
  runPageChecks,
  scanTargetUrl,
} from '../src/lib/page-checks.js';

const HTTPS = 'https://shop.example/account';
const HTTP = 'http://shop.example/account';

const h = (pairs) => headerMap(Object.entries(pairs).map(([name, value]) => ({ name, value })));

const STRONG_HEADERS = [
  { name: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },
  { name: 'Content-Security-Policy', value: "default-src 'self'; frame-ancestors 'none'" },
  { name: 'X-Content-Type-Options', value: 'nosniff' },
  { name: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { name: 'Permissions-Policy', value: 'camera=(), microphone=()' },
];

describe('headerMap', () => {
  it('matches header names case-insensitively and keeps repeated headers in order', () => {
    const map = headerMap([
      { name: 'Content-Security-Policy', value: "script-src 'self'" },
      { name: 'content-security-policy', value: "frame-ancestors 'none'" },
    ]);
    expect(map.get('content-security-policy')).toEqual(["script-src 'self'", "frame-ancestors 'none'"]);
  });
});

describe('checkHttps', () => {
  it('passes https, fails public http, and only warns for loopback http', () => {
    expect(checkHttps(HTTPS).status).toBe('pass');
    expect(checkHttps(HTTP).status).toBe('fail');
    expect(checkHttps('http://localhost:8080/').status).toBe('warn');
    expect(checkHttps('http://127.0.0.1/').status).toBe('warn');
    expect(checkHttps('http://[::1]:3000/').status).toBe('warn');
  });
});

describe('checkHsts', () => {
  it('does not apply to plain HTTP pages even if the header is sent', () => {
    expect(checkHsts(HTTP, h({ 'Strict-Transport-Security': 'max-age=31536000' })).status).toBe('na');
  });

  it('fails when missing, max-age=0 or unparseable', () => {
    expect(checkHsts(HTTPS, h({})).status).toBe('fail');
    expect(checkHsts(HTTPS, h({ 'Strict-Transport-Security': 'max-age=0' })).status).toBe('fail');
    expect(checkHsts(HTTPS, h({ 'Strict-Transport-Security': 'includeSubDomains' })).status).toBe('fail');
  });

  it('warns below 180 days and passes at 180 days', () => {
    expect(checkHsts(HTTPS, h({ 'Strict-Transport-Security': 'max-age=86400' })).status).toBe('warn');
    expect(checkHsts(HTTPS, h({ 'Strict-Transport-Security': 'max-age=15552000' })).status).toBe('pass');
    expect(checkHsts(HTTPS, h({ 'Strict-Transport-Security': 'MAX-AGE="31536000"; preload' })).status).toBe('pass');
  });
});

describe('analyzeCsp', () => {
  const codes = (policy) => analyzeCsp(policy).issues.map((i) => i.code);

  it('flags unsafe-inline, unsafe-eval and wildcard script sources', () => {
    expect(codes("script-src 'self' 'unsafe-inline'")).toEqual(['unsafe-inline']);
    expect(codes("script-src 'self' 'unsafe-eval'")).toEqual(['unsafe-eval']);
    expect(codes('script-src *')).toEqual(['any-origin']);
    expect(codes("default-src 'self' https:")).toEqual(['any-origin']);
    expect(codes("script-src 'self' data:")).toEqual(['data-scripts']);
  });

  it('falls back to default-src when script-src is absent', () => {
    expect(codes("default-src 'unsafe-inline'")).toEqual(['unsafe-inline']);
    expect(codes("default-src *; script-src 'self'")).toEqual([]);
  });

  it("ignores 'unsafe-inline' next to a nonce or hash, as CSP2+ browsers do", () => {
    expect(codes("script-src 'nonce-abc123' 'unsafe-inline'")).toEqual([]);
    expect(codes("script-src 'sha256-AbCd=' 'unsafe-inline'")).toEqual([]);
  });

  it("ignores host and scheme fallbacks under 'strict-dynamic'", () => {
    expect(codes("script-src 'nonce-r4nd' 'strict-dynamic' https: 'unsafe-inline'")).toEqual([]);
  });

  it('uses the first occurrence of a repeated directive', () => {
    expect(codes("script-src 'self'; script-src *")).toEqual([]);
  });

  it('reports a policy without script-src or default-src as unrestricted', () => {
    expect(analyzeCsp("frame-ancestors 'none'").restricted).toBe(false);
  });
});

describe('checkCsp', () => {
  it('warns when there is no policy or only a report-only policy', () => {
    expect(checkCsp(h({})).status).toBe('warn');
    const reportOnly = checkCsp(h({ 'Content-Security-Policy-Report-Only': "default-src 'self'" }));
    expect(reportOnly.status).toBe('warn');
    expect(reportOnly.detail).toMatch(/report-only/i);
  });

  it('passes a restrictive policy and fails a policy allowing inline script', () => {
    expect(checkCsp(h({ 'Content-Security-Policy': "default-src 'self'" })).status).toBe('pass');
    const weak = checkCsp(h({ 'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'" }));
    expect(weak.status).toBe('fail');
    expect(weak.items).toHaveLength(1);
  });

  it('only warns when the sole weakness is unsafe-eval', () => {
    expect(checkCsp(h({ 'Content-Security-Policy': "script-src 'self' 'unsafe-eval'" })).status).toBe('warn');
  });

  it('treats a weakness as real only when every enforced policy has it', () => {
    const tightened = headerMap([
      { name: 'Content-Security-Policy', value: "script-src 'self' 'unsafe-inline'" },
      { name: 'Content-Security-Policy', value: "script-src 'self'" },
    ]);
    expect(checkCsp(tightened).status).toBe('pass');

    // Comma-joined policies in one header are separate policies too.
    const joined = h({ 'Content-Security-Policy': "script-src *, frame-ancestors 'none'" });
    expect(checkCsp(joined).status).toBe('fail');
  });

  it('warns when the enforced policy does not restrict scripts at all', () => {
    expect(checkCsp(h({ 'Content-Security-Policy': "frame-ancestors 'none'" })).status).toBe('warn');
  });

  it('analyzes a <meta> policy when no header policy exists', () => {
    expect(checkCsp(h({}), ["script-src 'self'"]).status).toBe('pass');
    expect(checkCsp(h({}), ["script-src 'unsafe-inline'"]).status).toBe('fail');
  });
});

describe('checkFraming', () => {
  it('passes with X-Frame-Options DENY/SAMEORIGIN in any case', () => {
    expect(checkFraming(h({ 'X-Frame-Options': 'deny' })).status).toBe('pass');
    expect(checkFraming(h({ 'X-Frame-Options': 'SAMEORIGIN' })).status).toBe('pass');
  });

  it('passes with a restrictive CSP frame-ancestors even without X-Frame-Options', () => {
    expect(checkFraming(h({ 'Content-Security-Policy': "frame-ancestors 'self'" })).status).toBe('pass');
  });

  it('fails when frame-ancestors allows any origin, even if X-Frame-Options is set', () => {
    // frame-ancestors takes precedence over X-Frame-Options in browsers.
    const headers = h({ 'Content-Security-Policy': 'frame-ancestors *', 'X-Frame-Options': 'DENY' });
    expect(checkFraming(headers).status).toBe('fail');
  });

  it('warns when missing, obsolete ALLOW-FROM, or invalid', () => {
    expect(checkFraming(h({})).status).toBe('warn');
    expect(checkFraming(h({ 'X-Frame-Options': 'ALLOW-FROM https://a.example' })).status).toBe('warn');
    expect(checkFraming(h({ 'X-Frame-Options': 'yes' })).status).toBe('warn');
  });
});

describe('simple header checks', () => {
  it('X-Content-Type-Options requires nosniff', () => {
    expect(checkNosniff(h({ 'X-Content-Type-Options': 'NoSniff' })).status).toBe('pass');
    expect(checkNosniff(h({ 'X-Content-Type-Options': 'sniff' })).status).toBe('warn');
    expect(checkNosniff(h({})).status).toBe('warn');
  });

  it('Referrer-Policy uses the last recognised token and fails unsafe-url', () => {
    expect(checkReferrerPolicy(h({ 'Referrer-Policy': 'no-referrer' })).status).toBe('pass');
    expect(checkReferrerPolicy(h({ 'Referrer-Policy': 'unsafe-url' })).status).toBe('fail');
    expect(checkReferrerPolicy(h({ 'Referrer-Policy': 'no-referrer-when-downgrade' })).status).toBe('warn');
    expect(checkReferrerPolicy(h({ 'Referrer-Policy': 'unsafe-url, made-up-policy' })).status).toBe('fail');
    expect(checkReferrerPolicy(h({ 'Referrer-Policy': 'unsafe-url, strict-origin' })).status).toBe('pass');
    expect(checkReferrerPolicy(h({})).status).toBe('warn');
    expect(checkReferrerPolicy(h({}), 'same-origin').status).toBe('pass');
  });

  it('Permissions-Policy passes when set and warns on legacy Feature-Policy or absence', () => {
    expect(checkPermissionsPolicy(h({ 'Permissions-Policy': 'geolocation=()' })).status).toBe('pass');
    expect(checkPermissionsPolicy(h({ 'Feature-Policy': "geolocation 'none'" })).status).toBe('warn');
    expect(checkPermissionsPolicy(h({})).status).toBe('warn');
  });
});

describe('checkMixedContent', () => {
  it('does not apply to http pages', () => {
    expect(checkMixedContent(HTTP, [{ url: 'http://cdn.example/a.js', kind: 'script' }]).status).toBe('na');
  });

  it('passes when every subresource is https', () => {
    const resources = [
      { url: 'https://cdn.example/a.js', kind: 'script' },
      { url: 'https://cdn.example/b.png', kind: 'img' },
    ];
    expect(checkMixedContent(HTTPS, resources).status).toBe('pass');
  });

  it('warns for passive http content and fails for active http content', () => {
    const passive = checkMixedContent(HTTPS, [{ url: 'http://cdn.example/b.png', kind: 'img' }]);
    expect(passive.status).toBe('warn');
    expect(passive.items).toEqual(['img: http://cdn.example/b.png']);

    for (const kind of ['script', 'stylesheet', 'iframe', 'fetch', 'xmlhttprequest', 'object']) {
      expect(checkMixedContent(HTTPS, [{ url: 'http://cdn.example/x', kind }]).status).toBe('fail');
    }
  });

  it('counts a URL once and as active if any reference to it is active', () => {
    const result = checkMixedContent(HTTPS, [
      { url: 'http://cdn.example/x.svg', kind: 'img' },
      { url: 'http://cdn.example/x.svg', kind: 'iframe' },
    ]);
    expect(result.status).toBe('fail');
    expect(result.items).toEqual(['iframe: http://cdn.example/x.svg']);
  });

  it('ignores unparseable URLs', () => {
    expect(checkMixedContent(HTTPS, [{ url: 'not a url', kind: 'script' }]).status).toBe('pass');
  });
});

describe('checkForms', () => {
  it('fails a password field on an http page, inside or outside a form', () => {
    expect(checkForms(HTTP, { forms: [{ action: `${HTTP}/login`, hasPassword: true }] }).status).toBe('fail');
    expect(checkForms(HTTP, { forms: [], passwordOutsideForm: true }).status).toBe('fail');
  });

  it('fails an https page with a form posting to http', () => {
    const result = checkForms(HTTPS, {
      forms: [{ action: 'http://collector.example/submit?x=1', hasPassword: false }],
    });
    expect(result.status).toBe('fail');
    expect(result.items).toEqual(['http://collector.example/submit']);
  });

  it('passes https forms, including relative and empty actions', () => {
    const forms = [
      { action: 'https://shop.example/login', hasPassword: true },
      { action: '/search', hasPassword: false },
      { action: '', hasPassword: false },
    ];
    expect(checkForms(HTTPS, { forms }).status).toBe('pass');
    expect(checkForms(HTTPS, { forms: [] }).status).toBe('pass');
  });

  it('warns about non-password forms on an http page', () => {
    expect(checkForms(HTTP, { forms: [{ action: '/search', hasPassword: false }] }).status).toBe('warn');
  });
});

describe('checkCookies', () => {
  const cookie = (name, flags = {}) => ({ name, secure: true, httpOnly: true, sameSite: 'lax', ...flags });

  it('recognises likely session cookie names, including __Host- prefixed ones', () => {
    for (const name of ['PHPSESSID', 'connect.sid', 'session', '__Host-auth', 'remember_me', 'access_token', 'csrftoken']) {
      expect(isLikelySessionCookie(name), name).toBe(true);
    }
    for (const name of ['_ga', '_gid', 'theme', 'lang', 'OptanonConsent']) {
      expect(isLikelySessionCookie(name), name).toBe(false);
    }
  });

  it('passes when there are no cookies or session cookies are fully flagged', () => {
    expect(checkCookies(HTTPS, []).status).toBe('pass');
    expect(checkCookies(HTTPS, [cookie('sessionid', { sameSite: 'strict' })]).status).toBe('pass');
  });

  it('fails a session cookie without Secure on an https site', () => {
    const result = checkCookies(HTTPS, [cookie('sessionid', { secure: false })]);
    expect(result.status).toBe('fail');
    expect(result.items).toEqual(['sessionid: no Secure']);
  });

  it('warns for missing HttpOnly or SameSite, and lists names only', () => {
    const result = checkCookies(HTTPS, [
      cookie('auth', { httpOnly: false }),
      cookie('sid', { sameSite: 'unspecified' }),
      cookie('token', { sameSite: 'no_restriction' }),
      cookie('_ga', { secure: false, httpOnly: false, sameSite: 'unspecified' }),
    ]);
    expect(result.status).toBe('warn');
    expect(result.items).toEqual(['auth: no HttpOnly', 'sid: no SameSite', 'token: SameSite=None']);
  });

  it('does not require HttpOnly on CSRF cookies, which page scripts must read', () => {
    expect(checkCookies(HTTPS, [cookie('XSRF-TOKEN', { httpOnly: false })]).status).toBe('pass');
  });

  it('does not fail a missing Secure flag on an http site (the HTTPS check covers that)', () => {
    expect(checkCookies(HTTP, [cookie('sessionid', { secure: false })]).status).toBe('warn');
  });
});

describe('runPageChecks', () => {
  const cleanPage = { resources: [], forms: [], passwordOutsideForm: false, metaCsp: [], metaReferrer: null };

  it('passes every check for a well-configured https page', () => {
    const report = runPageChecks({ url: HTTPS, headers: STRONG_HEADERS, cookies: [], page: cleanPage });
    expect(report.supported).toBe(true);
    expect(report.checks.map((c) => [c.id, c.status])).toEqual([
      ['https', 'pass'],
      ['hsts', 'pass'],
      ['csp', 'pass'],
      ['framing', 'pass'],
      ['nosniff', 'pass'],
      ['referrer', 'pass'],
      ['permissions', 'pass'],
      ['mixed', 'pass'],
      ['forms', 'pass'],
      ['cookies', 'pass'],
    ]);
    expect(report.summary).toEqual({ pass: 10, warn: 0, fail: 0, status: 'pass' });
  });

  it('marks checks unknown when their data could not be collected, and does not count them', () => {
    const report = runPageChecks({
      url: HTTPS,
      headers: null,
      cookies: null,
      page: null,
      unavailable: { headers: 'Needs site access.' },
    });
    const unknown = report.checks.filter((c) => c.status === 'unknown');
    expect(unknown).toHaveLength(9);
    expect(report.checks.find((c) => c.id === 'csp').detail).toBe('Needs site access.');
    expect(report.summary).toEqual({ pass: 1, warn: 0, fail: 0, status: 'pass' });
  });

  it('uses <meta> CSP and referrer values collected from the page', () => {
    const report = runPageChecks({
      url: HTTPS,
      headers: [],
      cookies: [],
      page: { ...cleanPage, metaCsp: ["script-src 'self'"], metaReferrer: 'no-referrer' },
    });
    expect(report.checks.find((c) => c.id === 'csp').status).toBe('pass');
    expect(report.checks.find((c) => c.id === 'referrer').status).toBe('pass');
  });

  it('refuses non-web URLs', () => {
    expect(runPageChecks({ url: 'chrome://settings', headers: [], cookies: [], page: cleanPage }).supported).toBe(false);
    expect(runPageChecks({ url: 'file:///etc/hosts', headers: [], cookies: [], page: cleanPage }).supported).toBe(false);
  });
});

describe('badgeFor', () => {
  it('shows failures first, then warnings, then a check mark', () => {
    expect(badgeFor({ fail: 2, warn: 5, pass: 1 }).text).toBe('2');
    expect(badgeFor({ fail: 0, warn: 3, pass: 1 }).text).toBe('3');
    expect(badgeFor({ fail: 0, warn: 0, pass: 9 }).text).toBe('✓');
  });
});

describe('scanTargetUrl', () => {
  it('drops the query string and fragment before anything is sent to the server', () => {
    expect(scanTargetUrl('https://shop.example/reset?token=s3cret#step2')).toBe('https://shop.example/reset');
  });
});
