/**
 * Security checks for the page in the active tab.
 *
 * Everything here is pure: the background worker collects response headers,
 * cookie flags and DOM signals and passes plain data in. Nothing in this module
 * touches the network or a browser API, which is what keeps the checks local
 * and testable.
 *
 * A check is `{ id, title, status, detail, items? }` where status is one of
 * STATUS. `na` means the check does not apply (HSTS on plain HTTP); `unknown`
 * means the data could not be collected (no site access, restricted page).
 */

export const STATUS = Object.freeze({
  PASS: 'pass',
  WARN: 'warn',
  FAIL: 'fail',
  NA: 'na',
  UNKNOWN: 'unknown',
});

/** Host permissions requested (optionally, at first use) for headers and cookies. */
export const PAGE_ORIGINS = Object.freeze(['http://*/*', 'https://*/*']);

/** Response headers the background keeps. Everything else is dropped. */
export const SECURITY_HEADER_NAMES = Object.freeze([
  'strict-transport-security',
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
  'feature-policy',
]);

/** 180 days. Shorter HSTS lifetimes lapse between visits for many users. */
export const HSTS_MIN_MAX_AGE = 15552000;

const LOOPBACK_HOST = /^(localhost|127(?:\.\d{1,3}){3}|\[::1\])$/i;
const MAX_ITEMS = 20;

function check(id, title, status, detail, items) {
  return items && items.length ? { id, title, status, detail, items } : { id, title, status, detail };
}

/**
 * Normalise webRequest-style headers (`[{ name, value }]`) into a map of
 * lower-cased name → list of values, preserving order.
 */
export function headerMap(headers) {
  const map = new Map();
  for (const { name, value } of headers || []) {
    if (!name || value == null) continue;
    const key = name.toLowerCase();
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(String(value));
  }
  return map;
}

function first(map, name) {
  const values = map.get(name);
  return values && values.length ? values[0].trim() : null;
}

// ─── HTTPS / HSTS ───

export function checkHttps(pageUrl) {
  const url = new URL(pageUrl);
  if (url.protocol === 'https:') {
    return check('https', 'HTTPS', STATUS.PASS, 'Page is served over HTTPS.');
  }
  if (LOOPBACK_HOST.test(url.hostname)) {
    return check(
      'https',
      'HTTPS',
      STATUS.WARN,
      'Plain HTTP on a loopback address. Fine for local development, never for a public site.'
    );
  }
  return check(
    'https',
    'HTTPS',
    STATUS.FAIL,
    'Page is served over plain HTTP. Anyone on the network path can read or change it.'
  );
}

export function checkHsts(pageUrl, headers) {
  const title = 'Strict-Transport-Security';
  if (new URL(pageUrl).protocol !== 'https:') {
    return check('hsts', title, STATUS.NA, 'Only applies to HTTPS pages; browsers ignore it over HTTP.');
  }
  // Browsers honour the first HSTS header only.
  const value = first(headers, 'strict-transport-security');
  if (!value) {
    return check(
      'hsts',
      title,
      STATUS.FAIL,
      'Missing. The first visit, and any http:// link, can be downgraded to plain HTTP.'
    );
  }
  const match = /(?:^|;)\s*max-age\s*=\s*"?(\d+)"?/i.exec(value);
  if (!match) {
    return check('hsts', title, STATUS.FAIL, 'Header has no valid max-age, so browsers ignore it.');
  }
  const maxAge = Number(match[1]);
  if (maxAge === 0) {
    return check('hsts', title, STATUS.FAIL, 'max-age=0 tells browsers to forget HSTS for this host.');
  }
  const days = Math.floor(maxAge / 86400);
  if (maxAge < HSTS_MIN_MAX_AGE) {
    const lifetime = days >= 1 ? `${days} day${days === 1 ? '' : 's'}` : `${maxAge} seconds`;
    return check(
      'hsts',
      title,
      STATUS.WARN,
      `max-age is ${lifetime}. Use at least 180 days; one year is the usual value.`
    );
  }
  const extras = [
    /(?:^|;)\s*includesubdomains\s*(?:;|$)/i.test(value) && 'includeSubDomains',
    /(?:^|;)\s*preload\s*(?:;|$)/i.test(value) && 'preload',
  ].filter(Boolean);
  return check(
    'hsts',
    title,
    STATUS.PASS,
    `max-age ${days} days${extras.length ? `, ${extras.join(', ')}` : ''}.`
  );
}

// ─── CSP ───

/** Parse one serialized policy into directive name → lower-cased source list. */
export function parseCsp(policy) {
  const directives = new Map();
  for (const part of String(policy).split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    const name = tokens[0].toLowerCase();
    // Per spec, a repeated directive is ignored; the first one wins.
    if (!directives.has(name)) directives.set(name, tokens.slice(1).map((t) => t.toLowerCase()));
  }
  return directives;
}

const NONCE_OR_HASH = /^'(nonce-|sha256-|sha384-|sha512-)/;
const ANY_ORIGIN = new Set(['*', 'http:', 'https:', 'http://*', 'https://*']);

/**
 * Weaknesses in one policy's script controls. `restricted: false` means the
 * policy has neither script-src nor default-src and so says nothing about
 * scripts.
 */
export function analyzeCsp(policy) {
  const directives = parseCsp(policy);
  const directive = directives.has('script-src') ? 'script-src' : directives.has('default-src') ? 'default-src' : null;
  if (!directive) return { restricted: false, issues: [], directives };

  const sources = directives.get(directive);
  const strictDynamic = sources.includes("'strict-dynamic'");
  const issues = [];

  // CSP2+ browsers ignore 'unsafe-inline' when a nonce or hash is present.
  if (sources.includes("'unsafe-inline'") && !sources.some((s) => NONCE_OR_HASH.test(s))) {
    issues.push({
      code: 'unsafe-inline',
      severity: STATUS.FAIL,
      message: `${directive} allows 'unsafe-inline', so injected inline scripts run.`,
    });
  }
  if (sources.includes("'unsafe-eval'")) {
    issues.push({
      code: 'unsafe-eval',
      severity: STATUS.WARN,
      message: `${directive} allows 'unsafe-eval' (eval, new Function, string timers).`,
    });
  }
  // With 'strict-dynamic', CSP3 browsers ignore host and scheme sources; they
  // are only there as a fallback for old browsers.
  if (!strictDynamic) {
    const wide = sources.filter((s) => ANY_ORIGIN.has(s));
    if (wide.length) {
      issues.push({
        code: 'any-origin',
        severity: STATUS.FAIL,
        message: `${directive} allows scripts from any origin (${wide.join(' ')}).`,
      });
    }
    if (sources.includes('data:')) {
      issues.push({
        code: 'data-scripts',
        severity: STATUS.FAIL,
        message: `${directive} allows data: URLs as scripts.`,
      });
    }
  }
  return { restricted: true, issues, directives };
}

/** Split header values into individual policies (a comma joins policies). */
function policiesOf(values) {
  return (values || [])
    .flatMap((v) => v.split(','))
    .map((p) => p.trim())
    .filter(Boolean);
}

/**
 * Every enforced policy applies independently, so a weakness is real only when
 * every policy that restricts scripts has it. Policies that don't mention
 * scripts at all (e.g. only frame-ancestors) don't loosen anything.
 */
function combineCsp(policies) {
  const analyses = policies.map(analyzeCsp).filter((a) => a.restricted);
  if (!analyses.length) return null;
  const [head, ...rest] = analyses;
  return head.issues.filter((issue) => rest.every((a) => a.issues.some((i) => i.code === issue.code)));
}

export function checkCsp(headers, metaPolicies = []) {
  const title = 'Content-Security-Policy';
  let policies = policiesOf(headers.get('content-security-policy'));
  let source = 'header';
  if (!policies.length && metaPolicies.length) {
    policies = metaPolicies.map((p) => p.trim()).filter(Boolean);
    source = '<meta> tag';
  }

  if (!policies.length) {
    if (policiesOf(headers.get('content-security-policy-report-only')).length) {
      return check('csp', title, STATUS.WARN, 'Only Content-Security-Policy-Report-Only is set; nothing is enforced.');
    }
    return check('csp', title, STATUS.WARN, 'Missing. Nothing limits where scripts can load from if XSS lands.');
  }

  const issues = combineCsp(policies);
  if (issues === null) {
    return check(
      'csp',
      title,
      STATUS.WARN,
      `Policy (${source}) has no script-src or default-src, so scripts are unrestricted.`
    );
  }
  if (!issues.length) {
    return check('csp', title, STATUS.PASS, `Enforced via ${source}; script sources are restricted.`);
  }
  const status = issues.some((i) => i.severity === STATUS.FAIL) ? STATUS.FAIL : STATUS.WARN;
  return check(
    'csp',
    title,
    status,
    `Enforced via ${source}, but weak.`,
    issues.map((i) => i.message)
  );
}

// ─── Framing ───

export function checkFraming(headers) {
  const title = 'Clickjacking protection';
  // frame-ancestors is ignored in <meta> policies, so only headers count.
  const ancestors = policiesOf(headers.get('content-security-policy'))
    .map((p) => parseCsp(p).get('frame-ancestors'))
    .filter(Boolean);
  if (ancestors.length) {
    if (ancestors.some((list) => !list.some((s) => ANY_ORIGIN.has(s)))) {
      return check('framing', title, STATUS.PASS, 'CSP frame-ancestors restricts who can frame this page.');
    }
    return check('framing', title, STATUS.FAIL, 'CSP frame-ancestors lets any site frame this page.');
  }

  const xfo = first(headers, 'x-frame-options');
  if (!xfo) {
    return check(
      'framing',
      title,
      STATUS.WARN,
      'No X-Frame-Options or CSP frame-ancestors. Any site can frame this page.'
    );
  }
  const value = xfo.toUpperCase();
  if (value === 'DENY' || value === 'SAMEORIGIN') {
    return check('framing', title, STATUS.PASS, `X-Frame-Options: ${value}.`);
  }
  if (value.startsWith('ALLOW-FROM')) {
    return check(
      'framing',
      title,
      STATUS.WARN,
      'X-Frame-Options ALLOW-FROM is obsolete and ignored by current browsers. Use CSP frame-ancestors.'
    );
  }
  return check('framing', title, STATUS.WARN, `X-Frame-Options has an invalid value (${xfo}).`);
}

// ─── Simple headers ───

export function checkNosniff(headers) {
  const title = 'X-Content-Type-Options';
  const value = first(headers, 'x-content-type-options');
  if (!value) return check('nosniff', title, STATUS.WARN, 'Missing. Browsers may MIME-sniff responses.');
  if (value.toLowerCase() === 'nosniff') return check('nosniff', title, STATUS.PASS, 'nosniff.');
  return check('nosniff', title, STATUS.WARN, `Invalid value (${value}); only "nosniff" is recognised.`);
}

const REFERRER_POLICIES = new Set([
  'no-referrer',
  'no-referrer-when-downgrade',
  'origin',
  'origin-when-cross-origin',
  'same-origin',
  'strict-origin',
  'strict-origin-when-cross-origin',
  'unsafe-url',
]);

export function checkReferrerPolicy(headers, metaReferrer = null) {
  const title = 'Referrer-Policy';
  const raw = [...(headers.get('referrer-policy') || []), ...(metaReferrer ? [metaReferrer] : [])];
  // The last recognised token wins; unknown tokens are fallbacks for old browsers.
  const policy = raw
    .flatMap((v) => v.split(','))
    .map((t) => t.trim().toLowerCase())
    .filter((t) => REFERRER_POLICIES.has(t))
    .pop();
  if (!policy) {
    return check(
      'referrer',
      title,
      STATUS.WARN,
      'Not set. Current browsers default to strict-origin-when-cross-origin; older ones leak full URLs.'
    );
  }
  if (policy === 'unsafe-url') {
    return check('referrer', title, STATUS.FAIL, 'unsafe-url sends the full URL, query string included, to every site.');
  }
  if (policy === 'no-referrer-when-downgrade') {
    return check('referrer', title, STATUS.WARN, 'no-referrer-when-downgrade sends the full URL to other HTTPS sites.');
  }
  return check('referrer', title, STATUS.PASS, `${policy}.`);
}

export function checkPermissionsPolicy(headers) {
  const title = 'Permissions-Policy';
  if (first(headers, 'permissions-policy')) {
    return check('permissions', title, STATUS.PASS, 'Set.');
  }
  if (first(headers, 'feature-policy')) {
    return check('permissions', title, STATUS.WARN, 'Only the legacy Feature-Policy header is set.');
  }
  return check(
    'permissions',
    title,
    STATUS.WARN,
    'Missing. Embedded content can ask for camera, microphone, geolocation and similar features.'
  );
}

// ─── Mixed content ───

/** Kinds the browser treats as passive (display) content. */
const PASSIVE_KINDS = new Set(['img', 'image', 'audio', 'video', 'media', 'source', 'track', 'icon']);

/**
 * `resources` is `[{ url, kind }]` from the page: Resource Timing entries
 * (kind = initiatorType) and DOM references (kind = element type).
 */
export function checkMixedContent(pageUrl, resources) {
  const title = 'Mixed content';
  if (new URL(pageUrl).protocol !== 'https:') {
    return check('mixed', title, STATUS.NA, 'Only applies to HTTPS pages.');
  }
  const seen = new Map();
  for (const { url, kind } of resources || []) {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      continue;
    }
    if (parsed.protocol !== 'http:') continue;
    const key = parsed.href;
    const passive = PASSIVE_KINDS.has(String(kind).toLowerCase());
    const prior = seen.get(key);
    // If any reference to the URL is active, count it as active.
    if (!prior || (prior.passive && !passive)) seen.set(key, { url: key, kind, passive });
  }
  if (!seen.size) {
    return check('mixed', title, STATUS.PASS, 'No http:// subresources found.');
  }
  const found = [...seen.values()];
  const active = found.filter((r) => !r.passive);
  const items = [...active, ...found.filter((r) => r.passive)]
    .slice(0, MAX_ITEMS)
    .map((r) => `${r.kind}: ${r.url}`);
  if (active.length) {
    return check(
      'mixed',
      title,
      STATUS.FAIL,
      `${active.length} active http:// resource${active.length === 1 ? '' : 's'} (scripts, frames, styles or requests). Browsers block these; if not, they can rewrite the page.`,
      items
    );
  }
  return check(
    'mixed',
    title,
    STATUS.WARN,
    `${found.length} passive http:// resource${found.length === 1 ? '' : 's'} (images or media).`,
    items
  );
}

// ─── Forms ───

function safeUrl(value, base) {
  try {
    return new URL(value, base);
  } catch {
    return null;
  }
}

/**
 * `forms` is `[{ action, hasPassword }]` with `action` resolved against the
 * document; `passwordOutsideForm` covers password inputs not in any form.
 */
export function checkForms(pageUrl, { forms = [], passwordOutsideForm = false } = {}) {
  const title = 'Forms';
  const page = new URL(pageUrl);
  const pageIsHttps = page.protocol === 'https:';
  const hasPassword = passwordOutsideForm || forms.some((f) => f.hasPassword);

  if (!pageIsHttps && hasPassword) {
    return check('forms', title, STATUS.FAIL, 'Password field on a page served over plain HTTP.');
  }

  const insecure = forms
    .map((f) => ({ ...f, target: safeUrl(f.action || pageUrl, pageUrl) }))
    .filter((f) => f.target && f.target.protocol === 'http:');

  if (pageIsHttps && insecure.length) {
    const items = [...new Set(insecure.map((f) => `${f.target.origin}${f.target.pathname}`))].slice(0, MAX_ITEMS);
    const withPassword = insecure.some((f) => f.hasPassword);
    return check(
      'forms',
      title,
      STATUS.FAIL,
      `${insecure.length} form${insecure.length === 1 ? '' : 's'} submit${insecure.length === 1 ? 's' : ''} to http://${withPassword ? ', including a password' : ''}.`,
      items
    );
  }
  if (!pageIsHttps && insecure.length) {
    return check(
      'forms',
      title,
      STATUS.WARN,
      `${insecure.length} form${insecure.length === 1 ? '' : 's'} submit${insecure.length === 1 ? 's' : ''} over plain HTTP.`
    );
  }
  if (!forms.length && !hasPassword) {
    return check('forms', title, STATUS.PASS, 'No forms on this page.');
  }
  return check('forms', title, STATUS.PASS, 'Forms submit over HTTPS.');
}

// ─── Cookies ───

const SESSION_NAME = /sess|sid|auth|token|jwt|login|remember|identity|account|user|^id$/i;
const CSRF_NAME = /csrf|xsrf/i;

/** Heuristic: does the cookie name look like it carries a login session? */
export function isLikelySessionCookie(name) {
  const bare = String(name).replace(/^__(Host|Secure)-/i, '');
  return SESSION_NAME.test(bare) || CSRF_NAME.test(bare);
}

/**
 * `cookies` carries flags only: `[{ name, secure, httpOnly, sameSite }]` with
 * sameSite in chrome.cookies terms (no_restriction | lax | strict |
 * unspecified). Values never reach this function.
 */
export function checkCookies(pageUrl, cookies) {
  const title = 'Cookies';
  const list = cookies || [];
  if (!list.length) return check('cookies', title, STATUS.PASS, 'No cookies for this site.');

  const pageIsHttps = new URL(pageUrl).protocol === 'https:';
  const sessionLike = list.filter((c) => isLikelySessionCookie(c.name));
  let failed = false;
  const items = [];

  for (const c of sessionLike) {
    const problems = [];
    if (!c.secure) {
      problems.push('no Secure');
      if (pageIsHttps) failed = true;
    }
    // CSRF tokens are meant to be read by page scripts.
    if (!c.httpOnly && !CSRF_NAME.test(c.name)) problems.push('no HttpOnly');
    if (c.sameSite === 'no_restriction') problems.push('SameSite=None');
    else if (!c.sameSite || c.sameSite === 'unspecified') problems.push('no SameSite');
    if (problems.length) items.push(`${c.name}: ${problems.join(', ')}`);
  }

  const summary = `${list.length} cookie${list.length === 1 ? '' : 's'}, ${sessionLike.length} look${sessionLike.length === 1 ? 's' : ''} like session cookies`;
  if (!items.length) return check('cookies', title, STATUS.PASS, `${summary}; all flagged Secure, HttpOnly and SameSite.`);
  return check(
    'cookies',
    title,
    failed ? STATUS.FAIL : STATUS.WARN,
    `${summary}; ${items.length} missing protections.`,
    items.slice(0, MAX_ITEMS)
  );
}

// ─── Report ───

const HEADER_CHECKS = [
  ['hsts', 'Strict-Transport-Security'],
  ['csp', 'Content-Security-Policy'],
  ['framing', 'Clickjacking protection'],
  ['nosniff', 'X-Content-Type-Options'],
  ['referrer', 'Referrer-Policy'],
  ['permissions', 'Permissions-Policy'],
];

export function summarize(checks) {
  const summary = { pass: 0, warn: 0, fail: 0 };
  for (const c of checks) if (c.status in summary) summary[c.status] += 1;
  summary.status = summary.fail ? STATUS.FAIL : summary.warn ? STATUS.WARN : STATUS.PASS;
  return summary;
}

/** Badge text/colour for a summary: failures first, then warnings. */
export function badgeFor(summary) {
  if (summary.fail) return { text: String(summary.fail), color: '#ef4444' };
  if (summary.warn) return { text: String(summary.warn), color: '#f59e0b' };
  return { text: '✓', color: '#00c853' };
}

export function isCheckableUrl(url) {
  try {
    const { protocol } = new URL(url);
    return protocol === 'http:' || protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * What "Scan with ThreatCrush" sends: origin and path only. Query strings and
 * fragments often carry tokens, and the header scan doesn't need them.
 */
export function scanTargetUrl(url) {
  const u = new URL(url);
  return `${u.origin}${u.pathname}`;
}

/**
 * Build the full report. Pass `null` for any input that couldn't be collected
 * and say why in `unavailable` ({ headers, cookies, page } → reason).
 *
 * @param {object} input
 * @param {string} input.url
 * @param {Array<{name: string, value: string}>|null} input.headers
 * @param {Array<object>|null} input.cookies
 * @param {object|null} input.page  Output of collectPageSignals()
 * @param {Record<string,string>} [input.unavailable]
 */
export function runPageChecks({ url, headers, cookies, page, unavailable = {} }) {
  if (!isCheckableUrl(url)) {
    return { url, supported: false, checks: [], summary: summarize([]) };
  }
  const unknown = (id, title, reason) => check(id, title, STATUS.UNKNOWN, reason);
  const checks = [checkHttps(url)];

  if (headers) {
    const map = headerMap(headers);
    checks.push(
      checkHsts(url, map),
      checkCsp(map, page?.metaCsp || []),
      checkFraming(map),
      checkNosniff(map),
      checkReferrerPolicy(map, page?.metaReferrer || null),
      checkPermissionsPolicy(map)
    );
  } else {
    const reason = unavailable.headers || 'Response headers were not captured.';
    for (const [id, title] of HEADER_CHECKS) checks.push(unknown(id, title, reason));
  }

  if (page) {
    checks.push(checkMixedContent(url, page.resources), checkForms(url, page));
  } else {
    const reason = unavailable.page || 'The page could not be inspected.';
    checks.push(unknown('mixed', 'Mixed content', reason), unknown('forms', 'Forms', reason));
  }

  checks.push(
    cookies ? checkCookies(url, cookies) : unknown('cookies', 'Cookies', unavailable.cookies || 'Cookies could not be read.')
  );

  return { url, supported: true, checks, summary: summarize(checks) };
}
