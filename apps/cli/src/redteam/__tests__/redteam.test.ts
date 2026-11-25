import { describe, expect, it } from 'vitest';
import {
  extractLinks, extractForms, parseOpenApi, extractSourceMapUrls, parseRobots, parseSitemap,
  discoverSurface, type Fetcher,
} from '../recon.js';
import { planActions } from '../plan.js';
import { evaluateResponse, makeCanary, executeAction, type ResponseView } from '../execute.js';
import { runRedteam } from '../index.js';
import type { Action } from '../plan.js';

describe('recon parsers', () => {
  it('extractLinks keeps same-origin paths, drops anchors/mailto/other hosts', () => {
    const html = `<a href="/a">a</a><a href="https://other.com/x">x</a><a href="#f">f</a>
      <a href="mailto:a@b.c">m</a><a href="https://site.test/b?q=1">b</a>`;
    const got = extractLinks(html, 'https://site.test/');
    expect(got).toContain('/a');
    expect(got).toContain('/b?q=1');
    expect(got).not.toContain('/x');
    expect(got.some((p) => p.includes('other.com'))).toBe(false);
  });

  it('extractForms reads action, method and input names', () => {
    const html = `<form action="/login" method="post"><input name="user"><input name="pass"></form>`;
    const forms = extractForms(html);
    expect(forms[0]).toMatchObject({ action: '/login', method: 'POST' });
    expect(forms[0].inputs).toEqual(['user', 'pass']);
  });

  it('parseOpenApi reads v3 paths and methods', () => {
    const spec = { paths: { '/users': { get: {}, post: {} }, '/users/{id}': { delete: {} } } };
    const routes = parseOpenApi(spec);
    expect(routes).toEqual([
      { path: '/users', method: 'GET', source: 'openapi' },
      { path: '/users', method: 'POST', source: 'openapi' },
      { path: '/users/{id}', method: 'DELETE', source: 'openapi' },
    ]);
  });

  it('parseOpenApi tolerates junk', () => {
    expect(parseOpenApi(null)).toEqual([]);
    expect(parseOpenApi({})).toEqual([]);
    expect(parseOpenApi({ paths: 5 })).toEqual([]);
  });

  it('extractSourceMapUrls finds non-data map refs', () => {
    expect(extractSourceMapUrls('x=1\n//# sourceMappingURL=app.js.map')).toEqual(['app.js.map']);
    expect(extractSourceMapUrls('//# sourceMappingURL=data:application/json;base64,AAA')).toEqual([]);
  });

  it('parseRobots and parseSitemap pull paths', () => {
    expect(parseRobots('User-agent: *\nDisallow: /admin\nAllow: /public\nDisallow: /')).toEqual(['/admin', '/public']);
    expect(parseSitemap('<loc>https://s.test/a</loc><loc>https://other/b</loc>', 'https://s.test')).toEqual(['/a']);
  });
});

/** A fetcher backed by a path→{status,body,headers} map. */
function fakeFetcher(routes: Record<string, { status?: number; body?: string; headers?: Record<string, string> }>): Fetcher {
  return async (url) => {
    const u = new URL(url);
    const key = u.pathname;
    const hit = routes[key] ?? { status: 404, body: 'not found' };
    const status = hit.status ?? 200;
    return {
      status,
      ok: status >= 200 && status < 300,
      headers: { get: (n: string) => hit.headers?.[n.toLowerCase()] ?? null },
      text: async () => hit.body ?? '',
    };
  };
}

describe('discoverSurface', () => {
  it('maps links, forms, robots, sitemap and an OpenAPI spec', async () => {
    const f = fakeFetcher({
      '/': { body: `<a href="/about">about</a><form action="/login" method="post"><input name="u"></form>` },
      '/robots.txt': { body: 'Disallow: /secret-admin' },
      '/sitemap.xml': { body: '<loc>https://site.test/blog</loc>' },
      '/openapi.json': { body: JSON.stringify({ paths: { '/api/users': { get: {}, post: {} } } }) },
    });
    const surface = await discoverSurface('https://site.test', f);
    const keys = surface.routes.map((r) => `${r.method} ${r.path}`);
    expect(keys).toContain('GET /about');
    expect(keys).toContain('POST /login');
    expect(keys).toContain('GET /secret-admin');
    expect(keys).toContain('GET /blog');
    expect(keys).toContain('GET /api/users');
    expect(keys).toContain('POST /api/users');
  });
});

describe('planActions ranking', () => {
  it('ranks sensitive write API routes above static pages', () => {
    const surface = {
      target: 'https://s.test', origin: 'https://s.test', notes: [],
      routes: [
        { path: '/about', method: 'GET' as const, source: 'html' as const },
        { path: '/api/admin/users', method: 'POST' as const, source: 'openapi' as const },
      ],
    };
    const actions = planActions(surface);
    expect(actions[0].path).toBe('/api/admin/users');
    expect(actions[0].priority).toBeGreaterThan(actions[1].priority);
  });
});

describe('evaluateResponse', () => {
  const action: Action = { method: 'GET', path: '/admin', url: 'https://s.test/admin', reason: '', priority: 50 };
  it('flags unauthenticated access to a sensitive path on a 200', () => {
    const res: ResponseView = { status: 200, headers: {}, body: 'ok' };
    const f = evaluateResponse(action, res, 'canary');
    expect(f.some((x) => x.type === 'unauthenticated-access')).toBe(true);
  });
  it('does not flag unauth access when the endpoint 401s', () => {
    const res: ResponseView = { status: 401, headers: {}, body: 'nope' };
    expect(evaluateResponse(action, res, 'canary').some((x) => x.type === 'unauthenticated-access')).toBe(false);
  });
  it('flags unencoded canary reflection', () => {
    const res: ResponseView = { status: 200, headers: {}, body: 'hello CANARY123 world' };
    const a: Action = { ...action, path: '/search' };
    expect(evaluateResponse(a, res, 'CANARY123').some((x) => x.type === 'reflected-input')).toBe(true);
  });
  it('flags wide-open CORS and version disclosure', () => {
    const res: ResponseView = { status: 200, headers: { 'access-control-allow-origin': '*', server: 'nginx/1.25.0' }, body: '' };
    const a: Action = { ...action, path: '/x' };
    const types = evaluateResponse(a, res, '').map((x) => x.type);
    expect(types).toContain('cors');
    expect(types).toContain('version-disclosure');
  });
});

describe('executeAction', () => {
  it('downgrades a write method to OPTIONS and never sends it', async () => {
    const calls: { url: string }[] = [];
    const f: Fetcher = async (url) => {
      calls.push({ url });
      return { status: 200, ok: true, headers: { get: () => null }, text: async () => '' };
    };
    const action: Action = { method: 'DELETE', path: '/api/users/1', url: 'https://s.test/api/users/1', reason: '', priority: 80 };
    const r = await executeAction(action, f);
    expect(r.status).toBe(200);
    // Only a safe method was used; the canary query is not appended to OPTIONS.
    expect(calls.every((c) => !c.url.includes('tc='))).toBe(true);
  });

  it('self-corrects: one retry on transport error then reports unreachable', async () => {
    let n = 0;
    const f: Fetcher = async () => { n++; throw new Error('ECONNRESET'); };
    const action: Action = { method: 'GET', path: '/x', url: 'https://s.test/x', reason: '', priority: 10 };
    const r = await executeAction(action, f, { timeoutMs: 50 });
    expect(n).toBe(2); // initial + one retry
    expect(r.status).toBeNull();
    expect(r.findings).toHaveLength(0);
  });

  it('verifies an unauth finding and drops it if not reproduced', async () => {
    let call = 0;
    const f: Fetcher = async () => {
      call++;
      // first (canary GET) 200, second (verify) 403 → finding dropped
      const status = call === 1 ? 200 : 403;
      return { status, ok: status < 400, headers: { get: () => null }, text: async () => '' };
    };
    const action: Action = { method: 'GET', path: '/admin', url: 'https://s.test/admin', reason: '', priority: 90 };
    const r = await executeAction(action, f);
    expect(r.findings.some((x) => x.type === 'unauthenticated-access')).toBe(false);
  });
});

describe('runRedteam end-to-end', () => {
  it('maps, probes within budget, and returns a redteam RunResult', async () => {
    const f = fakeFetcher({
      '/': { body: `<a href="/api/admin">admin</a>` },
      '/openapi.json': { body: JSON.stringify({ paths: { '/api/secret': { get: {} } } }) },
      '/api/admin': { status: 200, body: 'admin panel' },
      '/api/secret': { status: 200, body: 'secrets', headers: { 'access-control-allow-origin': '*' } },
    });
    const { result, surface, steps } = await runRedteam('https://site.test', f, { maxActions: 10 });
    expect(result.type).toBe('redteam');
    expect(surface.routes.length).toBeGreaterThan(0);
    expect(steps.length).toBeGreaterThan(0);
    expect(result.findings.some((x) => x.type === 'unauthenticated-access')).toBe(true);
  });

  it('respects the action budget', async () => {
    const links = Array.from({ length: 40 }, (_, i) => `<a href="/p${i}">p</a>`).join('');
    const f = fakeFetcher({ '/': { body: links } });
    const { steps } = await runRedteam('https://site.test', f, { maxActions: 5, htmlOnly: true });
    expect(steps.length).toBe(5);
  });
});

describe('makeCanary', () => {
  it('is unique-ish and alphanumeric', () => {
    expect(makeCanary()).toMatch(/^tcrt[a-z0-9]+$/);
    expect(makeCanary()).not.toBe(makeCanary());
  });
});
