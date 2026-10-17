import { describe, expect, it } from 'vitest';

import { checkEntitlement, crawlSite, diffBroken, extractLinks, isBrokenStatus, toThreatEvent } from '../index.js';

type Route = { status: number; type?: string; body?: string } | Error;

/** A fake web: url -> answer; anything unlisted is a 404. */
function web(routes: Record<string, Route>) {
  const asked: string[] = [];
  const fetchImpl = async (url: string, init?: RequestInit) => {
    asked.push(`${init?.method ?? 'GET'} ${url}`);
    const r = routes[url];
    if (r instanceof Error) throw r;
    const hit = r ?? { status: 404 };
    return new Response(init?.method === 'HEAD' ? null : (hit.body ?? ''), {
      status: hit.status,
      headers: { 'content-type': hit.type ?? 'text/html' },
    });
  };
  return { fetchImpl, asked };
}

const html = (body: string) => ({ status: 200, type: 'text/html; charset=utf-8', body });

describe('extractLinks', () => {
  it('skips script bodies, honours <base>, survives unclosed junk', () => {
    expect(
      extractLinks(
        '<base href="https://cdn.example/x/"><script>var s = "<a href=/not-a-link>"</script><a href=page>p</a><a href="/never-closed',
        'https://site.example/',
      ),
    ).toEqual(['https://cdn.example/x/page']);
    // A pathological page finishes promptly (no backtracking).
    const t = Date.now();
    extractLinks('<a '.repeat(50_000) + '<!--'.repeat(20_000), 'https://site.example/');
    expect(Date.now() - t).toBeLessThan(2000);
  });

  it('resolves hrefs and srcs, drops fragments and non-http schemes', () => {
    const links = extractLinks(
      `<a href="/register">x</a><a href='#top'>t</a><a href="mailto:a@b.c">m</a>
       <img src="img/logo.png"><a href="https://other.example/x#y">o</a>
       <link rel="preconnect" href="https://fonts.example"><!-- <a href="/commented"> -->`,
      'https://site.example/traffic',
    );
    expect(links.sort()).toEqual([
      'https://other.example/x',
      'https://site.example/img/logo.png',
      'https://site.example/register',
    ]);
  });
});

describe('isBrokenStatus', () => {
  it('reports 404/410/5xx, not bot walls', () => {
    expect([404, 410, 500, 502].every(isBrokenStatus)).toBe(true);
    expect([200, 301, 401, 402, 403, 405, 429, 999].some(isBrokenStatus)).toBe(false);
  });
});

describe('crawlSite', () => {
  it('finds the /register 404 linked from /traffic (the bug that started this)', async () => {
    const { fetchImpl } = web({
      'https://threatcrush.example/': html('<a href="/traffic">Traffic</a><a href="/auth/signup">Sign up</a>'),
      'https://threatcrush.example/traffic': html('<a href="/register">Get an API key</a>'),
      'https://threatcrush.example/auth/signup': html('<h1>Sign up</h1>'),
    });
    const r = await crawlSite('https://threatcrush.example', { fetchImpl });
    expect(r.pages).toBe(3);
    expect(r.broken).toEqual([
      {
        url: 'https://threatcrush.example/register',
        status: 404,
        error: null,
        internal: true,
        foundOn: ['https://threatcrush.example/traffic'],
      },
    ]);
  });

  it('checks externals once, believes a GET over a bad HEAD, ignores flaky strangers', async () => {
    const { fetchImpl, asked } = web({
      'https://site.example/': html(
        '<a href="https://ok.example/">ok</a><a href="https://gone.example/a">gone</a><a href="https://slow.example/">slow</a><a href="https://headless.example/">h</a>',
      ),
      'https://ok.example/': { status: 200 },
      'https://slow.example/': Object.assign(new Error('timeout'), { name: 'TimeoutError' }),
      'https://headless.example/': { status: 200 },
    });
    const r = await crawlSite('https://site.example', { fetchImpl });
    expect(r.broken.map((b) => b.url)).toEqual(['https://gone.example/a']);
    expect(r.broken[0].internal).toBe(false);
    expect(asked.filter((a) => a === 'HEAD https://ok.example/' || a === 'GET https://ok.example/')).toEqual(['HEAD https://ok.example/']);
  });

  it('retries an own-site timeout once before calling it broken', async () => {
    let tries = 0;
    const base = web({ 'https://site.example/': html('<img src="/slow.png">') });
    const fetchImpl = async (url: string, init?: RequestInit) => {
      if (url === 'https://site.example/slow.png' && tries++ < 1) throw Object.assign(new Error('t'), { name: 'TimeoutError' });
      return url === 'https://site.example/slow.png' ? new Response('', { status: 200 }) : base.fetchImpl(url, init);
    };
    const r = await crawlSite('https://site.example', { fetchImpl });
    expect(r.broken.map((b) => b.url)).toEqual([]);
  });

  it('honours ignore_paths, max_pages and the sitemap', async () => {
    const { fetchImpl } = web({
      'https://site.example/': html('<a href="/api/x">api</a><a href="/a">a</a>'),
      'https://site.example/sitemap.xml': { status: 200, type: 'application/xml', body: '<urlset><url><loc>https://site.example/from-sitemap</loc></url></urlset>' },
      'https://site.example/a': html('<a href="/b">b</a>'),
      'https://site.example/from-sitemap': html(''),
    });
    const r = await crawlSite('https://site.example', { fetchImpl, ignorePaths: ['/api/'], maxPages: 3 });
    expect(r.broken.map((b) => b.url)).not.toContain('https://site.example/api/x');
    expect(r.pages).toBe(2);
    expect(r.truncated).toBe(true);
  });
});

describe('events and state', () => {
  const b = { url: 'https://s.example/register', status: 404, error: null, internal: true, foundOn: ['https://s.example/traffic'] };
  it('an own 404 is a medium web event naming where it is linked from', () => {
    const e = toThreatEvent('https://s.example/', b);
    expect(e).toMatchObject({ module: 'link-watch', category: 'web', severity: 'medium' });
    expect(e.message).toContain('linked from https://s.example/traffic');
  });
  it('only new breaks are emitted; fixed ones are forgotten', () => {
    const result = { site: 'https://s.example/', pages: 1, checked: 2, truncated: false, broken: [b] };
    expect(diffBroken([], result).fresh).toHaveLength(1);
    expect(diffBroken([b.url], result).fresh).toHaveLength(0);
    expect(diffBroken([b.url, 'https://s.example/fixed'], result).keep).toEqual([b.url]);
  });
});

describe('checkEntitlement', () => {
  it('runs only when the server says active', async () => {
    const ok = async () => new Response(JSON.stringify({ active: true, until: '2027-01-01' }), { status: 200 });
    const no = async () => new Response(JSON.stringify({ active: false }), { status: 200 });
    expect((await checkEntitlement('https://tc.example', 'k', ok)).active).toBe(true);
    expect((await checkEntitlement('https://tc.example', 'k', no)).active).toBe(false);
    expect((await checkEntitlement('https://tc.example', null, ok)).reason).toContain('no api_key');
    const down = async () => {
      throw new Error('ECONNREFUSED');
    };
    expect((await checkEntitlement('https://tc.example', 'k', down)).active).toBe(false);
  });
});
