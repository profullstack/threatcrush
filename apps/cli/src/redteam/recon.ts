/**
 * Recon — the discovery phase of an autonomous red-team run.
 *
 * Given a target you own, build an attack-surface map: same-origin links,
 * forms, robots/sitemap paths, and — the part that matters most, the way the
 * ARTEX-class tools work — any OpenAPI/Swagger specs and JavaScript source maps
 * the app exposes, parsed into a concrete route list.
 *
 * Everything here is read-only: GET/HEAD of documents the app already serves.
 * The parsing helpers are pure so they can be unit-tested without a network.
 */

export type Fetcher = (url: string, init?: { method?: string; signal?: AbortSignal }) => Promise<{
  status: number;
  ok: boolean;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}>;

export interface Route {
  path: string;
  method: string;
  /** Where we learned about this route. */
  source: 'html' | 'form' | 'robots' | 'sitemap' | 'openapi' | 'sourcemap';
}

export interface Surface {
  target: string;
  origin: string;
  routes: Route[];
  notes: string[];
}

const SPEC_PATHS = [
  '/openapi.json', '/openapi.yaml', '/swagger.json', '/swagger/v1/swagger.json',
  '/api-docs', '/v2/api-docs', '/v3/api-docs', '/.well-known/openapi.json',
];

/** Same-origin hrefs/srcs from an HTML document, as absolute-path strings. */
export function extractLinks(html: string, baseUrl: string): string[] {
  const base = new URL(baseUrl);
  const out = new Set<string>();
  const re = /(?:href|src|action)\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    const raw = m[1].trim();
    if (!raw || raw.startsWith('#') || raw.startsWith('mailto:') || raw.startsWith('javascript:') || raw.startsWith('data:')) continue;
    try {
      const u = new URL(raw, base);
      if (u.origin === base.origin) out.add(u.pathname + (u.search || ''));
    } catch {
      /* ignore malformed */
    }
  }
  return [...out];
}

export interface FormInfo {
  action: string;
  method: string;
  inputs: string[];
}

/** Forms (action, method, input names) from an HTML document. */
export function extractForms(html: string): FormInfo[] {
  const forms: FormInfo[] = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let fm: RegExpExecArray | null;
  while ((fm = formRe.exec(html))) {
    const attrs = fm[1];
    const inner = fm[2];
    const action = /\baction\s*=\s*["']([^"']*)["']/i.exec(attrs)?.[1] ?? '';
    const method = (/\bmethod\s*=\s*["']([^"']*)["']/i.exec(attrs)?.[1] ?? 'GET').toUpperCase();
    const inputs: string[] = [];
    const inputRe = /<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)["']/gi;
    let im: RegExpExecArray | null;
    while ((im = inputRe.exec(inner))) inputs.push(im[1]);
    forms.push({ action, method, inputs });
  }
  return forms;
}

/** Routes from an OpenAPI/Swagger document (v2 or v3), as {path, method}. */
export function parseOpenApi(json: unknown): Route[] {
  const out: Route[] = [];
  const doc = json as { paths?: Record<string, Record<string, unknown>> } | null;
  if (!doc || typeof doc !== 'object' || !doc.paths) return out;
  for (const [path, item] of Object.entries(doc.paths)) {
    if (!item || typeof item !== 'object') continue;
    for (const method of Object.keys(item)) {
      if (['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(method.toLowerCase())) {
        out.push({ path, method: method.toUpperCase(), source: 'openapi' });
      }
    }
  }
  return out;
}

/** sourceMappingURL references in a JS bundle. */
export function extractSourceMapUrls(js: string): string[] {
  const out: string[] = [];
  const re = /[#@]\s*sourceMappingURL=([^\s'"]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(js))) if (!m[1].startsWith('data:')) out.push(m[1]);
  return out;
}

/** Disallow/Allow paths from a robots.txt body. */
export function parseRobots(body: string): string[] {
  const out = new Set<string>();
  for (const line of body.split(/\r?\n/)) {
    const m = /^\s*(?:dis)?allow\s*:\s*(\S+)/i.exec(line);
    if (m && m[1] !== '/' && m[1] !== '*') out.add(m[1]);
  }
  return [...out];
}

/** <loc> URLs from a sitemap.xml, as same-origin paths. */
export function parseSitemap(xml: string, origin: string): string[] {
  const out = new Set<string>();
  const re = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml))) {
    try {
      const u = new URL(m[1]);
      if (u.origin === origin) out.add(u.pathname);
    } catch {
      /* ignore */
    }
  }
  return [...out];
}

async function tryText(fetchFn: Fetcher, url: string): Promise<string | null> {
  try {
    const r = await fetchFn(url, { method: 'GET', signal: AbortSignal.timeout(8000) });
    if (!r.ok) return null;
    return await r.text();
  } catch {
    return null;
  }
}

export interface ReconOptions {
  /** Max routes to keep in the surface map (default 60). */
  maxRoutes?: number;
  /** Skip spec/source-map probing (faster, HTML only). */
  htmlOnly?: boolean;
}

/** Build the attack-surface map for a target. Read-only. */
export async function discoverSurface(target: string, fetchFn: Fetcher, opts: ReconOptions = {}): Promise<Surface> {
  const url = target.startsWith('http') ? target : `https://${target}`;
  const origin = new URL(url).origin;
  const notes: string[] = [];
  const routes = new Map<string, Route>();
  const add = (r: Route) => { const k = `${r.method} ${r.path}`; if (!routes.has(k)) routes.set(k, r); };

  // Landing page: links + forms.
  const html = await tryText(fetchFn, url);
  if (html) {
    for (const p of extractLinks(html, url)) add({ path: p, method: 'GET', source: 'html' });
    for (const f of extractForms(html)) {
      let path = f.action;
      try { path = new URL(f.action || url, url).pathname; } catch { /* keep raw */ }
      add({ path, method: f.method, source: 'form' });
    }
    notes.push(`landing page: ${extractLinks(html, url).length} link(s), ${extractForms(html).length} form(s)`);
  } else {
    notes.push('landing page did not return readable HTML');
  }

  if (!opts.htmlOnly) {
    // robots.txt + sitemap.xml
    const robots = await tryText(fetchFn, `${origin}/robots.txt`);
    if (robots) for (const p of parseRobots(robots)) add({ path: p, method: 'GET', source: 'robots' });
    const sitemap = await tryText(fetchFn, `${origin}/sitemap.xml`);
    if (sitemap) for (const p of parseSitemap(sitemap, origin)) add({ path: p, method: 'GET', source: 'sitemap' });

    // OpenAPI / Swagger specs — the highest-value recon.
    for (const sp of SPEC_PATHS) {
      const body = await tryText(fetchFn, `${origin}${sp}`);
      if (!body) continue;
      try {
        const parsed = parseOpenApi(JSON.parse(body));
        if (parsed.length) {
          for (const r of parsed) add(r);
          notes.push(`found API spec at ${sp}: ${parsed.length} route(s)`);
        }
      } catch {
        /* not JSON (maybe YAML) — skip */
      }
    }
  }

  const maxRoutes = opts.maxRoutes ?? 60;
  return { target: url, origin, routes: [...routes.values()].slice(0, maxRoutes), notes };
}
