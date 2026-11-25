/**
 * Execution — run benign, non-destructive probes against one planned action and
 * score the response into findings.
 *
 * Hard rules (this is a tool you point at your OWN systems, so it still must be
 * safe): only GET/HEAD/OPTIONS are ever sent; write methods from the surface map
 * are downgraded to an OPTIONS pre-flight. Injection checks use a harmless
 * per-run canary and look for UNENCODED reflection — they never try to execute
 * anything. On a transport error we self-correct (one retry, longer timeout);
 * a suspected finding is verified with a second request before it is kept.
 */

import type { Severity, StructuredFinding } from '../core/run-result.js';
import type { Action } from './plan.js';
import type { Fetcher } from './recon.js';

export interface ResponseView {
  status: number;
  headers: Record<string, string>;
  body: string;
}

const HIGH_RISK_PATH = /(?:^|\/)(?:admin|config|secret|\.env|\.git|actuator|debug|internal|billing|payment)(?:\/|$|\?)/i;

/** Make the harmless canary a run uses to detect unencoded reflection. */
export function makeCanary(): string {
  return `tcrt${Math.random().toString(36).slice(2, 10)}`;
}

/** Pure scoring of one response. No network. */
export function evaluateResponse(action: Action, res: ResponseView, canary: string): StructuredFinding[] {
  const out: StructuredFinding[] = [];
  const h = res.headers;
  const loc = `${action.method} ${action.url}`;

  // Unauthenticated reach of a sensitive endpoint.
  if (HIGH_RISK_PATH.test(action.path) && res.status >= 200 && res.status < 300) {
    out.push({
      type: 'unauthenticated-access',
      severity: HIGH_RISK_PATH.test(action.path) && /\.env|\.git|secret|config|actuator/i.test(action.path) ? 'high' : 'medium',
      message: `Sensitive path ${action.path} is reachable (HTTP ${res.status}) without authentication`,
      location: loc,
      details: { status: res.status, remediation: 'Require authentication/authorization on this endpoint, or remove it from the public surface.' },
    });
  }

  // Unencoded reflection of our canary → possible reflected XSS.
  if (canary && res.body.includes(canary)) {
    out.push({
      type: 'reflected-input',
      severity: 'medium',
      message: `Input is reflected unencoded in the response for ${action.path} — review for reflected XSS`,
      location: loc,
      details: { remediation: 'Context-encode reflected user input; add a Content-Security-Policy.' },
    });
  }

  // Error / stack-trace disclosure.
  if (/stack trace|traceback|exception in|at [\w.$]+\([\w.]+:\d+\)|ORA-\d{4,}|SQLSTATE/i.test(res.body)) {
    out.push({
      type: 'error-disclosure',
      severity: 'low',
      message: `Response for ${action.path} leaks an internal error/stack trace`,
      location: loc,
      details: { remediation: 'Return generic error pages; log details server-side only.' },
    });
  }

  // Directory listing.
  if (/<title>\s*Index of\s*\/|Directory listing for/i.test(res.body)) {
    out.push({
      type: 'directory-listing',
      severity: 'medium',
      message: `Directory listing is enabled at ${action.path}`,
      location: loc,
      details: { remediation: 'Disable automatic directory indexing.' },
    });
  }

  // Wide-open CORS.
  const acao = h['access-control-allow-origin'];
  if (acao === '*' || acao === 'null') {
    out.push({
      type: 'cors',
      severity: 'medium',
      message: `${action.path} returns Access-Control-Allow-Origin: ${acao}`,
      location: loc,
      details: { remediation: 'Reflect only an allow-list of trusted origins.' },
    });
  }

  // Information disclosure via server banners.
  const banner = h['server'] || h['x-powered-by'];
  if (banner && /\d/.test(banner)) {
    out.push({
      type: 'version-disclosure',
      severity: 'info',
      message: `${action.path} discloses software version: ${banner}`,
      location: loc,
      details: { remediation: 'Suppress version strings in Server / X-Powered-By.' },
    });
  }

  return out;
}

export interface ExecOptions {
  timeoutMs?: number;
  canary?: string;
}

export interface ExecResult {
  action: Action;
  status: number | null;
  findings: StructuredFinding[];
  note: string;
}

/** Only ever send a safe method; downgrade writes to a pre-flight OPTIONS. */
function safeMethod(method: string): 'GET' | 'HEAD' | 'OPTIONS' {
  if (method === 'HEAD') return 'HEAD';
  if (['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'].includes(method)) return 'OPTIONS';
  return 'GET';
}

async function readResponse(fetchFn: Fetcher, url: string, method: string, timeoutMs: number): Promise<ResponseView> {
  const r = await fetchFn(url, { method, signal: AbortSignal.timeout(timeoutMs) });
  const headers: Record<string, string> = {};
  // The Fetcher's headers only exposes get(); pull the ones we score.
  for (const name of ['access-control-allow-origin', 'server', 'x-powered-by', 'content-type']) {
    const v = r.headers.get(name);
    if (v) headers[name] = v;
  }
  const body = method === 'GET' ? await r.text() : '';
  return { status: r.status, headers, body };
}

/**
 * Execute one action with self-correction (one retry on transport error) and
 * verification (a flagged finding is re-checked once). Never throws.
 */
export async function executeAction(action: Action, fetchFn: Fetcher, opts: ExecOptions = {}): Promise<ExecResult> {
  const timeoutMs = opts.timeoutMs ?? 8000;
  const canary = opts.canary ?? makeCanary();
  const method = safeMethod(action.method);
  // Thread the canary through a benign query param to test for reflection.
  const probeUrl = method === 'GET' ? appendQuery(action.url, 'tc', canary) : action.url;

  let res: ResponseView | null = null;
  let note = '';
  for (let attempt = 0; attempt < 2 && !res; attempt++) {
    try {
      res = await readResponse(fetchFn, probeUrl, method, timeoutMs * (attempt + 1));
    } catch (err) {
      note = `transport error: ${(err as Error).message}`;
      if (attempt === 0) note += ' (retried)';
    }
  }
  if (!res) return { action, status: null, findings: [], note: note || 'unreachable' };

  let findings = evaluateResponse(action, res, canary);

  // Verify an unauthenticated-access finding with a second plain request.
  if (findings.some((f) => f.type === 'unauthenticated-access')) {
    try {
      const confirm = await readResponse(fetchFn, action.url, method, timeoutMs);
      if (!(confirm.status >= 200 && confirm.status < 300)) {
        findings = findings.filter((f) => f.type !== 'unauthenticated-access');
        note = note ? `${note}; unauth finding not reproduced on verify` : 'unauth finding not reproduced on verify';
      }
    } catch {
      /* keep original finding if verify request fails */
    }
  }

  return { action, status: res.status, findings, note };
}

function appendQuery(url: string, key: string, value: string): string {
  try {
    const u = new URL(url);
    u.searchParams.set(key, value);
    return u.toString();
  } catch {
    return url;
  }
}

export const SEVERITY_FOR_TYPE: Record<string, Severity> = {
  'unauthenticated-access': 'high',
  'reflected-input': 'medium',
  'directory-listing': 'medium',
  cors: 'medium',
  'error-disclosure': 'low',
  'version-disclosure': 'info',
};
