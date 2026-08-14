/**
 * Missing security controls: findings about what is *not* there.
 *
 * Every other rule in this package reports a construct it can point at. This
 * one reports an absence — no rate limiter anywhere in an HTTP service, no
 * CSRF token, no security headers — which is a different kind of claim and
 * needs different handling in three ways.
 *
 *   **It is whole-project, not per-line.** A rate limiter installed in
 *   `app.js` protects a route defined in `routes/admin.js`. Any per-file rule
 *   would report the second file while the first sits three directories away
 *   with the answer in it. So this accumulates across the whole walk and
 *   reports once, at the end.
 *
 *   **It is weaker evidence.** "We did not see a CSRF token" is not the same
 *   statement as "we saw a SQL query built by concatenation". The control may
 *   be installed by a framework, by a reverse proxy, by an API gateway, or by
 *   a package whose name nobody here has heard of. So these are opt-in — the
 *   CLI asks for them with `--missing-controls` — and they report at
 *   confidence `pattern`, which the shared cap in `types.ts` holds at medium.
 *
 *   **It needs an applicability test.** "This library has no CSRF protection"
 *   is not a finding, it is a category error. Nothing is reported unless the
 *   tree contains something that answers HTTP requests.
 *
 * Provenance: the idea of inverting rules to report absent controls is
 * njsscan's, and the four controls checked here are the ones it covers. The
 * mechanism is not — njsscan detects controls with its ordinary rule engine
 * and subtracts the hits afterwards, while this accumulates evidence during
 * the walk so no file has to be held in memory. Patterns and prose are
 * original; see the licence note at the top of `node-rules.ts`.
 */

import type { ScanFinding, Severity } from './types';
import { severityFor } from './types';

export interface SecurityControl {
  id: string;
  title: string;
  /** What the absence costs. */
  consequence: string;
  cwe: string;
  severity: Severity;
  /** Anything matching this, anywhere in the tree, counts as installed. */
  evidence: RegExp;
}

/**
 * Evidence that this tree serves HTTP.
 *
 * The gate for the whole module. A CLI, a library or a batch job has no
 * business being told it is missing a CSRF token, and reporting one is the
 * fastest way to teach an operator that these findings are noise.
 *
 * Deliberately narrow: constructing the server, not merely importing
 * something HTTP-shaped. A build script that requires `express` to type a
 * config object is not a web service.
 */
const SERVER_FRAMEWORK =
  /\bexpress\s*\(\s*\)|\bnew\s+Koa\s*\(|\bfastify\s*\(|\brequire\s*\(\s*['"](?:express|koa|@hapi\/hapi|restify)['"]\s*\)|\bfrom\s+['"](?:express|koa|@hapi\/hapi|restify)['"]|\bhttp\s*\.\s*createServer\s*\(|\bNestFactory\s*\.\s*create\s*\(/;

export const SECURITY_CONTROLS: readonly SecurityControl[] = [
  {
    id: 'control-security-headers-absent',
    title: 'no security header middleware',
    consequence:
      'Without them the browser applies no framing protection, sniffs content types, sends full referrers cross-origin and never learns to require HTTPS — a set of defences that cost one line to enable.',
    cwe: 'CWE-693',
    severity: 'medium',
    evidence:
      /\bhelmet\b|\bkoa-helmet\b|\b@fastify\/helmet\b|\blusca\b|Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options/i,
  },
  {
    id: 'control-anti-csrf-absent',
    title: 'no cross-site request forgery protection',
    consequence:
      'A cookie-authenticated endpoint with no token check can be driven by a form on any other site — the browser attaches the session automatically, so the victim only has to visit a page.',
    cwe: 'CWE-352',
    severity: 'medium',
    // SameSite counts. A cookie the browser refuses to send cross-site is not
    // reachable by the attack this control exists to stop, so a project that
    // chose that route instead of tokens has the control, not a gap.
    evidence:
      /\bcsurf\b|\bcsrf\b|\bxsrf\b|\blusca\b|\b@fastify\/csrf\b|\bdouble-csrf\b|\bsameSite\s*:\s*['"](?:strict|lax)['"]/i,
  },
  {
    id: 'control-rate-limiting-absent',
    title: 'no request rate limiting',
    consequence:
      'Login and password-reset endpoints with no limiter can be tried at the speed of the network — credential stuffing, token brute force and enumeration all become a matter of waiting.',
    cwe: 'CWE-770',
    severity: 'medium',
    evidence:
      /\bexpress-rate-limit\b|\brateLimit\b|\brate-limiter\b|\bratelimit\b|\bexpress-slow-down\b|\bslowDown\b|\bbottleneck\b|\bthrottle\b/i,
  },
  {
    id: 'control-body-size-limit-absent',
    title: 'no request body size limit',
    consequence:
      'The body is parsed into memory before any handler — and before any authentication check — so unbounded parsing lets a few concurrent requests exhaust the process.',
    cwe: 'CWE-400',
    severity: 'medium',
    evidence: /\blimit\s*:\s*['"]?\d+\s*(?:kb|mb|b)\b|\bbodyLimit\b|\bmaxRequestBodySize\b|\bclient_max_body_size\b/i,
  },
];

/**
 * Accumulates control evidence over a walk, then reports what was never seen.
 *
 * Holds four booleans and one path, not the files — a whole-project question
 * answered without a whole-project buffer, which matters because the walker is
 * otherwise streaming and a repository can be large.
 */
export class ControlAudit {
  private readonly seen = new Set<string>();
  /** Where the server is built. Anchors the findings somewhere meaningful. */
  private serverFile: string | null = null;

  observe(relativePath: string, text: string): void {
    if (this.serverFile === null && SERVER_FRAMEWORK.test(text)) {
      this.serverFile = relativePath;
    }
    for (const control of SECURITY_CONTROLS) {
      if (this.seen.has(control.id)) continue;
      if (control.evidence.test(text)) this.seen.add(control.id);
    }
  }

  /** Controls with no evidence anywhere. Empty when the tree serves no HTTP. */
  missing(): readonly SecurityControl[] {
    if (this.serverFile === null) return [];
    return SECURITY_CONTROLS.filter((control) => !this.seen.has(control.id));
  }

  findings(): ScanFinding[] {
    const anchor = this.serverFile;
    if (anchor === null) return [];

    return this.missing().map((control) => ({
      ruleId: control.id,
      title: control.title,
      file: anchor,
      line: 1,
      // `pattern` is doing real work here: it caps the severity, and it says
      // in the report itself how much the scanner is claiming. An absence is
      // never `evidence`.
      severity: severityFor(control.severity, 'pattern'),
      confidence: 'pattern' as const,
      message: `${control.title} — no evidence of one anywhere in the scanned tree (${control.cwe})`,
      consequence: control.consequence,
      cwe: control.cwe,
      excerpt: '',
      category: 'code' as const,
    }));
  }
}
