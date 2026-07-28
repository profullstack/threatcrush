/**
 * Secret detection rules and the redaction that makes them safe to report.
 *
 * Implements PRD 0003. Two ideas do most of the work here:
 *
 *  1. **Structure beats entropy.** "This string looks random" matches minified
 *     JavaScript, base64 fixtures, UUIDs, git SHAs and lockfile integrity
 *     hashes. "This string is 20 characters beginning AKIA" does not. Where a
 *     format also carries a checksum — Stripe and GitHub both do — a candidate
 *     that fails it is a lookalike rather than a leak, and that single check is
 *     the highest-value precision lever available.
 *
 *  2. **A finding must prove itself without reproducing itself.** Findings
 *     travel to Slack, email and log files; a scanner that quotes the secret
 *     has moved it somewhere new. Redaction is therefore structural — the raw
 *     value never leaves this module — and there is deliberately no
 *     configuration option to turn it off.
 */

import { createHash } from 'node:crypto';

export type SecretSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface SecretRule {
  id: string;
  /** What was found, in words an operator can act on. */
  description: string;
  pattern: RegExp;
  severity: SecretSeverity;
  /**
   * Optional structural check. A format with a checksum can be verified rather
   * than guessed at, which turns a heuristic into a fact.
   */
  verify?: (value: string) => boolean;
}

/**
 * Base62 checksum used by GitHub's token formats (`ghp_`, `gho_`, …): the
 * final six characters are a CRC-32 of the preceding body.
 */
function githubChecksum(token: string): boolean {
  const ALPHABET = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const underscore = token.indexOf('_');
  if (underscore === -1) return false;

  const body = token.slice(underscore + 1);
  if (body.length < 7) return false;

  const payload = body.slice(0, -6);
  const checksum = body.slice(-6);

  let crc = 0xffffffff;
  for (const byte of Buffer.from(payload, 'utf8')) {
    crc ^= byte;
    for (let i = 0; i < 8; i += 1) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  crc = (crc ^ 0xffffffff) >>> 0;

  let encoded = '';
  let remaining = crc;
  while (remaining > 0) {
    encoded = ALPHABET[remaining % 62] + encoded;
    remaining = Math.floor(remaining / 62);
  }

  return encoded.padStart(6, '0') === checksum;
}

/**
 * Values that are documentation rather than credentials.
 *
 * AWS's own docs use `AKIAIOSFODNN7EXAMPLE`, Stripe publishes `sk_test_` keys,
 * and half the world's `.env.example` files say `changeme`. Reporting these
 * trains an operator to ignore the scanner, which is worse than missing them.
 */
// Every quantifier here is bounded. This regex runs against file content the
// scanner does not control, and an unbounded `<[^>]+>` gives a crafted file a
// polynomial-backtracking path — a denial of service against the security
// agent itself, which is a worse outcome than the missed placeholder that the
// bound might cost. Same reasoning applies to every pattern in this file.
const PLACEHOLDER =
  /(?:EXAMPLE|example|xxxx|XXXX|changeme|CHANGEME|your[_-]?(?:key|token|secret)|placeholder|<[^<>]{1,64}>|\bfake\b|\bdummy\b|\btest[_-]?key\b|0{8,12}|1234567890)/;

export const SECRET_RULES: readonly SecretRule[] = [
  {
    id: 'private-key',
    description: 'private key block',
    // The header alone is conclusive; no entropy judgement needed.
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    severity: 'critical',
  },
  {
    id: 'aws-access-key-id',
    description: 'AWS access key id',
    pattern: /\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b/g,
    severity: 'critical',
  },
  {
    id: 'github-token',
    description: 'GitHub token',
    pattern: /\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,255})\b/g,
    severity: 'critical',
    verify: githubChecksum,
  },
  {
    id: 'stripe-secret-key',
    description: 'Stripe live secret key',
    // Only live keys. `sk_test_` is a test credential and belongs in repos.
    pattern: /\b(sk_live_[0-9A-Za-z]{16,})\b/g,
    severity: 'critical',
  },
  {
    id: 'slack-token',
    description: 'Slack token',
    pattern: /\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/g,
    severity: 'high',
  },
  {
    id: 'google-api-key',
    description: 'Google API key',
    pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    severity: 'high',
  },
  {
    id: 'openai-api-key',
    description: 'OpenAI API key',
    pattern: /\b(sk-(?:proj-)?[0-9A-Za-z_-]{20,})\b/g,
    severity: 'critical',
  },
  {
    id: 'anthropic-api-key',
    description: 'Anthropic API key',
    pattern: /\b(sk-ant-[0-9A-Za-z_-]{20,})\b/g,
    severity: 'critical',
  },
  {
    id: 'npm-token',
    description: 'npm access token',
    pattern: /\b(npm_[0-9A-Za-z]{36})\b/g,
    severity: 'high',
  },
  {
    id: 'jwt',
    description: 'JSON Web Token',
    pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    severity: 'medium',
  },
  {
    id: 'basic-auth-url',
    description: 'credentials embedded in a URL',
    pattern: /\b[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:([^\s/@]{3,})@[^\s/]+/gi,
    severity: 'high',
  },
  {
    id: 'connection-string-password',
    description: 'database connection string with an inline password',
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@]+:([^\s@]{3,})@/gi,
    severity: 'high',
  },
  {
    id: 'generic-assigned-secret',
    description: 'secret assigned to a suspiciously-named variable',
    // The contextual rule from PRD 0003 R7: entropy alone never fires, but
    // entropy assigned to something called `api_secret` is a different claim.
    pattern:
      /(?:api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|password|passwd)\s*[:=]\s*["']([^"'\s]{12,})["']/gi,
    severity: 'medium',
  },
];

/** Shannon entropy in bits per character. */
export function entropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);

  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

/**
 * Shapes that look random but are public by construction.
 *
 * Each is a named check rather than a tuning constant, so a wrong suppression
 * can be found and argued with instead of being invisible.
 */
export function isKnownNonSecret(value: string): string | null {
  if (PLACEHOLDER.test(value)) return 'placeholder-or-example';
  if (/^[0-9a-f]{40}$/i.test(value)) return 'git-sha1';
  if (/^[0-9a-f]{64}$/i.test(value)) return 'hex-digest';
  if (/^sha\d{3}-[A-Za-z0-9+/]+=*$/.test(value)) return 'lockfile-integrity';
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return 'uuid';
  if (/^data:[a-z]+\/[a-z0-9.+-]+;base64,/i.test(value)) return 'data-uri';
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip-address';
  // A run with no digits and no case mixing is prose, not a key.
  if (/^[a-z ]+$/.test(value)) return 'lowercase-prose';
  return null;
}

export interface SecretMatch {
  ruleId: string;
  description: string;
  severity: SecretSeverity;
  line: number;
  column: number;
  /** Masked. The raw value never leaves this module. */
  preview: string;
  /** `sha256:…`, stable across scans, for dedupe and allowlisting. */
  fingerprint: string;
  /** True when the format's own checksum validated. */
  verified: boolean;
  entropy: number;
}

/**
 * Mask a secret so a human can locate it without being able to use it.
 *
 * Keeps the first four and last five characters. Short values are masked
 * entirely — for those, any retained prefix is a meaningful fraction of the
 * secret.
 */
export function redact(value: string): string {
  if (value.length <= 12) return '*'.repeat(Math.min(value.length, 12));
  return `${value.slice(0, 4)}${'*'.repeat(Math.max(4, value.length - 9))}${value.slice(-5)}`;
}

export function fingerprint(value: string): string {
  return `sha256:${createHash('sha256').update(value).digest('hex').slice(0, 16)}`;
}

/** Byte offset -> 1-based line and column. */
function locate(text: string, index: number): { line: number; column: number } {
  let line = 1;
  let lineStart = 0;
  for (let i = 0; i < index; i += 1) {
    if (text[i] === '\n') {
      line += 1;
      lineStart = i + 1;
    }
  }
  return { line, column: index - lineStart + 1 };
}

export interface ScanTextOptions {
  /** Require contextual entropy for the generic rule. Default true. */
  entropyEnabled?: boolean;
  /** Minimum bits/char for the generic assigned-secret rule to fire. */
  minEntropy?: number;
}

/**
 * Find secrets in a blob of text.
 *
 * Pure and synchronous, so the rules can be tested against fixtures — including
 * the assertion that no raw value ever appears in the output.
 */
export function scanText(text: string, options: ScanTextOptions = {}): SecretMatch[] {
  const entropyEnabled = options.entropyEnabled ?? true;
  const minEntropy = options.minEntropy ?? 3.2;
  const matches: SecretMatch[] = [];
  const seen = new Set<string>();

  for (const rule of SECRET_RULES) {
    const pattern = new RegExp(rule.pattern.source, rule.pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = pattern.exec(text)) !== null) {
      // Capture group 1 where present; otherwise the whole match (the private
      // key header, which is conclusive on its own).
      const value = match[1] ?? match[0];
      if (!value) continue;

      const nonSecret = isKnownNonSecret(value);
      if (nonSecret) continue;

      // The generic rule is the noisy one, so it alone must clear an entropy
      // bar. Structured rules have already proven their shape.
      if (rule.id === 'generic-assigned-secret') {
        if (!entropyEnabled) continue;
        if (entropy(value) < minEntropy) continue;
      }

      // A format that defines a checksum gets to be checked. Failing it means
      // lookalike, not leak.
      const verified = rule.verify ? rule.verify(value) : false;
      if (rule.verify && !verified) continue;

      const print = fingerprint(value);
      const key = `${rule.id}:${print}:${match.index}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const { line, column } = locate(text, match.index);
      matches.push({
        ruleId: rule.id,
        description: rule.description,
        severity: rule.severity,
        line,
        column,
        preview: redact(value),
        fingerprint: print,
        verified,
        entropy: Number(entropy(value).toFixed(2)),
      });
    }
  }

  // Collapse rules that fired on the same value.
  //
  // A connection string matches both `basic-auth-url` and
  // `connection-string-password`; reporting one secret twice is exactly the
  // noise that gets a scanner switched off. The more severe rule wins, and on
  // a tie the more specific one — the later rule in SECRET_RULES — does.
  const bySecret = new Map<string, SecretMatch>();
  const rank = { low: 0, medium: 1, high: 2, critical: 3 };
  const specificity = new Map(SECRET_RULES.map((rule, index) => [rule.id, index]));

  for (const match of matches) {
    const key = `${match.fingerprint}:${match.line}`;
    const existing = bySecret.get(key);
    if (
      !existing ||
      rank[match.severity] > rank[existing.severity] ||
      (rank[match.severity] === rank[existing.severity] &&
        (specificity.get(match.ruleId) ?? 0) > (specificity.get(existing.ruleId) ?? 0))
    ) {
      bySecret.set(key, match);
    }
  }

  return [...bySecret.values()].sort((a, b) => a.line - b.line || a.column - b.column);
}
