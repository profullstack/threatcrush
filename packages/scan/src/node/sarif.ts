/**
 * SARIF 2.1.0 output.
 *
 * Why native, rather than converting the CLI's terminal output: a text parser
 * sitting between a scanner and its consumer fails in the one way that matters
 * — silently. `profullstack/malware-test-prs` documents three separate bugs its
 * `threatcrush-to-sarif.py` hit, and one of them (paths relative to the scan
 * root, unprefixed) made a working scan report a 0% true-positive rate. The
 * scan was fine. The pipe was lying.
 *
 * Emitting SARIF from the process that found the finding removes that class of
 * failure. It also makes the output portable: GitHub's Security tab, the
 * testbed's coverage validator, and any other SARIF consumer read the same
 * bytes, and none of them has to know what a ThreatCrush terminal line looks
 * like.
 *
 * Two details the spec is strict about and consumers are not forgiving about:
 *
 *   - `startLine` must be >= 1. Whole-file findings carry no line, so they are
 *     clamped rather than emitted as 0, which fails schema validation.
 *   - `artifactLocation.uri` must be relative to something the consumer can
 *     resolve. Absolute paths from a CI runner (`/home/runner/work/…`) match
 *     nothing in the repository view, so every finding lands "outside" whatever
 *     the consumer was scoping to.
 */

import { createHash } from 'node:crypto';
import { isAbsolute, relative, resolve, sep } from 'node:path';
import type { ScanFinding, Severity } from '../types.js';

/**
 * The key our fingerprint is published under.
 *
 * Deliberately *not* `primaryLocationLineHash`. That name is reserved: the
 * CodeQL upload action computes its own value for it and logs
 *
 *     Calculated fingerprint of 13bfd14c5cc763c:1 for file debtap line 104,
 *     but found existing inconsistent fingerprint value <ours>
 *
 * for every finding whose value differs from what it derived — which is any
 * value we supply, whatever it contains. The first attempt at this replaced
 * the old `ruleId:file:line` with a content hash and still logged the warning,
 * because the collision is over the *key*, not the format.
 *
 * Namespacing it leaves GitHub to compute the fingerprint it wants while other
 * SARIF consumers keep a stable identity from us. The version suffix is there
 * so the hash input can change later without silently redefining what an
 * existing value meant.
 */
const FINGERPRINT_KEY = 'threatcrush/contentHash/v1';

/**
 * A stable identity for a finding, for `partialFingerprints`.
 *
 * The line number is deliberately not part of it. It used to be — the value
 * was `ruleId:file:line` — which meant adding an import at the top of a file
 * re-fingerprinted every finding below it. A consumer that tracks findings by
 * fingerprint then treats them as new: previously dismissed ones come back,
 * and review comments detach from the code they were written about. Hashing
 * the rule, the file and the matched text instead keeps one finding identified
 * as one finding while it moves around the file.
 *
 * Whitespace is normalised so reindentation does not count as a new finding.
 * Two identical lines in one file collide onto one fingerprint, which is the
 * right trade: they are the same defect, and SARIF locations still tell them
 * apart.
 */
export function fingerprintOf(finding: ScanFinding): string {
  const content = finding.excerpt.replace(/\s+/g, ' ').trim();
  return createHash('sha256')
    .update(`${finding.ruleId}\n${finding.file}\n${content}`)
    .digest('hex')
    .slice(0, 32);
}

export const SARIF_VERSION = '2.1.0';
export const SARIF_SCHEMA =
  'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

/**
 * SARIF has three levels; ThreatCrush has five severities. The mapping is
 * lossy in the direction that matters least — the exact severity survives in
 * `properties.severity` and in `security-severity`, which is what GitHub's
 * Security tab actually sorts on.
 */
export function sarifLevel(severity: Severity): SarifLevel {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    default:
      return 'none';
  }
}

/** GitHub reads this to place a finding on its own severity scale. */
export function securitySeverity(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return '9.0';
    case 'high':
      return '7.0';
    case 'medium':
      return '5.0';
    case 'low':
      return '3.0';
    default:
      return '1.0';
  }
}

/**
 * Turn a finding's path into a SARIF artifact URI.
 *
 * Findings carry paths relative to the *scan root*; consumers resolve URIs
 * against the *repository root*. Those are the same directory only when the
 * scan target is `.`, and the difference is silent — `secrets/x.env` matches
 * nothing in a repository that holds `vulns/secrets/x.env`, so a working scan
 * reports every finding as out-of-scope. `root` closes that gap by
 * reconstructing the absolute path before making it relative to `base`.
 *
 * Files outside `base` keep an absolute POSIX path rather than acquiring a run
 * of `../` segments no consumer resolves usefully.
 */
export function toArtifactUri(
  filePath: string,
  base: string,
  prefix = '',
  root = base,
): string {
  const absolute = isAbsolute(filePath) ? filePath : resolve(root, filePath);
  const relativePath = relative(base, absolute);
  const escapedOut = relativePath.startsWith('..') || relativePath === '';
  const chosen = escapedOut ? absolute : relativePath;
  const posix = chosen.split(sep).join('/').replace(/^\.\//, '');
  if (!prefix || escapedOut) return posix;
  const trimmed = prefix.replace(/^\/+|\/+$/g, '');
  return trimmed ? `${trimmed}/${posix}` : posix;
}

export interface SarifOptions {
  /** Version string reported as the tool's. */
  toolVersion: string;
  /**
   * Prepended to every relative URI. Covers the one case `root` cannot: a
   * scan run from *inside* the directory it is scanning, where the repository
   * root is not an ancestor of the working directory in any way the process
   * can observe.
   */
  pathPrefix?: string;
  /** Absolute path the URIs are made relative to. Defaults to `process.cwd()`. */
  base?: string;
  /** Absolute scan root that finding paths are relative to. Defaults to `base`. */
  root?: string;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string; markdown: string };
  defaultConfiguration: { level: SarifLevel };
  properties: {
    tags: string[];
    'security-severity': string;
    precision: string;
  };
}

/**
 * Build a complete SARIF log.
 *
 * Always returns a valid run, including for zero findings — an empty `results`
 * array is a meaningful statement ("looked, found nothing") and consumers
 * distinguish it from a missing file.
 */
export function buildSarif(findings: readonly ScanFinding[], options: SarifOptions): unknown {
  const rules = new Map<string, SarifRule>();

  for (const finding of findings) {
    if (rules.has(finding.ruleId)) continue;
    const tags = ['security'];
    if (finding.cwe) tags.push(`external/cwe/${finding.cwe.toLowerCase()}`);
    tags.push(`threatcrush/${finding.category}`);

    const description = finding.consequence
      ? `${finding.title}. ${finding.consequence}`
      : finding.title;

    rules.set(finding.ruleId, {
      id: finding.ruleId,
      name: finding.ruleId,
      shortDescription: { text: finding.title },
      fullDescription: { text: description },
      help: {
        text: description,
        markdown: finding.consequence
          ? `**${finding.title}**\n\n${finding.consequence}`
          : `**${finding.title}**`,
      },
      defaultConfiguration: { level: sarifLevel(finding.severity) },
      properties: {
        tags,
        'security-severity': securitySeverity(finding.severity),
        // SARIF's vocabulary for how much the rule is claiming. It lines up
        // with the confidence model: a bare construct match is `medium`, a
        // match with visible untrusted input is `high`.
        precision: finding.confidence === 'pattern' ? 'medium' : 'high',
      },
    });
  }

  const base = options.base ?? process.cwd();
  const root = options.root ?? base;

  const results = findings.map((finding) => ({
    ruleId: finding.ruleId,
    level: sarifLevel(finding.severity),
    message: { text: finding.message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: toArtifactUri(finding.file, base, options.pathPrefix, root),
            uriBaseId: '%SRCROOT%',
          },
          region: {
            // Clamped, never 0. A whole-file finding has no line; SARIF has no
            // way to say that, and 0 fails validation outright.
            startLine: Math.max(1, finding.line),
            snippet: { text: finding.excerpt },
          },
        },
      },
    ],
    partialFingerprints: {
      [FINGERPRINT_KEY]: fingerprintOf(finding),
    },
    properties: {
      severity: finding.severity,
      confidence: finding.confidence,
      category: finding.category,
      ...(finding.cwe ? { cwe: finding.cwe } : {}),
    },
  }));

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'ThreatCrush',
            version: options.toolVersion,
            informationUri: 'https://threatcrush.com',
            rules: [...rules.values()],
          },
        },
        results,
        columnKind: 'utf16CodeUnits',
      },
    ],
  };
}
