/**
 * Dependency advisory lookup against OSV.dev (PRD 06).
 *
 * Split out of `commands/scan.ts` unchanged in behaviour. It is the only part
 * of a scan that makes network calls, and that difference is worth a module
 * boundary: the pattern rules are deterministic and fast, this is neither, and
 * CI wants to choose. `runScan` keeps calling it (the daemon has always
 * included advisories); the CLI asks for it with `--deps`.
 */

import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ScanFinding, Severity } from '../types.js';

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  severity?: Array<{ type: string; score: string }>;
}

const LOCKFILES: readonly { file: string; ecosystem: string }[] = [
  { file: 'package-lock.json', ecosystem: 'npm' },
  { file: 'pnpm-lock.yaml', ecosystem: 'npm' },
  { file: 'yarn.lock', ecosystem: 'npm' },
  { file: 'requirements.txt', ecosystem: 'PyPI' },
  { file: 'Pipfile.lock', ecosystem: 'PyPI' },
];

/** Cap per lockfile, so a first run on a neglected tree summarises rather than floods OSV. */
const MAX_DEPS_PER_LOCKFILE = 50;

export async function scanDependencies(targetPath: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];

  for (const { file, ecosystem } of LOCKFILES) {
    const lockPath = join(targetPath, file);
    if (!existsSync(lockPath)) continue;

    let deps: Array<{ name: string; version: string }>;
    try {
      deps = parseDependencies(lockPath, file);
    } catch {
      continue;
    }

    for (const dep of deps.slice(0, MAX_DEPS_PER_LOCKFILE)) {
      let vulns: OsvVulnerability[];
      try {
        vulns = await queryOsv(dep.name, dep.version, ecosystem);
      } catch {
        continue;
      }

      for (const vuln of vulns) {
        const cvss = vuln.severity?.find((entry) => entry.type === 'CVSS_V3')?.score;
        findings.push({
          ruleId: 'dependency-known-vulnerability',
          title: 'Dependency CVE',
          file,
          line: 1,
          severity: severityFromCvss(cvss),
          confidence: 'evidence',
          message: `${dep.name}@${dep.version}: ${vuln.summary ?? vuln.id}`,
          consequence: 'A published advisory exists for the exact version resolved in this lockfile.',
          excerpt: `${vuln.id}${cvss ? ` (CVSS: ${cvss})` : ''}`,
          category: 'dependency',
        });
      }
    }
  }

  return findings;
}

function severityFromCvss(score: string | undefined): Severity {
  if (!score) return 'medium';
  const value = Number.parseFloat(score);
  if (Number.isNaN(value)) return 'medium';
  if (value >= 9) return 'critical';
  if (value >= 7) return 'high';
  if (value >= 4) return 'medium';
  return 'low';
}

function parseDependencies(lockPath: string, filename: string): Array<{ name: string; version: string }> {
  const deps: Array<{ name: string; version: string }> = [];

  if (filename === 'package-lock.json') {
    const lock = JSON.parse(readFileSync(lockPath, 'utf-8')) as {
      packages?: Record<string, { version?: string }>;
      dependencies?: Record<string, { version?: string }>;
    };
    const packages = lock.packages ?? lock.dependencies ?? {};
    for (const [key, value] of Object.entries(packages)) {
      const name = key.replace(/^node_modules\//, '');
      const version = value?.version;
      if (name && version && !name.startsWith('.')) deps.push({ name, version });
    }
    return deps;
  }

  if (filename === 'requirements.txt') {
    for (const line of readFileSync(lockPath, 'utf-8').split('\n')) {
      const match = /^([a-zA-Z0-9_.-]+)==([0-9.]+)/.exec(line);
      if (match?.[1] && match[2]) deps.push({ name: match[1], version: match[2] });
    }
  }

  return deps;
}

/** Package names and versions are validated before they reach the query body. */
function isValidPackageName(name: string): boolean {
  return /^[@a-zA-Z0-9_.\-/]{1,214}$/.test(name);
}

function isValidVersion(version: string): boolean {
  return /^[0-9a-zA-Z._\-+]{1,50}$/.test(version);
}

async function queryOsv(name: string, version: string, ecosystem: string): Promise<OsvVulnerability[]> {
  if (!isValidPackageName(name) || !isValidVersion(version)) return [];

  try {
    const response = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name, ecosystem }, version }),
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) return [];
    const data = (await response.json()) as { vulns?: OsvVulnerability[] };
    return data.vulns ?? [];
  } catch {
    return [];
  }
}
