/**
 * OSV.dev advisory lookup (PRD 0002 R7, R8).
 *
 * OSV is used rather than a vendor feed because it aggregates GHSA, PyPA,
 * RustSec and the Go vulnerability database behind one schema, and because it
 * is queryable without an API key — which matters for a module that is meant to
 * be on by default for operators who have no security budget.
 *
 * `fetch` is injected so the matching logic can be tested against recorded
 * fixtures without network access, and so a deployment can point at an internal
 * mirror.
 */

import { fixedVersionFor, isVersionAffected, type OsvRange } from './semver.js';

export interface OsvSeverity {
  type?: string;
  score?: string;
}

export interface OsvAffected {
  package?: { name?: string; ecosystem?: string };
  ranges?: OsvRange[];
  versions?: string[];
}

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  affected?: OsvAffected[];
  severity?: OsvSeverity[];
  database_specific?: { severity?: string };
}

export interface Finding {
  package: string;
  version: string;
  id: string;
  aliases: string[];
  summary: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  fixedIn: string | null;
  url: string;
}

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_BY_ID = 'https://api.osv.dev/v1/vulns/';

/**
 * Normalize a severity.
 *
 * OSV reports severity inconsistently: some records carry a CVSS vector, some
 * only a `database_specific.severity` string, and some carry nothing at all. A
 * record with no severity is treated as **medium** rather than dropped —
 * discarding an advisory because its metadata is thin is exactly the silent
 * false negative this module exists to prevent.
 */
export function normalizeSeverity(vuln: OsvVulnerability): Finding['severity'] {
  const label = vuln.database_specific?.severity?.toLowerCase();
  if (label && ['low', 'medium', 'moderate', 'high', 'critical'].includes(label)) {
    return label === 'moderate' ? 'medium' : (label as Finding['severity']);
  }

  const vector = vuln.severity?.find((s) => s.type?.startsWith('CVSS'))?.score;
  const score = vector ? cvssBaseScore(vector) : null;
  if (score === null) return 'medium';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

/**
 * Pull a numeric base score out of a CVSS field.
 *
 * OSV puts either a bare number or a full vector string here. Deriving a score
 * from a vector properly means implementing the CVSS formula; that is not worth
 * it for a ranking input, so an un-scored vector falls back to null and the
 * caller lands on medium.
 */
export function cvssBaseScore(field: string): number | null {
  const bare = Number(field);
  if (!Number.isNaN(bare)) return bare;

  // A few feeds append the score to the vector, e.g. "CVSS:3.1/AV:N/... 9.8".
  const trailing = /(?:^|\s)(\d{1,2}(?:\.\d)?)\s*$/.exec(field);
  return trailing ? Number(trailing[1]) : null;
}

/** Which of a vulnerability's ranges actually cover this version. */
export function affectsVersion(
  vuln: OsvVulnerability,
  name: string,
  version: string,
): { affected: boolean; fixedIn: string | null } {
  const entries = (vuln.affected ?? []).filter(
    (a) => !a.package?.name || a.package.name === name,
  );

  for (const entry of entries) {
    // An explicit version list is authoritative when present.
    if (entry.versions?.length && entry.versions.includes(version)) {
      return { affected: true, fixedIn: fixedVersionFor(version, entry.ranges ?? []) };
    }
    for (const range of entry.ranges ?? []) {
      if (isVersionAffected(version, range)) {
        return { affected: true, fixedIn: fixedVersionFor(version, entry.ranges ?? []) };
      }
    }
  }

  return { affected: false, fixedIn: null };
}

export function toFinding(
  vuln: OsvVulnerability,
  name: string,
  version: string,
  fixedIn: string | null,
): Finding {
  return {
    package: name,
    version,
    id: vuln.id,
    aliases: vuln.aliases ?? [],
    summary: vuln.summary ?? vuln.details?.split('\n')[0] ?? 'no summary provided',
    severity: normalizeSeverity(vuln),
    fixedIn,
    url: `https://osv.dev/vulnerability/${vuln.id}`,
  };
}

export interface QueryOptions {
  fetchImpl?: FetchLike;
  /** Batch size. OSV accepts large batches; smaller ones fail more gracefully. */
  chunkSize?: number;
  signal?: AbortSignal;
}

/**
 * Look up advisories for a set of packages.
 *
 * `querybatch` returns only vulnerability *ids* per query, so hydrating each
 * one costs a second request. Ids are deduplicated across packages first —
 * one advisory frequently covers many packages in a monorepo, and hydrating it
 * per-package multiplies the request count for no new information.
 */
export async function queryAdvisories(
  packages: readonly { name: string; version: string }[],
  options: QueryOptions = {},
): Promise<Finding[]> {
  const doFetch = options.fetchImpl ?? (globalThis.fetch as FetchLike);
  const chunkSize = options.chunkSize ?? 100;
  if (!doFetch || packages.length === 0) return [];

  const idsByPackage = new Map<string, Set<string>>();

  for (let i = 0; i < packages.length; i += chunkSize) {
    const chunk = packages.slice(i, i + chunkSize);
    const body = {
      queries: chunk.map((p) => ({
        package: { name: p.name, ecosystem: 'npm' },
        version: p.version,
      })),
    };

    const response = await doFetch(OSV_BATCH, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: options.signal,
    });
    if (!response.ok) {
      throw new Error(`OSV querybatch failed: HTTP ${response.status}`);
    }

    const payload = (await response.json()) as {
      results?: { vulns?: { id: string }[] }[];
    };

    payload.results?.forEach((result, index) => {
      const pkg = chunk[index];
      if (!pkg || !result.vulns?.length) return;
      const key = `${pkg.name}@${pkg.version}`;
      const set = idsByPackage.get(key) ?? new Set<string>();
      for (const vuln of result.vulns) set.add(vuln.id);
      idsByPackage.set(key, set);
    });
  }

  const uniqueIds = new Set([...idsByPackage.values()].flatMap((set) => [...set]));
  const hydrated = new Map<string, OsvVulnerability>();

  for (const id of uniqueIds) {
    const response = await doFetch(`${OSV_BY_ID}${id}`, { signal: options.signal });
    if (!response.ok) continue;
    hydrated.set(id, (await response.json()) as OsvVulnerability);
  }

  const findings: Finding[] = [];
  for (const [key, ids] of idsByPackage) {
    const at = key.lastIndexOf('@');
    const name = key.slice(0, at);
    const version = key.slice(at + 1);

    for (const id of ids) {
      const vuln = hydrated.get(id);
      if (!vuln) continue;
      // Re-check locally. querybatch is a coarse index and the authoritative
      // answer is the range data on the record itself.
      const { affected, fixedIn } = affectsVersion(vuln, name, version);
      if (affected) findings.push(toFinding(vuln, name, version, fixedIn));
    }
  }

  return findings.sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || a.package.localeCompare(b.package),
  );
}

export function severityRank(severity: Finding['severity']): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity];
}
