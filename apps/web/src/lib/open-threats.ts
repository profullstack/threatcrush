import "server-only";
import { createHash } from "node:crypto";
import type { ScanFinding } from "@threatcrush/scan";
import { getSupabaseAdmin } from "@/lib/supabase";

/**
 * The OpenThreat descriptor for threatcrush.com/discovery.
 *
 * OpenThreat (logicsrc.com/openthreat) is one file a reporter serves about the
 * threats it identified in the open, at /.well-known/openthreat.json. This
 * builds ThreatCrush's from the GitHub App's scans.
 *
 * WHAT IS PUBLISHED, AND WHAT IS NOT
 *
 * Only findings from PUBLIC repositories, and only from installations whose
 * announce switch is on (it is on by default; the installer turns it off in
 * app settings). Nothing from a private repository ever reaches this file,
 * and nothing about organizations, servers, properties or detections does
 * either: those belong to paying customers and are not the open web's
 * business. Installation ids and account logins stay out too; the subject is
 * the repository, which is public by definition.
 *
 * A secret finding (`sensitive`, or category `secret`) is published as a rule,
 * a severity and a subject, and nothing more. A committed credential in a
 * public repository is already exposed; pointing at the line, or quoting it,
 * would make this page the fastest way to find it. No finding of any kind
 * carries its `excerpt`.
 *
 * FIXED
 *
 * A finding key present in an earlier scan of the same repository and absent
 * from the latest is published as `fixed`: the one fact a directory cannot
 * learn from anyone but the scanner that saw both. History is bounded to a
 * few scans per repository so the build stays cheap.
 */

export const OPENTHREAT_VERSION = "0.1";
export const MAX_THREATS = 2000;
export const HISTORY_PER_REPO = 5;
export const CACHE_MS = 5 * 60 * 1000;

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type OpenThreatItem = {
  id: string;
  kind: "finding" | "attack" | "indicator" | "advisory";
  title: string;
  severity?: Severity;
  confidence?: string;
  rule?: string;
  cwe?: string;
  category?: string;
  subject?: { name: string; url: string; ref?: string; commit?: string };
  location?: { file: string; line: number };
  status: "open" | "fixed" | "mitigated" | "blocked" | "withdrawn";
  first_seen?: string;
  last_seen?: string;
  count?: number;
  message?: string;
  consequence?: string;
  refs?: string[];
  tlp: "clear";
};

export type OpenThreatDescriptor = {
  openthreat: string;
  reporter: {
    name: string;
    web: string;
    operator: string;
    tool: string;
    policy: string;
  };
  updated: string;
  truncated?: true;
  threats: OpenThreatItem[];
};

export type InstallationRow = {
  installation_id: number;
  status: string | null;
  announce?: boolean | null;
  deleted_at?: string | null;
  suspended_at?: string | null;
};

export type RepoRow = {
  installation_id: number;
  full_name: string;
  private: boolean;
  removed_at?: string | null;
};

export type ScanRow = {
  installation_id: number;
  full_name: string;
  ref?: string | null;
  commit_sha?: string | null;
  status: string;
  findings?: ScanFinding[] | null;
  started_at: string;
  finished_at?: string | null;
};

const SITE_URL =
  process.env.NEXT_PUBLIC_APP_URL?.replace(/\/$/, "") || "https://threatcrush.com";

export const REPORTER: OpenThreatDescriptor["reporter"] = {
  name: "ThreatCrush",
  web: SITE_URL,
  operator: "https://profullstack.com/.well-known/openprofile.md",
  tool: "threatcrush",
  policy: `${SITE_URL}/discovery#policy`,
};

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** An installation publishes when it is active, not deleted or suspended, and has not turned announcements off. */
export function installationAnnounces(row: InstallationRow): boolean {
  if (row.status !== "active") return false;
  if (row.deleted_at || row.suspended_at) return false;
  // The column arrives with the announce migration; until then, the default.
  return row.announce !== false;
}

/**
 * The (installation, repository) pairs allowed into the file: public, still
 * on the installation, and on an installation that announces.
 */
export function eligibleRepos(repos: RepoRow[], installations: InstallationRow[]): Set<string> {
  const announcing = new Set(
    installations.filter(installationAnnounces).map((i) => i.installation_id)
  );
  const out = new Set<string>();
  for (const repo of repos) {
    if (repo.private) continue;
    if (repo.removed_at) continue;
    if (!announcing.has(repo.installation_id)) continue;
    out.add(repoKey(repo.installation_id, repo.full_name));
  }
  return out;
}

export function repoKey(installationId: number, fullName: string): string {
  return `${installationId}:${fullName.toLowerCase()}`;
}

export function isSensitive(finding: Pick<ScanFinding, "sensitive" | "category">): boolean {
  return finding.sensitive === true || finding.category === "secret";
}

/** Stable across line shifts: the repository, the rule and the file. */
export function threatId(fullName: string, ruleId: string, file: string): string {
  return createHash("sha256").update(`${fullName}|${ruleId}|${file}`).digest("hex").slice(0, 16);
}

function findingKey(f: ScanFinding): string {
  return `${f.ruleId}|${f.file}`;
}

function subjectFor(scan: ScanRow): OpenThreatItem["subject"] {
  return {
    name: scan.full_name,
    url: `https://github.com/${scan.full_name}`,
    ...(scan.ref ? { ref: scan.ref } : {}),
    ...(scan.commit_sha ? { commit: scan.commit_sha } : {}),
  };
}

function itemFrom(
  finding: ScanFinding,
  scan: ScanRow,
  status: OpenThreatItem["status"],
  firstSeen: string,
  lastSeen: string,
  count: number
): OpenThreatItem {
  const base: OpenThreatItem = {
    id: threatId(scan.full_name, finding.ruleId, finding.file),
    kind: "finding",
    title: finding.title,
    severity: finding.severity,
    confidence: finding.confidence,
    rule: finding.ruleId,
    ...(finding.cwe ? { cwe: finding.cwe } : {}),
    category: finding.category,
    subject: subjectFor(scan),
    status,
    first_seen: firstSeen,
    last_seen: lastSeen,
    count,
    tlp: "clear",
  };
  if (isSensitive(finding)) return base;
  return {
    ...base,
    location: { file: finding.file, line: finding.line },
    message: finding.message,
    ...(finding.consequence ? { consequence: finding.consequence } : {}),
  };
}

/**
 * Threats from the complete scans of the allowed repositories: the latest
 * scan's findings as `open`, findings that vanished since an earlier scan as
 * `fixed`. Most recently seen first.
 */
export function threatsFrom(scans: ScanRow[], allowed: Set<string>): OpenThreatItem[] {
  const byRepo = new Map<string, ScanRow[]>();
  for (const scan of scans) {
    if (scan.status !== "complete") continue;
    const key = repoKey(scan.installation_id, scan.full_name);
    if (!allowed.has(key)) continue;
    const list = byRepo.get(key) ?? [];
    list.push(scan);
    byRepo.set(key, list);
  }

  const out: OpenThreatItem[] = [];
  for (const list of byRepo.values()) {
    list.sort((a, b) => b.started_at.localeCompare(a.started_at));
    const window = list.slice(0, HISTORY_PER_REPO);
    const latest = window[0];
    const earlier = window.slice(1);
    const latestSeen = latest.finished_at ?? latest.started_at;

    // Earliest scan in the window that carried each key.
    const firstSeen = new Map<string, string>();
    for (const scan of [...window].reverse()) {
      for (const f of scan.findings ?? []) {
        const k = findingKey(f);
        if (!firstSeen.has(k)) firstSeen.set(k, scan.started_at);
      }
    }

    const inLatest = new Map<string, { finding: ScanFinding; count: number }>();
    for (const f of latest.findings ?? []) {
      const k = findingKey(f);
      const hit = inLatest.get(k);
      if (hit) hit.count += 1;
      else inLatest.set(k, { finding: f, count: 1 });
    }
    for (const [k, { finding, count }] of inLatest) {
      out.push(
        itemFrom(finding, latest, "open", firstSeen.get(k) ?? latest.started_at, latestSeen, count)
      );
    }

    const fixed = new Map<string, { finding: ScanFinding; scan: ScanRow }>();
    for (const scan of earlier) {
      for (const f of scan.findings ?? []) {
        const k = findingKey(f);
        if (inLatest.has(k) || fixed.has(k)) continue;
        fixed.set(k, { finding: f, scan });
      }
    }
    for (const [k, { finding, scan }] of fixed) {
      out.push(
        itemFrom(
          finding,
          { ...latest, ref: scan.ref, commit_sha: scan.commit_sha },
          "fixed",
          firstSeen.get(k) ?? scan.started_at,
          latestSeen,
          0
        )
      );
    }
  }

  out.sort((a, b) => {
    const t = (b.last_seen ?? "").localeCompare(a.last_seen ?? "");
    if (t !== 0) return t;
    return SEVERITY_RANK[b.severity ?? "info"] - SEVERITY_RANK[a.severity ?? "info"];
  });
  return out;
}

export function buildDescriptor(threats: OpenThreatItem[], updated = new Date()): OpenThreatDescriptor {
  const capped = threats.slice(0, MAX_THREATS);
  return {
    openthreat: OPENTHREAT_VERSION,
    reporter: REPORTER,
    updated: updated.toISOString(),
    ...(threats.length > MAX_THREATS ? { truncated: true as const } : {}),
    threats: capped,
  };
}

/** Everything the file must never contain, checked once more at the door. */
export function assertNoPrivateData(descriptor: OpenThreatDescriptor): void {
  const text = JSON.stringify(descriptor);
  for (const forbidden of ["installation_id", "account_login", "sender_login", "excerpt", "organization"]) {
    if (text.includes(`"${forbidden}"`)) {
      throw new Error(`OpenThreat descriptor carries a forbidden key: ${forbidden}`);
    }
  }
}

// ─── Loading ───

type Loaded = { descriptor: OpenThreatDescriptor; at: number };
let cache: Loaded | null = null;

const isMissingColumn = (err: { code?: string; message?: string } | null | undefined) =>
  err?.code === "42703" || /announce/.test(err?.message ?? "");

const isMissingTable = (err: { code?: string } | null | undefined) => err?.code === "42P01";

async function loadInstallations(): Promise<InstallationRow[]> {
  const admin = getSupabaseAdmin();
  const withAnnounce = await admin
    .from("github_installations")
    .select("installation_id, status, announce, deleted_at, suspended_at")
    .eq("status", "active");
  if (!withAnnounce.error) return (withAnnounce.data ?? []) as InstallationRow[];
  if (isMissingTable(withAnnounce.error)) return [];
  if (!isMissingColumn(withAnnounce.error)) throw new Error(withAnnounce.error.message);

  // Announce migration not applied yet: every active installation announces.
  const plain = await admin
    .from("github_installations")
    .select("installation_id, status, deleted_at, suspended_at")
    .eq("status", "active");
  if (plain.error) throw new Error(plain.error.message);
  return (plain.data ?? []) as InstallationRow[];
}

export async function loadOpenThreat(now = Date.now()): Promise<OpenThreatDescriptor> {
  if (cache && now - cache.at < CACHE_MS) return cache.descriptor;

  const admin = getSupabaseAdmin();
  const installations = await loadInstallations();

  const repos = await admin
    .from("github_installation_repositories")
    .select("installation_id, full_name, private, removed_at")
    .eq("private", false)
    .is("removed_at", null);
  if (repos.error && !isMissingTable(repos.error)) throw new Error(repos.error.message);

  const allowed = eligibleRepos((repos.data ?? []) as RepoRow[], installations);

  let threats: OpenThreatItem[] = [];
  if (allowed.size > 0) {
    const names = Array.from(
      new Set(((repos.data ?? []) as RepoRow[]).map((r) => r.full_name))
    );
    const scans = await admin
      .from("github_repo_scans")
      .select("installation_id, full_name, ref, commit_sha, status, findings, started_at, finished_at")
      .eq("status", "complete")
      .in("full_name", names)
      .order("started_at", { ascending: false })
      .limit(5000);
    if (scans.error && !isMissingTable(scans.error)) throw new Error(scans.error.message);
    threats = threatsFrom((scans.data ?? []) as ScanRow[], allowed);
  }

  const descriptor = buildDescriptor(threats);
  assertNoPrivateData(descriptor);
  cache = { descriptor, at: now };
  return descriptor;
}

/** For tests and for a settings change that should show up before the cache expires. */
export function resetOpenThreatCache(): void {
  cache = null;
}
