import "server-only";
import { createHash } from "node:crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import { createAppJwt, createInstallationToken, readAppCredentials } from "./github-app";
import { classifyRepositoryFindings, type RepositoryFinding } from "./repository-warnings";
import { scanRepository } from "./github-repo-scan";
import { parseIncidentReport } from "./incidents/report";
import { pageable, upsertIncident } from "./incidents/store";
import { notifyIncident } from "./incidents/notify";

export type GitHubOwner = { id: number; login: string; type: string };
export type GitHubInstallation = { id: number; account: GitHubOwner; repository_selection: string; suspended_at: string | null };
type GitHubRepo = { id: number; full_name: string; default_branch?: string; pushed_at: string | null; archived?: boolean };
export type MonitoringOwner = { id: string; org_id: string; installation_id: number; account_id: number; account_login: string; enabled: boolean; silence_examples: boolean; silence_warnings: boolean; last_discovery_at: string | null };

export class GitHubMonitorError extends Error {
  constructor(public status: number, message: string) { super(message); }
}
export async function githubRead<T>(path: string, token: string, fetcher: typeof fetch = fetch): Promise<T> {
  const res = await fetcher(`https://api.github.com${path}`, { headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": "ThreatCrush", "X-GitHub-Api-Version": "2022-11-28" }, redirect: "error", signal: AbortSignal.timeout(30000) });
  if (!res.ok) throw new GitHubMonitorError(res.status, res.status === 403 || res.status === 429 ? "GitHub access or rate limit: reconnect or retry after quota resets" : `GitHub request failed (${res.status})`);
  return res.json();
}

/** All pages, not the first 30/100 repos. Never present a capped list as complete. */
export async function githubPages<T>(path: string, token: string, field?: string, fetcher: typeof fetch = fetch): Promise<T[]> {
  const all: T[] = [];
  for (let page = 1; page <= 100; page++) {
    const response = await githubRead<unknown>(`${path}${path.includes("?") ? "&" : "?"}per_page=100&page=${page}`, token, fetcher);
    const batch = field ? (response as Record<string, unknown>)[field] : response;
    if (!Array.isArray(batch)) throw new Error("Invalid GitHub list response");
    all.push(...batch);
    if (batch.length < 100) return all;
  }
  throw new Error("GitHub list exceeded 10000 entries; discovery was not completed");
}

export function appToken(): string {
  const credentials = readAppCredentials();
  if (!credentials) throw new Error("GitHub App is not configured");
  return createAppJwt(credentials.appId, credentials.privateKey, Math.floor(Date.now() / 1000));
}
export async function installations(): Promise<GitHubInstallation[]> { return githubPages("/app/installations", appToken()); }

/** Only personal ownership and verified active GitHub org admins authorize linking. */
export async function verifyGitHubIdentity(token: string, fetcher: typeof fetch = fetch) {
  const user = await githubRead<{ id: number; login: string }>("/user", token, fetcher);
  if (!Number.isSafeInteger(user.id) || !/^[\w-]+$/.test(user.login)) throw new Error("Invalid GitHub identity");
  const memberships = await githubPages<{ role: string; state: string; organization: GitHubOwner }>("/user/memberships/orgs?state=active", token, undefined, fetcher);
  const owners: GitHubOwner[] = [{ id: user.id, login: user.login, type: "User" }, ...memberships.filter((m) => m.state === "active" && m.role === "admin").map((m) => ({ ...m.organization, type: "Organization" }))];
  return { user, owners };
}

export async function linkIdentity(admin: SupabaseClient, orgId: string, userId: string, token: string) {
  const identity = await verifyGitHubIdentity(token);
  const saved = await admin.from("github_monitoring_links").upsert({ org_id: orgId, user_id: userId, github_user_id: identity.user.id, github_login: identity.user.login, allowed_owners: identity.owners, updated_at: new Date().toISOString() }, { onConflict: "org_id,github_user_id" });
  if (saved.error) throw new Error("Could not save GitHub connection");
  return identity;
}

/** Bind only installations matched to a previously verified GitHub owner ID. */
export async function enableOwners(admin: SupabaseClient, orgId: string, ownerIds: number[]) {
  const links = await admin.from("github_monitoring_links").select("allowed_owners").eq("org_id", orgId);
  if (links.error) throw new Error("Could not load GitHub identities");
  const allowed = new Set((links.data ?? []).flatMap((l) => (l.allowed_owners as GitHubOwner[]).map((o) => o.id)));
  if (!ownerIds.length || ownerIds.some((id) => !allowed.has(id))) throw new GitHubMonitorError(403, "Connect and authorize that GitHub account or organization first");
  const installed = await installations();
  const selected = installed.filter((i) => ownerIds.includes(i.account.id) && !i.suspended_at);
  if (selected.length !== new Set(ownerIds).size) throw new GitHubMonitorError(409, "Install the ThreatCrush GitHub App for the missing account/organization first, choosing All repositories");
  for (const i of selected) {
    const recorded = await admin.from("github_installations").upsert({ installation_id: i.id, account_id: i.account.id, account_login: i.account.login, account_type: i.account.type, repository_selection: i.repository_selection, status: "active", updated_at: new Date().toISOString() }, { onConflict: "installation_id" });
    if (recorded.error) throw new Error("Could not record GitHub installation");
    const owner = await admin.from("github_monitoring_owners").upsert({ org_id: orgId, installation_id: i.id, account_id: i.account.id, account_login: i.account.login, enabled: true }, { onConflict: "org_id,installation_id" }).select("*").single();
    if (owner.error) throw new Error("Could not enable monitoring");
    await discoverOwner(admin, owner.data as MonitoringOwner);
  }
}

export async function discoverOwner(admin: SupabaseClient, owner: MonitoringOwner) {
  const { token } = await createInstallationToken(appToken(), owner.installation_id);
  const repos = await githubPages<GitHubRepo>("/installation/repositories", token, "repositories");
  // The installation belongs to this owner. Never import an unexpected account.
  if (repos.some((r) => r.full_name.split("/")[0].toLowerCase() !== owner.account_login.toLowerCase())) throw new Error("Repository owner mismatch");
  const old = await admin.from("github_monitoring_repositories").select("id,repo_id,pushed_at,status,next_scan_at,error").eq("owner_id", owner.id);
  if (old.error) throw new Error("Could not load monitored repositories");
  const byId = new Map((old.data ?? []).map((r) => [r.repo_id, r]));
  const now = new Date().toISOString();
  const rows = repos.map((r) => {
    const previous = byId.get(r.id);
    const changed = !previous || (previous.status !== "running" && (previous.pushed_at !== r.pushed_at || previous.status === "removed"));
    return { owner_id: owner.id, repo_id: r.id, full_name: r.full_name, default_branch: r.default_branch || "HEAD", pushed_at: r.pushed_at,
      // Do not clobber an active worker's lease; it requeues if a push arrived.
      status: changed ? "queued" : previous!.status, next_scan_at: changed ? now : previous!.next_scan_at, error: changed ? null : previous!.error };
  });
  for (let i = 0; i < rows.length; i += 100) {
    const batch = await admin.from("github_monitoring_repositories").upsert(rows.slice(i, i + 100), { onConflict: "owner_id,repo_id" });
    if (batch.error) throw new Error("Could not queue all repositories; retry discovery");
  }
  const seen = new Set(repos.map((r) => r.id));
  const removed = (old.data ?? []).filter((r) => !seen.has(r.repo_id)).map((r) => r.id);
  if (removed.length) {
    const gone = await admin.from("github_monitoring_repositories").update({ status: "removed", lease_until: null }).in("id", removed);
    if (gone.error) throw new Error("Could not update removed repositories");
  }
  const saved = await admin.from("github_monitoring_owners").update({ last_discovery_at: now, repository_count: repos.length, error: null }).eq("id", owner.id);
  if (saved.error) throw new Error("Could not save discovery status");
  return repos.length;
}

/** One bounded job at a time; SQL leases survive restarts and concurrent workers. */
export async function runMonitoringJob(admin: SupabaseClient) {
  const claimed = await admin.rpc("claim_github_monitoring_job");
  if (claimed.error) throw new Error("Could not claim monitoring job");
  const job = claimed.data?.[0];
  if (!job) return { status: "idle" };
  const found = await admin.from("github_monitoring_owners").select("*").eq("id", job.owner_id).single();
  if (found.error) throw new Error("Monitoring owner missing");
  const owner = found.data as MonitoringOwner;
  try {
    const { token } = await createInstallationToken(appToken(), owner.installation_id);
    const quota = await githubRead<{ resources: { core: { remaining: number; reset: number } } }>("/rate_limit", token);
    // A scan fetches at most 400 blobs plus the tree. Reserve capacity up front.
    if (quota.resources.core.remaining < 450) {
      const next = new Date((quota.resources.core.reset + 30) * 1000).toISOString();
      await admin.from("github_monitoring_repositories").update({ next_scan_at: next }).eq("owner_id", owner.id).eq("status", "queued");
      await admin.from("github_monitoring_repositories").update({ status: "queued", lease_until: null, next_scan_at: next, error: "Waiting for GitHub API quota reset" }).eq("id", job.id);
      return { status: "rate_limited" };
    }
    const result = await scanRepository(token, job.full_name, job.default_branch);
    const findings: RepositoryFinding[] = result.findings.map((f) => ({ ruleId: f.ruleId, file: f.file, line: f.line, severity: f.severity, example: false, fingerprint: createHash("sha256").update(`${f.ruleId}\n${f.file}\n${f.excerpt.replace(/\s+/g, " ")}`).digest("hex").slice(0, 32) }));
    // Recompute example paths; no credential excerpts are stored in the queue.
    const { examplePath } = await import("./repository-warnings");
    for (const f of findings) f.example = examplePath(f.file);
    const classified = classifyRepositoryFindings(findings, owner);
    if (classified.critical.length) {
      const ids = [...new Set(classified.critical.map((f) => `${f.ruleId}:${f.file}:${f.fingerprint}`))].sort();
      const key = createHash("sha256").update(`${owner.org_id}\n${job.full_name}\n${ids.join("\n")}`).digest("hex");
      const report = parseIncidentReport({ source: "manual", severity: "critical", title: `Critical repository findings: ${job.full_name}`, dedupe_key: `repo-monitor:${key}`, summary: `${classified.critical.length} critical findings in https://github.com/${job.full_name}. Warning silences do not apply to critical findings.`, findings: classified.critical.slice(0, 200).map((f) => ({ id: f.fingerprint, module: "repository-scan", severity: "critical", title: f.ruleId, detail: `${f.file}:${f.line}`, evidence: "inference" })) });
      const outcome = await upsertIncident(admin, owner.org_id, null, report, { userId: null, agentKeyId: null });
      if (outcome.page) await notifyIncident(pageable(outcome.incident), admin);
    }
    // If a discovery noticed another push during this scan, scan again.
    const current = await admin.from("github_monitoring_repositories").select("pushed_at,status").eq("id", job.id).single();
    const status = current.data?.status === "removed" ? "removed" : current.data?.pushed_at !== job.pushed_at ? "queued" : "complete";
    const saved = await admin.from("github_monitoring_repositories").update({ status, lease_until: null, error: null, scanned_pushed_at: job.pushed_at, last_scanned_at: new Date().toISOString(), last_counts: classified.counts, truncated: result.truncated }).eq("id", job.id);
    if (saved.error) throw new Error("Could not save scan result");
    return { status, counts: classified.counts, truncated: result.truncated };
  } catch (e) {
    const retry = e instanceof GitHubMonitorError && (e.status === 403 || e.status === 429);
    await admin.from("github_monitoring_repositories").update({ status: retry ? "queued" : "failed", lease_until: null, next_scan_at: new Date(Date.now() + 3600000).toISOString(), error: retry ? "Waiting for GitHub access or API quota" : "Scan failed; retry from account monitoring" }).eq("id", job.id);
    return { status: retry ? "rate_limited" : "failed" };
  }
}
