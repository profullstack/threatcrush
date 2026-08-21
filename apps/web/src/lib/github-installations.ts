import { getSupabaseAdmin } from "@/lib/supabase";
import {
  createAppJwt,
  createInstallationToken,
  listInstallationRepos,
  readAppCredentials,
  type InstallationRepo,
} from "@/lib/github-app";
import { scanRepository } from "@/lib/github-repo-scan";

/**
 * Installation bookkeeping and the scans it kicks off.
 *
 * The webhook route stays a thin shell: it verifies, decides which of these to
 * call, and acknowledges. Everything that can be slow or can fail lives here,
 * behind functions that never throw into the request path.
 */

export type InstallationEventPayload = {
  action?: string;
  installation?: {
    id?: number;
    account?: { id?: number; login?: string; type?: string };
    repository_selection?: string;
    permissions?: Record<string, string>;
    events?: string[];
  };
  repositories?: Array<{ id?: number; full_name?: string; private?: boolean }>;
  repositories_added?: Array<{ id?: number; full_name?: string; private?: boolean }>;
  repositories_removed?: Array<{ id?: number; full_name?: string; private?: boolean }>;
  sender?: { login?: string };
  repository?: { id?: number; full_name?: string; default_branch?: string };
  ref?: string;
  after?: string;
};

/**
 * `deleted` and `suspend` are not the same as never having installed. The row
 * is kept and marked, so a reinstall keeps its scan history and an uninstall is
 * legible in the admin panel rather than being an absence.
 */
const STATUS_BY_ACTION: Record<string, string> = {
  created: "active",
  new_permissions_accepted: "active",
  unsuspend: "active",
  suspend: "suspended",
  deleted: "deleted",
};

export function statusForAction(action: string | undefined): string {
  return STATUS_BY_ACTION[action ?? ""] ?? "active";
}

export async function upsertInstallation(payload: InstallationEventPayload): Promise<number | null> {
  const installation = payload.installation;
  const installationId = installation?.id;
  if (typeof installationId !== "number") return null;

  const status = statusForAction(payload.action);
  const now = new Date().toISOString();

  const row: Record<string, unknown> = {
    installation_id: installationId,
    account_id: installation?.account?.id ?? null,
    account_login: installation?.account?.login ?? null,
    account_type: installation?.account?.type ?? null,
    repository_selection: installation?.repository_selection ?? null,
    permissions: installation?.permissions ?? {},
    events: installation?.events ?? [],
    sender_login: payload.sender?.login ?? null,
    status,
    updated_at: now,
  };

  // Only stamp the lifecycle columns on the transition that caused them, so a
  // later `new_permissions_accepted` does not clear a suspension timestamp that
  // is still historically true.
  if (status === "suspended") row.suspended_at = now;
  if (status === "deleted") row.deleted_at = now;
  if (payload.action === "unsuspend") row.suspended_at = null;

  const admin = getSupabaseAdmin();
  const { error } = await admin
    .from("github_installations")
    .upsert(row, { onConflict: "installation_id" });

  if (error) {
    console.error("[gh install] could not upsert installation", error.message);
    return null;
  }

  return installationId;
}

export async function recordRepositories(
  installationId: number,
  repos: Array<{ id?: number; full_name?: string; private?: boolean; default_branch?: string }>
): Promise<void> {
  const rows = repos
    .filter((repo) => typeof repo.id === "number" && repo.full_name)
    .map((repo) => ({
      installation_id: installationId,
      repo_id: repo.id as number,
      full_name: repo.full_name as string,
      private: Boolean(repo.private),
      default_branch: repo.default_branch ?? null,
      removed_at: null,
      updated_at: new Date().toISOString(),
    }));

  if (!rows.length) return;

  const admin = getSupabaseAdmin();
  const { error } = await admin
    .from("github_installation_repositories")
    .upsert(rows, { onConflict: "installation_id,repo_id" });

  if (error) console.error("[gh install] could not record repositories", error.message);
}

export async function markRepositoriesRemoved(
  installationId: number,
  repos: Array<{ id?: number }>
): Promise<void> {
  const ids = repos.map((repo) => repo.id).filter((id): id is number => typeof id === "number");
  if (!ids.length) return;

  const admin = getSupabaseAdmin();
  const { error } = await admin
    .from("github_installation_repositories")
    .update({ removed_at: new Date().toISOString(), updated_at: new Date().toISOString() })
    .eq("installation_id", installationId)
    .in("repo_id", ids);

  if (error) console.error("[gh install] could not mark repositories removed", error.message);
}

/**
 * How many repositories one installation event will scan.
 *
 * An org can install the app on hundreds of repositories at once. Scanning all
 * of them inline would run for an hour; scanning none would make the install a
 * no-op. This is the compromise, and the admin panel shows what was skipped.
 */
export const MAX_REPOS_PER_EVENT = 10;

export type ScanOutcome = { fullName: string; status: string; findings: number; error?: string };

/**
 * Scan a set of repositories and persist a row per scan.
 *
 * Never throws. A failure to scan one repository is recorded on that
 * repository's row and the rest continue — one unreadable repo must not cost
 * the installer every other result.
 */
export async function scanRepositories(
  installationId: number,
  repos: Array<{ id?: number; fullName: string; defaultBranch: string }>,
  trigger: string,
  commitSha: string | null = null
): Promise<ScanOutcome[]> {
  const credentials = readAppCredentials();
  if (!credentials) {
    console.warn("[gh scan] GITHUB_APP_ID / GITHUB_APP_PRIVATE_KEY not set; skipping scan");
    return [];
  }

  const admin = getSupabaseAdmin();
  const outcomes: ScanOutcome[] = [];

  let token: string;
  try {
    const jwt = createAppJwt(
      credentials.appId,
      credentials.privateKey,
      Math.floor(Date.now() / 1000)
    );
    const minted = await createInstallationToken(jwt, installationId);
    token = minted.token;
  } catch (err) {
    console.error("[gh scan] could not authenticate installation", (err as Error).message);
    return [];
  }

  for (const repo of repos.slice(0, MAX_REPOS_PER_EVENT)) {
    // The row goes in before the scan runs, so a scan that dies mid-flight is
    // visible as a stuck 'running' rather than leaving no trace at all.
    const { data: inserted, error: insertError } = await admin
      .from("github_repo_scans")
      .insert({
        installation_id: installationId,
        repo_id: repo.id ?? null,
        full_name: repo.fullName,
        ref: repo.defaultBranch,
        commit_sha: commitSha,
        trigger,
        status: "running",
      })
      .select("id")
      .single();

    if (insertError || !inserted) {
      console.error("[gh scan] could not open scan row", insertError?.message);
      continue;
    }

    try {
      const result = await scanRepository(token, repo.fullName, repo.defaultBranch);
      await admin
        .from("github_repo_scans")
        .update({
          status: "complete",
          files_considered: result.filesConsidered,
          files_scanned: result.filesScanned,
          findings_count: result.findings.length,
          peak_severity: result.peak,
          truncated: result.truncated,
          truncation_reason: result.truncationReason,
          findings: result.findings,
          finished_at: new Date().toISOString(),
        })
        .eq("id", inserted.id);

      outcomes.push({
        fullName: repo.fullName,
        status: "complete",
        findings: result.findings.length,
      });
    } catch (err) {
      const message = (err as Error).message.slice(0, 500);
      await admin
        .from("github_repo_scans")
        .update({ status: "failed", error: message, finished_at: new Date().toISOString() })
        .eq("id", inserted.id);

      outcomes.push({ fullName: repo.fullName, status: "failed", findings: 0, error: message });
    }
  }

  return outcomes;
}

/**
 * Everything an installation can see, straight from GitHub.
 *
 * The `installation` webhook payload includes a `repositories` array only when
 * the selection is small; for `repository_selection: "all"` it is absent
 * entirely, so the list has to be fetched.
 */
export async function fetchInstallationRepos(installationId: number): Promise<InstallationRepo[]> {
  const credentials = readAppCredentials();
  if (!credentials) return [];

  try {
    const jwt = createAppJwt(
      credentials.appId,
      credentials.privateKey,
      Math.floor(Date.now() / 1000)
    );
    const { token } = await createInstallationToken(jwt, installationId);
    return await listInstallationRepos(token);
  } catch (err) {
    console.error("[gh install] could not list repositories", (err as Error).message);
    return [];
  }
}
