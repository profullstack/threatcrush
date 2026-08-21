import { createSign } from "node:crypto";

/**
 * GitHub App authentication.
 *
 * A GitHub App never uses a static token. It signs a short-lived JWT with its
 * private key to prove it is the app, then trades that JWT for an *installation*
 * access token scoped to one account's selected repositories. Installation
 * tokens expire after an hour, so they are minted per job and never stored.
 *
 * Docs: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app
 *
 * Everything here is pure apart from the fetches, which take an injectable
 * `fetch` so the whole flow is testable without a network.
 */

export const GITHUB_API = "https://api.github.com";

/**
 * GitHub issues PKCS#1 keys ("BEGIN RSA PRIVATE KEY"). Env vars mangle the
 * newlines in two common ways: pasted with literal backslash-n, or pasted as
 * one line with the newlines eaten entirely. The first is repairable here; the
 * second is not, because PEM base64 has no reliable line-length guarantee once
 * the header is glued on. So repair what can be repaired and let the rest fail
 * loudly at signing time rather than silently producing bad signatures.
 */
export function normalizePrivateKey(raw: string): string {
  const unescaped = raw.includes("\\n") ? raw.replace(/\\n/g, "\n") : raw;
  return unescaped.trim().replace(/\r\n/g, "\n");
}

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

/**
 * A JWT proving we are the app. GitHub rejects anything with an `exp` more
 * than 10 minutes out, and rejects a clock that runs fast, so `iat` is backed
 * off 60s per GitHub's own recommendation and `exp` is kept well inside the
 * ceiling.
 */
export function createAppJwt(appId: string, privateKeyPem: string, nowSeconds: number): string {
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iat: nowSeconds - 60,
    exp: nowSeconds + 540,
    iss: appId,
  };

  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
  const signer = createSign("RSA-SHA256");
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign(normalizePrivateKey(privateKeyPem));

  return `${signingInput}.${base64url(signature)}`;
}

export type AppCredentials = { appId: string; privateKey: string };

/**
 * Reads the app credentials from the environment. Returns null rather than
 * throwing so callers can degrade to "not configured" instead of 500ing — the
 * webhook must still acknowledge deliveries when scanning is switched off.
 */
export function readAppCredentials(env: NodeJS.ProcessEnv = process.env): AppCredentials | null {
  const appId = env.GITHUB_APP_ID?.trim();
  const privateKey = env.GITHUB_APP_PRIVATE_KEY?.trim();
  if (!appId || !privateKey) return null;
  return { appId, privateKey };
}

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;

function headers(token: string, kind: "bearer" | "token"): Record<string, string> {
  return {
    accept: "application/vnd.github+json",
    authorization: `${kind === "bearer" ? "Bearer" : "token"} ${token}`,
    "user-agent": "threatcrush-app",
    "x-github-api-version": "2022-11-28",
  };
}

export class GitHubApiError extends Error {
  constructor(
    readonly status: number,
    readonly url: string,
    message: string
  ) {
    super(message);
    this.name = "GitHubApiError";
  }
}

/**
 * Trade the app JWT for an installation token. The response also tells us which
 * permissions were actually granted, which matters because an installation can
 * be older than the app's current permission set — GitHub does not upgrade an
 * installation until the account owner accepts the new permissions.
 */
export async function createInstallationToken(
  appJwt: string,
  installationId: number,
  fetchImpl: FetchLike = fetch
): Promise<{ token: string; expiresAt: string; permissions: Record<string, string> }> {
  const url = `${GITHUB_API}/app/installations/${installationId}/access_tokens`;
  const res = await fetchImpl(url, { method: "POST", headers: headers(appJwt, "bearer") });

  if (!res.ok) {
    throw new GitHubApiError(res.status, url, `Could not mint installation token: ${res.status}`);
  }

  const body = (await res.json()) as {
    token: string;
    expires_at: string;
    permissions?: Record<string, string>;
  };
  return { token: body.token, expiresAt: body.expires_at, permissions: body.permissions ?? {} };
}

export type InstallationRepo = {
  id: number;
  name: string;
  fullName: string;
  private: boolean;
  defaultBranch: string;
};

/**
 * Every repository this installation can see. Paginated at 100/page; the cap
 * exists so one enormous org cannot turn a webhook into an unbounded crawl.
 */
export async function listInstallationRepos(
  installationToken: string,
  fetchImpl: FetchLike = fetch,
  maxPages = 10
): Promise<InstallationRepo[]> {
  const repos: InstallationRepo[] = [];

  for (let page = 1; page <= maxPages; page++) {
    const url = `${GITHUB_API}/installation/repositories?per_page=100&page=${page}`;
    const res = await fetchImpl(url, { headers: headers(installationToken, "token") });
    if (!res.ok) {
      throw new GitHubApiError(res.status, url, `Could not list repositories: ${res.status}`);
    }

    const body = (await res.json()) as {
      repositories?: Array<{
        id: number;
        name: string;
        full_name: string;
        private: boolean;
        default_branch?: string;
      }>;
    };
    const batch = body.repositories ?? [];
    for (const repo of batch) {
      repos.push({
        id: repo.id,
        name: repo.name,
        fullName: repo.full_name,
        private: repo.private,
        defaultBranch: repo.default_branch || "main",
      });
    }
    if (batch.length < 100) break;
  }

  return repos;
}

export type TreeEntry = { path: string; sha: string; size: number };

/**
 * The full file list for a ref, in one request. `truncated` is GitHub telling
 * us the tree was too big to return whole — worth surfacing, because a silently
 * partial scan reported as complete is the failure mode that matters here.
 */
export async function listTree(
  installationToken: string,
  fullName: string,
  ref: string,
  fetchImpl: FetchLike = fetch
): Promise<{ entries: TreeEntry[]; truncated: boolean }> {
  const url = `${GITHUB_API}/repos/${fullName}/git/trees/${encodeURIComponent(ref)}?recursive=1`;
  const res = await fetchImpl(url, { headers: headers(installationToken, "token") });

  if (!res.ok) {
    throw new GitHubApiError(res.status, url, `Could not read tree for ${fullName}: ${res.status}`);
  }

  const body = (await res.json()) as {
    truncated?: boolean;
    tree?: Array<{ path?: string; type?: string; sha?: string; size?: number }>;
  };

  const entries: TreeEntry[] = [];
  for (const node of body.tree ?? []) {
    if (node.type !== "blob" || !node.path || !node.sha) continue;
    entries.push({ path: node.path, sha: node.sha, size: node.size ?? 0 });
  }

  return { entries, truncated: Boolean(body.truncated) };
}

/**
 * One blob's text. Blobs come back base64 even for text, and GitHub refuses
 * blobs over 100MB outright — the size filter upstream means we never ask.
 */
export async function fetchBlobText(
  installationToken: string,
  fullName: string,
  sha: string,
  fetchImpl: FetchLike = fetch
): Promise<string | null> {
  const url = `${GITHUB_API}/repos/${fullName}/git/blobs/${sha}`;
  const res = await fetchImpl(url, { headers: headers(installationToken, "token") });
  if (!res.ok) return null;

  const body = (await res.json()) as { content?: string; encoding?: string };
  if (!body.content) return null;
  if (body.encoding && body.encoding !== "base64") return null;

  const text = Buffer.from(body.content, "base64").toString("utf8");
  // A NUL byte means this is not source, whatever the extension claims.
  // Scanning it wastes rule time and can only produce noise.
  return text.includes("\u0000") ? null : text;
}
