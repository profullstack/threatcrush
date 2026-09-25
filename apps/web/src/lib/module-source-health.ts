import "server-only";
import dns from "dns/promises";
import { safeFetch } from "@/lib/ssrf-guard";
import type { SourceStatus } from "@/lib/module-marketplace";

export type ModuleSourceFields = {
  npm_package?: string | null;
  git_url?: string | null;
  tarball_url?: string | null;
  homepage_url?: string | null;
};

type SourceProbe = { kind: "npm" | "git" | "tarball" | "homepage"; url: string };

export type SourceCheckResult = {
  status: SourceStatus;
  detail: string;
  /** The listing URL that was checked, or null when the listing has none. */
  url: string | null;
};

const CHECK_TIMEOUT_MS = 8_000;
const USER_AGENT = "ThreatCrush-SourceCheck (+https://threatcrush.com)";

/**
 * The artifact `threatcrush modules install <slug>` would fetch, in the order
 * the CLI tries them (npm, then git, then tarball). A listing with none of
 * those falls back to its homepage, so a dead homepage still gets flagged.
 */
function sourceProbe(mod: ModuleSourceFields): SourceProbe | null {
  const npm = mod.npm_package?.trim();
  if (npm) return { kind: "npm", url: npm };
  const git = mod.git_url?.trim();
  if (git) return { kind: "git", url: git };
  const tarball = mod.tarball_url?.trim();
  if (tarball) return { kind: "tarball", url: tarball };
  const homepage = mod.homepage_url?.trim();
  if (homepage) return { kind: "homepage", url: homepage };
  return null;
}

/** Registry document URL for `name`, `name@range`, `@scope/name` or `@scope/name@range`. */
function npmRegistryUrl(spec: string): string {
  const name = spec.match(/^(@[^/@\s]+\/[^@\s]+|[^@\s]+)/)?.[1] ?? spec;
  return `https://registry.npmjs.org/${name.replace("/", "%2f")}`;
}

/**
 * The smart-HTTP ref advertisement `git clone` fetches first. Probing it rather
 * than the web page tells a clonable repository apart from a page that merely
 * exists (a paste, a GitHub /tree/ URL, a project website).
 */
function gitInfoRefsUrl(gitUrl: string): string {
  const https = gitUrl
    .replace(/^github:/, "https://github.com/")
    .replace(/^ssh:\/\/(?:[^@/]+@)?([^/:]+)(?::\d+)?\//, "https://$1/")
    .replace(/^[^@/:]+@([^:/]+):/, "https://$1/");
  const url = new URL(https);
  url.pathname = `${url.pathname.replace(/\/+$/, "")}/info/refs`;
  url.search = "?service=git-upload-pack";
  url.hash = "";
  return url.toString();
}

async function describeFailure(url: string, err: unknown): Promise<string> {
  // safeFetch reports an unresolvable name the same way as a private address;
  // say which one it was so the admin isn't sent chasing an SSRF block.
  try {
    await dns.lookup(new URL(url).hostname);
  } catch {
    return `hostname does not resolve (${new URL(url).hostname})`;
  }
  return err instanceof Error ? err.message : String(err);
}

async function probe(url: string, method: "GET" | "HEAD"): Promise<Response> {
  return safeFetch(url, {
    method,
    headers: { "user-agent": USER_AGENT },
    signal: AbortSignal.timeout(CHECK_TIMEOUT_MS),
  });
}

export async function checkModuleSource(mod: ModuleSourceFields): Promise<SourceCheckResult> {
  const source = sourceProbe(mod);
  if (!source) {
    return { status: "not_found", detail: "listing has no source, repository or homepage URL", url: null };
  }

  let target: string;
  try {
    target =
      source.kind === "npm"
        ? npmRegistryUrl(source.url)
        : source.kind === "git"
          ? gitInfoRefsUrl(source.url)
          : new URL(source.url).toString();
  } catch {
    return { status: "unreachable", detail: "not a valid URL", url: source.url };
  }

  let res: Response;
  try {
    // Git gets a GET: the ref advertisement is what clone needs. Everything
    // else is a HEAD first so a large tarball isn't downloaded, with a GET
    // retry for servers that refuse or mishandle HEAD.
    res = await probe(target, source.kind === "git" ? "GET" : "HEAD");
    if (source.kind !== "git" && res.status >= 400 && res.status !== 404 && res.status !== 410) {
      res = await probe(target, "GET");
    }
  } catch (err) {
    return { status: "unreachable", detail: await describeFailure(target, err), url: source.url };
  }

  const status = res.status;
  if (source.kind === "git") {
    if (status >= 200 && status < 300) {
      return (res.headers.get("content-type") ?? "").includes("text/html")
        ? { status: "not_found", detail: "URL is a web page, not a git repository", url: source.url }
        : { status: "ok", detail: "git repository", url: source.url };
    }
    // GitHub answers 401 for a repository that doesn't exist or isn't public.
    if (status === 401) {
      return { status: "not_found", detail: "git repository not found or private (HTTP 401)", url: source.url };
    }
    if (status === 404 || status === 410) {
      return { status: "not_found", detail: `no git repository at this URL (HTTP ${status})`, url: source.url };
    }
    return { status: "unreachable", detail: `HTTP ${status}`, url: source.url };
  }

  const homepageOnly = source.kind === "homepage" ? "; homepage only, no install artifact" : "";
  if (status < 400) return { status: "ok", detail: `HTTP ${status}${homepageOnly}`, url: source.url };
  if (status === 404 || status === 410) {
    return { status: "not_found", detail: `HTTP ${status}${homepageOnly}`, url: source.url };
  }
  return { status: "unreachable", detail: `HTTP ${status}${homepageOnly}`, url: source.url };
}
