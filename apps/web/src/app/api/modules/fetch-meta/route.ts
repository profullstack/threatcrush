import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";
import { getSupabaseAdmin } from "@/lib/supabase";

/**
 * POST /api/modules/fetch-meta
 *
 * Fetches metadata from a web URL and/or GitHub repo URL.
 * Merges both sources: GitHub data preferred, web data fills gaps.
 */
export async function POST(request: NextRequest) {
  let body: { url?: string; git_url?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const { url, git_url } = body;

  if (!url && !git_url) {
    return NextResponse.json(
      { error: "url or git_url is required" },
      { status: 400 }
    );
  }

  try {
    let webMeta: WebMeta | null = null;
    let ghMeta: GitHubMeta | null = null;

    // Fetch web metadata
    if (url) {
      webMeta = await fetchWebMeta(url);
    }

    // Fetch GitHub metadata
    if (git_url) {
      ghMeta = await fetchGitHubMeta(git_url);
    }

    // Merge: GitHub preferred, web fills gaps
    const merged = {
      name: ghMeta?.name || webMeta?.title || "",
      display_name: ghMeta?.display_name || webMeta?.title || "",
      description: ghMeta?.description || webMeta?.description || "",
      long_description: ghMeta?.long_description || "",
      logo_url: ghMeta?.logo_url || webMeta?.logo_url || "",
      banner_url: webMeta?.banner_url || "",
      screenshot_url: webMeta?.screenshot_url || "",
      tags: [
        ...new Set([...(ghMeta?.tags || []), ...(webMeta?.tags || [])]),
      ].slice(0, 10),
      version: ghMeta?.version || "0.1.0",
      license: ghMeta?.license || "MIT",
      homepage_url: ghMeta?.homepage_url || url || "",
      git_url: git_url || "",
      author_name: ghMeta?.author_name || "",
      stars: ghMeta?.stars || 0,
    };

    return NextResponse.json(merged);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Failed to fetch metadata";
    return NextResponse.json({ error: msg }, { status: 502 });
  }
}

// ─── Types ───

interface WebMeta {
  title: string;
  description: string;
  logo_url: string;
  banner_url: string;
  screenshot_url: string;
  tags: string[];
}

interface GitHubMeta {
  name: string;
  display_name: string;
  description: string;
  long_description: string;
  logo_url: string;
  homepage_url: string;
  tags: string[];
  version: string;
  license: string;
  author_name: string;
  stars: number;
}

// ─── Web Metadata Fetcher ───

async function fetchWebMeta(url: string): Promise<WebMeta> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    return { title: "", description: "", logo_url: "", banner_url: "", screenshot_url: "", tags: [] };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const res = await fetch(url, {
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; threatcrush-bot/1.0; +https://threatcrush.com)",
        Accept: "text/html,application/xhtml+xml",
      },
      signal: controller.signal,
      redirect: "follow",
    });
    clearTimeout(timeout);

    if (!res.ok) return { title: "", description: "", logo_url: "", banner_url: "", screenshot_url: "", tags: [] };

    const html = (await res.text()).substring(0, 200000);

    const title =
      extractMeta(html, 'property="og:title"') ||
      extractMeta(html, 'name="title"') ||
      extractTitle(html) || "";

    const description =
      extractMeta(html, 'property="og:description"') ||
      extractMeta(html, 'name="description"') || "";

    const ogImage = extractMeta(html, 'property="og:image"') || "";
    const twitterImage = extractMeta(html, 'name="twitter:image"') || "";
    const keywords = extractMeta(html, 'name="keywords"') || "";

    // Logo detection
    let logo_url = "";
    const logoCandidates = [
      `${parsedUrl.origin}/logo.svg`,
      `${parsedUrl.origin}/logo.png`,
      `${parsedUrl.origin}/favicon.svg`,
      `${parsedUrl.origin}/favicon.png`,
    ];

    for (const candidate of logoCandidates) {
      try {
        const logoRes = await fetch(candidate, {
          method: "HEAD",
          signal: AbortSignal.timeout(3000),
          redirect: "follow",
        });
        if (logoRes.ok) {
          logo_url = candidate;
          break;
        }
      } catch { /* try next */ }
    }

    if (!logo_url) {
      const faviconHref = extractFavicon(html);
      if (faviconHref) {
        try { logo_url = new URL(faviconHref, url).href; } catch { logo_url = faviconHref; }
      }
    }
    if (!logo_url && ogImage) {
      try { logo_url = new URL(ogImage, url).href; } catch { logo_url = ogImage; }
    }
    if (!logo_url) {
      logo_url = `${parsedUrl.origin}/favicon.ico`;
    }

    // Banner
    let banner_url = "";
    if (ogImage) {
      try { banner_url = new URL(ogImage, url).href; } catch { banner_url = ogImage; }
    }
    if (!banner_url && twitterImage) {
      try { banner_url = new URL(twitterImage, url).href; } catch { banner_url = twitterImage; }
    }

    // Screenshot via Microlink
    let screenshot_url = "";
    try {
      screenshot_url = await captureScreenshot(url);
    } catch { /* optional */ }

    // Tags from keywords
    const tags: string[] = keywords
      ? keywords.split(",").map((t: string) => t.trim().toLowerCase()).filter(Boolean).slice(0, 10)
      : [];

    // If we have AI available and description is weak, try to enhance
    if ((!description || description.length < 50) && process.env.OPENAI_API_KEY) {
      // AI description generation is optional — skip if no key
    }

    return { title, description, logo_url, banner_url, screenshot_url, tags };
  } catch {
    return { title: "", description: "", logo_url: "", banner_url: "", screenshot_url: "", tags: [] };
  } finally {
    clearTimeout(timeout);
  }
}

// ─── GitHub Metadata Fetcher ───

function parseGitHubUrl(gitUrl: string): { owner: string; repo: string } | null {
  // Handle: https://github.com/owner/repo, https://github.com/owner/repo.git, github.com/owner/repo
  const match = gitUrl.match(/github\.com\/([^/]+)\/([^/.]+)/);
  if (match) return { owner: match[1], repo: match[2] };
  return null;
}

async function fetchGitHubMeta(gitUrl: string): Promise<GitHubMeta | null> {
  const parsed = parseGitHubUrl(gitUrl);
  if (!parsed) return null;

  const { owner, repo } = parsed;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
    "User-Agent": "threatcrush-bot/1.0",
  };

  try {
    // Fetch repo info
    const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers,
      signal: AbortSignal.timeout(10000),
    });
    if (!repoRes.ok) return null;
    const repoData = await repoRes.json();

    // Fetch README for long_description
    let long_description = "";
    try {
      const readmeRes = await fetch(
        `https://raw.githubusercontent.com/${owner}/${repo}/${repoData.default_branch || "main"}/README.md`,
        { signal: AbortSignal.timeout(10000) }
      );
      if (readmeRes.ok) {
        long_description = (await readmeRes.text()).substring(0, 50000);
      }
    } catch { /* optional */ }

    // Fetch package.json for version/keywords
    let version = "0.1.0";
    let pkgKeywords: string[] = [];
    try {
      const pkgRes = await fetch(
        `https://raw.githubusercontent.com/${owner}/${repo}/${repoData.default_branch || "main"}/package.json`,
        { signal: AbortSignal.timeout(5000) }
      );
      if (pkgRes.ok) {
        const pkg = await pkgRes.json();
        if (pkg.version) version = pkg.version;
        if (Array.isArray(pkg.keywords)) pkgKeywords = pkg.keywords;
      }
    } catch { /* optional */ }

    // Check for logo in repo root
    let logo_url = "";
    for (const logoFile of ["logo.png", "logo.svg"]) {
      try {
        const logoRes = await fetch(
          `https://raw.githubusercontent.com/${owner}/${repo}/${repoData.default_branch || "main"}/${logoFile}`,
          { method: "HEAD", signal: AbortSignal.timeout(3000) }
        );
        if (logoRes.ok) {
          logo_url = `https://raw.githubusercontent.com/${owner}/${repo}/${repoData.default_branch || "main"}/${logoFile}`;
          break;
        }
      } catch { /* try next */ }
    }

    // Fall back to owner avatar
    if (!logo_url && repoData.owner?.avatar_url) {
      logo_url = repoData.owner.avatar_url;
    }

    const tags = [
      ...(repoData.topics || []),
      ...pkgKeywords,
    ].map((t: string) => t.toLowerCase()).slice(0, 10);

    return {
      name: repoData.name || repo,
      display_name: repoData.name || repo,
      description: repoData.description || "",
      long_description,
      logo_url,
      homepage_url: repoData.homepage || "",
      tags: [...new Set(tags)],
      version,
      license: repoData.license?.spdx_id || "MIT",
      author_name: repoData.owner?.login || owner,
      stars: repoData.stargazers_count || 0,
    };
  } catch {
    return null;
  }
}

// ─── Screenshot ───

async function captureScreenshot(url: string): Promise<string> {
  const microlinkUrl = `https://api.microlink.io/?url=${encodeURIComponent(url)}&screenshot=true&meta=false&embed=screenshot.url`;

  try {
    const res = await fetch(microlinkUrl, {
      signal: AbortSignal.timeout(10000),
      redirect: "follow",
    });

    if (!res.ok) return "";

    const contentType = res.headers.get("content-type") || "";
    let imageBuffer: Buffer;

    if (contentType.startsWith("image/")) {
      imageBuffer = Buffer.from(await res.arrayBuffer());
    } else {
      const data = await res.json();
      const screenshotUrl = data?.data?.screenshot?.url || data?.screenshot?.url;
      if (!screenshotUrl) return "";

      const imgRes = await fetch(screenshotUrl, { signal: AbortSignal.timeout(10000) });
      if (!imgRes.ok) return "";
      imageBuffer = Buffer.from(await imgRes.arrayBuffer());
    }

    if (imageBuffer.length === 0) return "";

    // Upload to Supabase storage
    const urlHash = crypto.createHash("md5").update(url).digest("hex");
    const filePath = `${urlHash}/${Date.now()}.png`;

    const sb = getSupabaseAdmin();
    const { error } = await sb.storage
      .from("module-screenshots")
      .upload(filePath, imageBuffer, {
        contentType: "image/png",
        upsert: true,
      });

    if (error) return "";

    const { data: { publicUrl } } = sb.storage
      .from("module-screenshots")
      .getPublicUrl(filePath);

    return publicUrl;
  } catch {
    return "";
  }
}

// ─── HTML Helpers ───

function extractMeta(html: string, attr: string): string {
  const regex = new RegExp(
    `<meta[^>]*${attr.replace(/"/g, '["\']')}[^>]*content=["']([^"']*)["'][^>]*/?>`,
    "i"
  );
  const match = html.match(regex);
  if (match) return decodeEntities(match[1]);

  const regex2 = new RegExp(
    `<meta[^>]*content=["']([^"']*)["'][^>]*${attr.replace(/"/g, '["\']')}[^>]*/?>`,
    "i"
  );
  const match2 = html.match(regex2);
  if (match2) return decodeEntities(match2[1]);
  return "";
}

function extractTitle(html: string): string {
  const match = html.match(/<title[^>]*>([^<]*)<\/title>/i);
  return match ? decodeEntities(match[1].trim()) : "";
}

function extractFavicon(html: string): string {
  const match = html.match(
    /<link[^>]*rel=["'](?:icon|shortcut icon|apple-touch-icon)["'][^>]*href=["']([^"']*)["'][^>]*\/?>/i
  );
  if (match) return match[1];
  const match2 = html.match(
    /<link[^>]*href=["']([^"']*)["'][^>]*rel=["'](?:icon|shortcut icon|apple-touch-icon)["'][^>]*\/?>/i
  );
  return match2 ? match2[1] : "";
}

function decodeEntities(str: string): string {
  return str
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#x27;/g, "'")
    .replace(/&#x2F;/g, "/");
}
