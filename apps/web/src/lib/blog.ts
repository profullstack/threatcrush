import "server-only";
import { sanitizeBlogHtml } from "./sanitize-blog-html";
import { getSupabaseAdmin } from "./supabase";

export type BlogPost = {
  id: string;
  source: string;
  source_id: string | null;
  slug: string;
  title: string;
  content_markdown: string | null;
  content_html: string | null;
  meta_description: string | null;
  image_url: string | null;
  tags: string[];
  source_created_at: string | null;
  published_at: string;
  created_at: string;
  updated_at: string;
};

export type BlogListItem = Pick<
  BlogPost,
  "id" | "slug" | "title" | "meta_description" | "image_url" | "tags" | "published_at"
>;

export const SITE_URL =
  process.env.NEXT_PUBLIC_APP_URL?.replace(/\/$/, "") || "https://threatcrush.com";

function tryGetAdmin() {
  try {
    return getSupabaseAdmin();
  } catch (err) {
    // Supabase env vars may be absent during `next build` (e.g. Railway build
    // image). Returning null lets prerender succeed with empty data; the route
    // will fetch real data on first request once runtime env is loaded.
    console.warn("[blog] supabase unavailable:", (err as Error).message);
    return null;
  }
}

export async function listPosts(limit = 50): Promise<BlogListItem[]> {
  const supabase = tryGetAdmin();
  if (!supabase) return [];
  const { data, error } = await supabase
    .from("blog_posts")
    .select("id, slug, title, meta_description, image_url, tags, published_at")
    .order("published_at", { ascending: false })
    .limit(limit);
  if (error) {
    console.error("[blog] list error:", error);
    return [];
  }
  return (data ?? []) as BlogListItem[];
}

export async function getPostBySlug(slug: string): Promise<BlogPost | null> {
  const supabase = tryGetAdmin();
  if (!supabase) return null;
  const { data, error } = await supabase
    .from("blog_posts")
    .select("*")
    .eq("slug", slug)
    .maybeSingle();
  if (error) {
    console.error("[blog] get error:", error);
    return null;
  }
  return (data as BlogPost) ?? null;
}

let slugCache: { at: number; slugs: Set<string> } | null = null;
const SLUG_TTL_MS = 10 * 60_000;

/** Every published slug, held ten minutes: what a /blog/ link may point at. */
export async function allSlugs(): Promise<Set<string>> {
  if (slugCache && Date.now() - slugCache.at < SLUG_TTL_MS) return slugCache.slugs;
  const supabase = tryGetAdmin();
  if (!supabase) return new Set();
  const { data, error } = await supabase.from("blog_posts").select("slug");
  if (error) {
    console.error("[blog] slug list error:", error);
    return slugCache?.slugs ?? new Set();
  }
  slugCache = { at: Date.now(), slugs: new Set((data ?? []).map((r: { slug: string }) => r.slug)) };
  return slugCache.slugs;
}

/** Levenshtein distance, stopping early once it exceeds `max`. */
export function editDistance(a: string, b: string, max = Infinity): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      best = Math.min(best, cur[j]);
    }
    if (best > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

/**
 * The real slug a mistyped one meant: the closest by edit distance within a
 * quarter of its length (at least 3), or null. Autoblog posts link to slugs
 * that were never published ("automation-in-cy-security" for
 * "automation-in-cyber-security"); this finds the one they meant.
 */
export function closestSlug(slug: string, slugs: Set<string>): string | null {
  if (slugs.has(slug)) return slug;
  const max = Math.max(3, Math.floor(slug.length / 4));
  let best: string | null = null;
  let bestD = max + 1;
  for (const s of slugs) {
    const d = editDistance(slug, s, bestD - 1);
    if (d < bestD) {
      best = s;
      bestD = d;
    }
  }
  return best;
}

const BLOG_HREF = /href="((?:https?:\/\/(?:www\.)?threatcrush\.com)?\/blog\/)([a-z0-9-]+)\/?((?:[?#][^"]*)?)"/g;

/**
 * Point every /blog/<slug> link in a post at a post that exists: the slug it
 * meant when one is close, else the blog index. Never leaves a link that 404s.
 */
export function fixBlogLinks(html: string, slugs: Set<string>): string {
  if (slugs.size === 0) return html;
  return html.replace(BLOG_HREF, (whole, prefix: string, slug: string, rest: string) => {
    if (slugs.has(slug)) return whole;
    const meant = closestSlug(slug, slugs);
    return meant ? `href="${prefix}${meant}${rest}"` : `href="${prefix.replace(/\/blog\/$/, "/blog")}"`;
  });
}

export function sanitizeHtml(html: string): string {
  return sanitizeBlogHtml(html);
}

// Autoblog posts carry their own CrawlProof ad embeds (banner units). The page
// renders exactly one low-profile <AdUnit />, so in-body units are dropped.
export function stripAdUnits(html: string): string {
  return html.replace(/<(div|aside|ins)\b[^>]*\bdata-cp-ad\b[^>]*>[\s\S]*?<\/\1>/gi, "");
}

export function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
}
