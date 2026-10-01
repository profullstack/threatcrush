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

export function sanitizeHtml(html: string): string {
  return sanitizeBlogHtml(html);
}

export function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
}
