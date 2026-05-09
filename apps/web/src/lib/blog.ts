import "server-only";
import DOMPurify from "isomorphic-dompurify";
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

export async function listPosts(limit = 50): Promise<BlogListItem[]> {
  const supabase = getSupabaseAdmin();
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
  const supabase = getSupabaseAdmin();
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

const SANITIZE_OPTIONS = {
  ALLOWED_TAGS: [
    "h1", "h2", "h3", "h4", "h5", "h6",
    "p", "br", "hr",
    "strong", "em", "b", "i", "u", "s", "code", "pre", "blockquote",
    "ul", "ol", "li",
    "a", "img", "figure", "figcaption",
    "table", "thead", "tbody", "tr", "th", "td",
    "span", "div",
  ],
  ALLOWED_ATTR: ["href", "src", "alt", "title", "target", "rel", "class", "id", "loading"],
  ALLOWED_URI_REGEXP: /^(?:(?:https?|mailto):|\/|#)/i,
};

export function sanitizeHtml(html: string): string {
  return DOMPurify.sanitize(html, SANITIZE_OPTIONS);
}

export function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
}
