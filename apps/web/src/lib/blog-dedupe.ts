import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * Autoblog generators published one topic many times: a keyword came back to
 * the queue and was written again as `<slug>-2` … `<slug>-6`, then
 * `<slug>-hl4w`, with titles that differed only after the colon (15 CI/CD
 * threat detection posts, 2026-10). The receivers refuse a post that is an
 * existing topic again, so the merge (blog_redirects) stays merged.
 */

/** What a generator appends on a slug collision: -2 … -7, or four base-36 characters. */
const COLLISION_SUFFIX = /-(?:\d{1,2}|[a-z0-9]{4})$/;

const slugish = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
/** The title before its subtitle: "CI/CD Security Threat Detection" of "...: An Operating Model". */
const head = (title: string) => slugish(title.split(/[:–—|]/)[0] ?? "");

export type Existing = { slug: string; title: string; source: string; source_id: string | null };
export type Incoming = { slug: string; title: string; source: string; source_id: string | null };

/** The slug of the post `post` duplicates, or null. Pure, for tests. */
export function duplicateOf(post: Incoming, existing: ReadonlyArray<Existing>, redirects: ReadonlyMap<string, string>): string | null {
  const retired = redirects.get(post.slug);
  if (retired) return retired;
  const base = post.slug.replace(COLLISION_SUFFIX, "");
  const topic = head(post.title);
  for (const row of existing) {
    // A redelivery of the same article is an update, not a duplicate.
    if (row.source === post.source && row.source_id !== null && row.source_id === post.source_id) continue;
    if (row.slug === post.slug) continue; // the upsert's own conflict, not ours to judge
    if (row.slug === base || row.slug.replace(COLLISION_SUFFIX, "") === base) return row.slug;
    if (topic && head(row.title) === topic) return row.slug;
  }
  return null;
}

/** Reads blog_posts + blog_redirects and judges each incoming post; null where it is new. */
export async function findDuplicates(supabase: SupabaseClient, posts: Incoming[]): Promise<Array<string | null>> {
  const [{ data: rows, error }, { data: moved }] = await Promise.all([
    supabase.from("blog_posts").select("slug, title, source, source_id"),
    supabase.from("blog_redirects").select("from_slug, to_slug"),
  ]);
  // Unknown is not "duplicate": a failed read must not stop publishing.
  if (error) return posts.map(() => null);
  const redirects = new Map(((moved ?? []) as Array<{ from_slug: string; to_slug: string }>).map((r) => [r.from_slug, r.to_slug]));
  return posts.map((post) => duplicateOf(post, (rows ?? []) as Existing[], redirects));
}
