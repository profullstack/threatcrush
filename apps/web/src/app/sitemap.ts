import type { MetadataRoute } from "next";
import { buildSitemapBlogEntries } from "@profullstack/autoblog/feeds";
import { listPosts, SITE_URL } from "@/lib/blog";

export const dynamic = "force-dynamic";

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const posts = await listPosts(500);

  const staticRoutes: MetadataRoute.Sitemap = [
    "",
    "/about",
    "/blog",
    "/store",
    "/docs",
    "/pricing",
    "/investors",
    "/get-whitepaper",
    "/security",
    "/privacy",
    "/terms",
  ].map((path) => ({
    url: `${SITE_URL}${path}`,
    changeFrequency: path === "/blog" ? "daily" : "weekly",
    priority: path === "" ? 1 : 0.7,
  }));

  const blogRoutes = buildSitemapBlogEntries({
    posts: posts.map((p) => ({
      slug: p.slug,
      title: p.title,
      publishedAt: p.published_at,
    })),
    baseUrl: SITE_URL,
    changeFrequency: "weekly",
  });

  return [...staticRoutes, ...blogRoutes];
}
