import { NextResponse } from "next/server";
import { buildRssXml } from "@profullstack/autoblog/feeds";
import { listPosts, SITE_URL } from "@/lib/blog";
import { webSubHubUrl } from "@/lib/websub";

export const dynamic = "force-dynamic";

export async function GET() {
  const posts = await listPosts(50);
  const xml = buildRssXml({
    title: "ThreatCrush Blog",
    description:
      "Threat intelligence, CTEM, and security operations from the ThreatCrush team.",
    siteUrl: SITE_URL,
    language: "en-us",
    hubUrl: webSubHubUrl(),
    posts: posts.map((p) => ({
      slug: p.slug,
      title: p.title,
      publishedAt: p.published_at,
      excerpt: p.meta_description,
      imageUrl: p.image_url,
      categories: p.tags,
    })),
  });

  return new NextResponse(xml, {
    headers: {
      "Content-Type": "application/rss+xml; charset=utf-8",
      "Cache-Control": "public, s-maxage=300, stale-while-revalidate=86400",
    },
  });
}
