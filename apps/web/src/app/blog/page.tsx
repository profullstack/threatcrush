import type { Metadata } from "next";
import Link from "next/link";
import { listPosts, formatDate, SITE_URL } from "@/lib/blog";

export const metadata: Metadata = {
  title: "Blog — ThreatCrush",
  description:
    "Threat intelligence, CTEM, and security operations — articles, deep dives, and announcements from the ThreatCrush team.",
  alternates: { canonical: `${SITE_URL}/blog` },
  openGraph: {
    title: "Blog — ThreatCrush",
    description:
      "Threat intelligence, CTEM, and security operations from the ThreatCrush team.",
    url: `${SITE_URL}/blog`,
    type: "website",
    images: ["/banner.png"],
  },
};

export const revalidate = 60;

export default async function BlogIndexPage() {
  const posts = await listPosts(100);

  return (
    <div className="min-h-screen bg-tc-darker pt-24 pb-16">
      <div className="mx-auto max-w-5xl px-4 sm:px-6">
        <header className="mb-12 border-b border-tc-border/50 pb-8">
          <h1 className="text-4xl font-bold text-white sm:text-5xl">Blog</h1>
          <p className="mt-3 text-tc-text-dim">
            Threat intelligence, CTEM, and security ops — straight from the ThreatCrush team.
          </p>
          <div className="mt-4 text-xs text-tc-text-dim">
            <a href="/blog/rss.xml" className="hover:text-tc-green">RSS feed →</a>
          </div>
        </header>

        {posts.length === 0 ? (
          <div className="rounded-lg border border-tc-border/50 bg-tc-dark p-8 text-center text-tc-text-dim">
            No posts yet. Check back soon.
          </div>
        ) : (
          <ul className="space-y-8">
            {posts.map((post) => (
              <li
                key={post.id}
                className="group rounded-lg border border-tc-border/50 bg-tc-dark p-6 transition-colors hover:border-tc-green/50"
              >
                <Link href={`/blog/${post.slug}`} className="block">
                  <div className="flex flex-col gap-4 sm:flex-row">
                    {post.image_url && (
                      <div className="sm:w-48 sm:flex-shrink-0">
                        {/* eslint-disable-next-line @next/next/no-img-element */}
                        <img
                          src={post.image_url}
                          alt=""
                          className="h-32 w-full rounded object-cover sm:h-32"
                          loading="lazy"
                        />
                      </div>
                    )}
                    <div className="min-w-0 flex-1">
                      <h2 className="text-xl font-semibold text-white transition-colors group-hover:text-tc-green sm:text-2xl">
                        {post.title}
                      </h2>
                      {post.meta_description && (
                        <p className="mt-2 text-sm text-tc-text-dim line-clamp-3">
                          {post.meta_description}
                        </p>
                      )}
                      <div className="mt-3 flex flex-wrap items-center gap-3 text-xs text-tc-text-dim">
                        <time dateTime={post.published_at}>{formatDate(post.published_at)}</time>
                        {post.tags.length > 0 && (
                          <>
                            <span aria-hidden>·</span>
                            <div className="flex flex-wrap gap-1.5">
                              {post.tags.slice(0, 4).map((tag) => (
                                <span
                                  key={tag}
                                  className="rounded bg-tc-green/10 px-2 py-0.5 text-tc-green"
                                >
                                  {tag}
                                </span>
                              ))}
                            </div>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
