import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { getPostBySlug, sanitizeHtml, formatDate, SITE_URL } from "@/lib/blog";

type RouteParams = { params: Promise<{ slug: string }> };

export const revalidate = 60;

export async function generateMetadata({ params }: RouteParams): Promise<Metadata> {
  const { slug } = await params;
  const post = await getPostBySlug(slug);
  if (!post) {
    return { title: "Not found — ThreatCrush" };
  }
  const url = `${SITE_URL}/blog/${post.slug}`;
  const images = post.image_url ? [post.image_url] : ["/banner.png"];
  return {
    title: `${post.title} — ThreatCrush`,
    description: post.meta_description || undefined,
    alternates: { canonical: url },
    openGraph: {
      title: post.title,
      description: post.meta_description || undefined,
      url,
      type: "article",
      publishedTime: post.published_at,
      images,
      tags: post.tags,
    },
    twitter: {
      card: "summary_large_image",
      title: post.title,
      description: post.meta_description || undefined,
      images,
    },
  };
}

export default async function BlogPostPage({ params }: RouteParams) {
  const { slug } = await params;
  const post = await getPostBySlug(slug);
  if (!post) notFound();

  const html = post.content_html ? sanitizeHtml(post.content_html) : null;

  const ldJson = {
    "@context": "https://schema.org",
    "@type": "BlogPosting",
    headline: post.title,
    description: post.meta_description || undefined,
    image: post.image_url || undefined,
    datePublished: post.published_at,
    dateModified: post.updated_at,
    mainEntityOfPage: `${SITE_URL}/blog/${post.slug}`,
    author: { "@type": "Organization", name: "ThreatCrush" },
    publisher: {
      "@type": "Organization",
      name: "ThreatCrush",
      logo: { "@type": "ImageObject", url: `${SITE_URL}/banner.png` },
    },
    keywords: post.tags.join(", "),
  };

  return (
    <div className="min-h-screen bg-tc-darker pt-24 pb-16">
      <article className="mx-auto max-w-3xl px-4 sm:px-6">
        <nav className="mb-6 text-sm">
          <Link href="/blog" className="text-tc-text-dim hover:text-tc-green">
            ← All posts
          </Link>
        </nav>

        <header className="mb-8">
          <h1 className="text-3xl font-bold text-white sm:text-4xl">{post.title}</h1>
          <div className="mt-4 flex flex-wrap items-center gap-3 text-sm text-tc-text-dim">
            <time dateTime={post.published_at}>{formatDate(post.published_at)}</time>
            {post.tags.length > 0 && (
              <>
                <span aria-hidden>·</span>
                <div className="flex flex-wrap gap-1.5">
                  {post.tags.map((tag) => (
                    <span
                      key={tag}
                      className="rounded bg-tc-green/10 px-2 py-0.5 text-xs text-tc-green"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </>
            )}
          </div>
          {post.image_url && (
            <div className="mt-6">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={post.image_url}
                alt={post.title}
                className="w-full rounded-lg border border-tc-border/50"
              />
            </div>
          )}
        </header>

        {html ? (
          <div
            className="blog-content"
            dangerouslySetInnerHTML={{ __html: html }}
          />
        ) : post.content_markdown ? (
          <pre className="whitespace-pre-wrap text-tc-text-dim">{post.content_markdown}</pre>
        ) : (
          <p className="text-tc-text-dim">No content.</p>
        )}

        <hr className="my-12 border-tc-border/50" />

        <div className="rounded-lg border border-tc-green/30 bg-tc-green/5 p-6">
          <h3 className="text-lg font-semibold text-white">Try ThreatCrush</h3>
          <p className="mt-2 text-sm text-tc-text-dim">
            Real-time threat intelligence, CTEM, and exposure management — built for security teams that move fast.
          </p>
          <Link
            href="/auth/signup"
            className="mt-4 inline-block rounded-lg bg-tc-green px-4 py-2 text-sm font-bold text-black hover:bg-tc-green-dim"
          >
            Get started →
          </Link>
        </div>
      </article>

      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(ldJson) }}
      />
    </div>
  );
}
