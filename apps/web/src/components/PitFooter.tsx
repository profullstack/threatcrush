/**
 * The pit.world network footer, fetched on the server and rendered as the last
 * thing in <body>. Cached for an hour; any failure (timeout, non-200, odd body)
 * renders nothing so the page never breaks.
 */
const PIT_FOOTER_URL = "https://pit.world/snippets/footer.html?site=threatcrush.com";

export default async function PitFooter() {
  try {
    const res = await fetch(PIT_FOOTER_URL, {
      next: { revalidate: 3600 },
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) return null;
    const html = await res.text();
    if (!html.includes("data-pit-footer")) return null;
    return <div dangerouslySetInnerHTML={{ __html: html }} />;
  } catch {
    return null;
  }
}
