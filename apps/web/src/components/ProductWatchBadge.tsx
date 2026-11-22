// "Featured on ProductWatch": ProductWatch's verifier string-matches its embed code,
// so it is injected byte-for-byte as raw HTML. Do NOT convert to JSX or edit it:
// JSX re-serializes it (&amp;, max-width:250px) and verification fails.
const PRODUCTWATCH_EMBED =
  '<a href="https://productwatch.io/products/threatcrush?utm_source=badge" target="_blank"><img src="https://productwatch.io/backend/api/v1/badge/featured?productId=bf971aab-3de6-466a-8ba2-1e299a3cf206&darkMode=true" alt="ThreatCrush" style="max-width: 250px;" /></a>';

export default function ProductWatchBadge() {
  return <div dangerouslySetInnerHTML={{ __html: PRODUCTWATCH_EMBED }} />;
}
