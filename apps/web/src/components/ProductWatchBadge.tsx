// "Featured on ProductWatch" badge: ProductWatch's embed code, verbatim.
// Do not add rel, referrerPolicy, query params or client-side rewriting —
// ProductWatch expects this exact markup.
export default function ProductWatchBadge() {
  return (
    <a href="https://productwatch.io/products/threatcrush?utm_source=badge" target="_blank">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src="https://productwatch.io/backend/api/v1/badge/featured?productId=bf971aab-3de6-466a-8ba2-1e299a3cf206&darkMode=true"
        alt="ThreatCrush"
        style={{ maxWidth: "250px" }}
      />
    </a>
  );
}
