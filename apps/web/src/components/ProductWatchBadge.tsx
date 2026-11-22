"use client";

import { useEffect, useState } from "react";

// "Featured on ProductWatch" badge. The href is ProductWatch's embed link,
// unchanged, so it works server-rendered and without JS. Once mounted we add
// the page the visitor clicked from (window.location) as `ref`, and the
// referrer policy below also sends that full URL as the Referer, so
// ProductWatch can attribute the visit to the exact threatcrush.com page.
// rel is "noopener" and not "noreferrer", which would strip the Referer.
const HREF = "https://productwatch.io/products/threatcrush?utm_source=badge";
// darkMode=true: the site is always dark (<html class="dark">).
const SRC =
  "https://productwatch.io/backend/api/v1/badge/featured?productId=bf971aab-3de6-466a-8ba2-1e299a3cf206&darkMode=true";

export default function ProductWatchBadge() {
  const [href, setHref] = useState(HREF);

  useEffect(() => {
    const url = new URL(HREF);
    url.searchParams.set("ref", window.location.href);
    setHref(url.toString());
  }, []);

  return (
    <a
      href={href}
      target="_blank"
      rel="noopener"
      referrerPolicy="no-referrer-when-downgrade"
      title="ThreatCrush on ProductWatch"
      className="inline-block leading-[0] rounded-md opacity-90 transition hover:opacity-100 focus-visible:opacity-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-tc-border"
    >
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src={SRC}
        alt="ThreatCrush"
        width={260}
        height={54}
        loading="lazy"
        decoding="async"
        className="block h-auto w-full max-w-[250px]"
      />
    </a>
  );
}
