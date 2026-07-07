import Script from "next/script";

// Scope the CrawlProof ad loader to /blog/* only. It scans for [data-cp-ad]
// slots (rendered by <AdUnit />) on the blog list and post pages and fills
// them in place. Kept out of the root layout so ads never run site-wide.
export default function BlogLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      {children}
      <Script src="https://crawlproof.com/ad.js" strategy="afterInteractive" />
    </>
  );
}
