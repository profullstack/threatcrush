// CrawlProof ad slot for threatcrush.com. The loader (crawlproof.com/ad.js) is
// mounted in app/blog/layout.tsx so ads only run under /blog/*. ad.js scans for
// [data-cp-ad] elements and fills each in place with a sandboxed iframe.
// Low profile: one thin text_link line per page (it carries its own
// "Sponsored" mark), no heading, no reserved box; it stays collapsed until filled.
const AD_SLOT = "f41fc35a-82d7-4795-b68e-c4af5a2ef0b6";
const AD_FORMAT = "text_link";

export function AdUnit({ className = "" }: { className?: string }) {
  return (
    <div
      data-cp-ad=""
      data-slot={AD_SLOT}
      data-format={AD_FORMAT}
      className={`my-2 w-full ${className}`}
    />
  );
}
