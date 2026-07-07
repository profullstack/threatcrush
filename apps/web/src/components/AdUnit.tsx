// CrawlProof ad slot for threatcrush.com. The loader (crawlproof.com/ad.js) is
// mounted in app/blog/layout.tsx so ads only run under /blog/*. ad.js scans for
// [data-cp-ad] elements and fills each in place with a sandboxed iframe.
const AD_SLOT = "f41fc35a-82d7-4795-b68e-c4af5a2ef0b6";
const AD_FORMAT = "banner_300x250";

export function AdUnit({ className = "" }: { className?: string }) {
  return (
    <div className={`flex flex-col items-center gap-2 ${className}`}>
      <span className="text-[10px] uppercase tracking-widest text-tc-text-dim/50">
        Advertisement
      </span>
      <div
        data-cp-ad=""
        data-slot={AD_SLOT}
        data-format={AD_FORMAT}
        className="min-h-[250px] w-[300px]"
      />
    </div>
  );
}
