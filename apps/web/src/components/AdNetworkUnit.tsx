"use client";

import { useEffect } from "react";

// The threatcrush.com listing on ad.network (a CrawlProof slot). ad.js is
// loaded by app/page.tsx; it scans for [data-cp-ad] once at load, so a unit
// mounted by client-side navigation asks it to scan again once it is there.
const AD_NETWORK_CODE = "qEyffBVzfV8gZ4U4";
const AD_SLOT = "0664e2e6-a9fa-4ff9-99e2-10883faf5bec";

declare global {
  interface Window {
    crawlproofAds?: { scan: () => void };
  }
}

export function AdNetworkUnit({ className = "" }: { className?: string }) {
  useEffect(() => {
    let tries = 0;
    const timer = setInterval(() => {
      if (window.crawlproofAds) {
        window.crawlproofAds.scan();
        clearInterval(timer);
      } else if (++tries >= 20) {
        clearInterval(timer);
      }
    }, 250);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className={`flex justify-center ${className}`}>
      <aside
        data-ad-network={AD_NETWORK_CODE}
        data-cp-ad=""
        data-slot={AD_SLOT}
        data-format="banner_300x250"
        className="w-[300px]"
      />
    </div>
  );
}
