import type { Metadata } from "next";
import Script from "next/script";
import Home from "./home-page";

// The home page itself is a client component (home-page.tsx), so this server
// wrapper is what can carry route metadata.
//
// ad.network verifies the site by fetching this page's raw HTML for the claim
// code; the unit is client-rendered, the meta tag is not.
export const metadata: Metadata = {
  other: { "ad.network": "qEyffBVzfV8gZ4U4" },
};

export default function Page() {
  return (
    <>
      <Home />
      {/* Fills the ad.network unit (<AdNetworkUnit />) on the home page. */}
      <Script src="https://crawlproof.com/ad.js" strategy="afterInteractive" />
    </>
  );
}
