import type { Metadata } from "next";
import Home from "./home-page";

// The home page itself is a client component (home-page.tsx), so this server
// wrapper is what can carry route metadata.
//
// ad.network verifies the site by fetching this page's raw HTML for the claim
// code. The home page itself carries no ad unit (blog pages do).
export const metadata: Metadata = {
  other: { "ad.network": "qEyffBVzfV8gZ4U4" },
};

export default function Page() {
  return (
    <Home />
  );
}
