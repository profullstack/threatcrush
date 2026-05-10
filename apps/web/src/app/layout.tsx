import type { Metadata } from "next";
import Script from "next/script";
import "./globals.css";
import SiteHeader from "@/components/SiteHeader";
import SiteFooter from "@/components/SiteFooter";
import { AuthProvider } from "@/lib/auth-context";

const SITE_URL =
  process.env.NEXT_PUBLIC_APP_URL?.replace(/\/$/, "") ||
  "https://threatcrush.com";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: "ThreatCrush — Real-Time Threat Intelligence Platform",
  description:
    "Crush every threat before it crushes you. Real-time threat feeds, vulnerability tracking, attack surface monitoring, and threat actor intelligence.",
  keywords: [
    "CTEM",
    "continuous threat exposure management",
    "exposure management",
    "vulnerability management",
    "threat intelligence",
    "cybersecurity",
    "attack surface monitoring",
    "threat feeds",
  ],
  alternates: { canonical: "/" },
  manifest: "/manifest.json",
  icons: {
    icon: [
      { url: "/favicon.svg", type: "image/svg+xml" },
      { url: "/icons/favicon-32.png", sizes: "32x32", type: "image/png" },
      { url: "/icons/favicon-16.png", sizes: "16x16", type: "image/png" },
    ],
    shortcut: "/favicon.ico",
    apple: [
      { url: "/icons/apple-touch-icon-180x180.png", sizes: "180x180" },
      { url: "/icons/apple-touch-icon-152x152.png", sizes: "152x152" },
      { url: "/icons/apple-touch-icon-144x144.png", sizes: "144x144" },
      { url: "/icons/apple-touch-icon-120x120.png", sizes: "120x120" },
      { url: "/icons/apple-touch-icon-114x114.png", sizes: "114x114" },
      { url: "/icons/apple-touch-icon-76x76.png", sizes: "76x76" },
      { url: "/icons/apple-touch-icon-72x72.png", sizes: "72x72" },
      { url: "/icons/apple-touch-icon-60x60.png", sizes: "60x60" },
      { url: "/icons/apple-touch-icon-57x57.png", sizes: "57x57" },
    ],
  },
  appleWebApp: {
    capable: true,
    title: "ThreatCrush",
    statusBarStyle: "black-translucent",
  },
  other: {
    "mobile-web-app-capable": "yes",
    "msapplication-TileColor": "#0a0a0a",
    "msapplication-config": "/browserconfig.xml",
    "msapplication-TileImage": "/icons/apple-touch-icon-144x144.png",
  },
  openGraph: {
    siteName: "ThreatCrush",
    title: "ThreatCrush — Real-Time Threat Intelligence Platform",
    description:
      "Crush every threat before it crushes you. Lifetime access to real-time threat intelligence.",
    url: SITE_URL,
    type: "website",
    images: ["/banner.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: "ThreatCrush — Real-Time Threat Intelligence Platform",
    description:
      "Crush every threat before it crushes you. Lifetime access to real-time threat intelligence.",
    images: ["/banner.png"],
  },
};

export const viewport = {
  themeColor: "#0a0a0a",
};

const organizationJsonLd = {
  "@context": "https://schema.org",
  "@type": "Organization",
  name: "ThreatCrush",
  alternateName: "Profullstack ThreatCrush",
  url: SITE_URL,
  logo: `${SITE_URL}/logo.svg`,
  description:
    "All-in-one security agent — monitor, detect, scan, and protect servers in real time. Continuous Threat Exposure Management (CTEM) platform with CLI, daemon, desktop app, and hosted dashboard.",
  email: "hello@threatcrush.com",
  foundingDate: "2025",
  sameAs: [
    "https://github.com/profullstack/threatcrush",
    "https://www.npmjs.com/package/@profullstack/threatcrush",
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap"
          rel="stylesheet"
        />
        <link rel="alternate" type="application/rss+xml" title="ThreatCrush Blog" href="/blog/rss.xml" />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(organizationJsonLd) }}
        />
      </head>
      <body className="antialiased">
        <AuthProvider>
          <SiteHeader />
          {children}
          <SiteFooter />
        </AuthProvider>
        <Script
          id="robauto-pixel"
          src="https://robauto.ai/pixel.js"
          data-site="dc9ed120-6cdb-4ded-8202-089d1f270e5e"
          strategy="afterInteractive"
        />
        <Script id="robauto-track" strategy="afterInteractive">
          {`(function(){var pid="dc9ed120-6cdb-4ded-8202-089d1f270e5e";var ep="https://hkeytqaukllckucnhzey.supabase.co/functions/v1/track";var d=JSON.stringify({path:location.pathname,url:location.href,referer:document.referrer});if(navigator.sendBeacon){navigator.sendBeacon(ep+"?pid="+pid,d)}else{var x=new XMLHttpRequest();x.open("POST",ep+"?pid="+pid);x.setRequestHeader("Content-Type","application/json");x.send(d)}})();`}
        </Script>
        <Script
          id="datafast"
          src="https://datafa.st/js/script.js"
          data-website-id="dfid_IxljOSv8TFXS4OlSBNIRK"
          data-domain="threatcrush.com"
          strategy="afterInteractive"
        />
      </body>
    </html>
  );
}
