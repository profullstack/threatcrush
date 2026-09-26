import type { Metadata } from "next";
import Script from "next/script";
import { FeedbackWidget } from "@profullstack/stack/feedback";
import "./globals.css";
import { serializeJsonForHtml } from "@/lib/safe-json";
import SiteHeader from "@/components/SiteHeader";
import SiteFooter from "@/components/SiteFooter";
import PwaLifecycle from "@/components/PwaLifecycle";
import { AuthProvider } from "@/lib/auth-context";

const SITE_URL =
  process.env.NEXT_PUBLIC_APP_URL?.replace(/\/$/, "") ||
  "https://threatcrush.com";

const TITLE = "ThreatCrush — Security Agent for Linux Servers";
const DESCRIPTION =
  "Open-source agent that detects attacks in your server logs and inbound connections, bans attackers at the firewall, checks hardening, scans code and spot-checks your URLs — with alerts and a cloud dashboard.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: TITLE,
  description: DESCRIPTION,
  keywords: [
    "CTEM",
    "continuous threat exposure management",
    "exposure management",
    "vulnerability management",
    "intrusion detection",
    "cybersecurity",
    "server security",
    "firewall auto-ban",
  ],
  // "./" resolves against each route's own pathname, so every page is its own
  // canonical unless it sets one; a fixed "/" would point every page at the homepage.
  alternates: { canonical: "./" },
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
    title: TITLE,
    description: DESCRIPTION,
    url: "./",
    type: "website",
    images: ["/banner.png"],
  },
  twitter: {
    card: "summary_large_image",
    title: TITLE,
    description: DESCRIPTION,
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
  parentOrganization: {
    "@type": "Organization",
    name: "Profullstack, Inc.",
    url: "https://profullstack.com",
  },
  contactPoint: [
    {
      "@type": "ContactPoint",
      contactType: "customer support",
      email: "hello@threatcrush.com",
      url: `${SITE_URL}/hire`,
      availableLanguage: ["English"],
    },
    {
      "@type": "ContactPoint",
      contactType: "security",
      email: "security@threatcrush.com",
    },
    {
      "@type": "ContactPoint",
      contactType: "investor relations",
      email: "invest@threatcrush.com",
      url: `${SITE_URL}/investors`,
    },
    {
      "@type": "ContactPoint",
      contactType: "sales",
      email: "gov@threatcrush.com",
      areaServed: "US",
      description: "Government & defense sales",
    },
  ],
  sameAs: [
    "https://github.com/profullstack/threatcrush",
    "https://www.npmjs.com/package/@profullstack/threatcrush",
    "https://www.linkedin.com/company/profullstackinc",
  ],
};

const websiteJsonLd = {
  "@context": "https://schema.org",
  "@type": "WebSite",
  name: "ThreatCrush",
  url: SITE_URL,
  description:
    "Open-source security agent for Linux servers, with a cloud dashboard and a module store.",
  publisher: { "@type": "Organization", name: "ThreatCrush", url: SITE_URL },
  inLanguage: "en",
  potentialAction: {
    "@type": "SearchAction",
    target: {
      "@type": "EntryPoint",
      urlTemplate: `${SITE_URL}/blog?q={search_term_string}`,
    },
    "query-input": "required name=search_term_string",
  },
};

const softwareApplicationJsonLd = {
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  name: "ThreatCrush",
  alternateName: "@profullstack/threatcrush",
  applicationCategory: "SecurityApplication",
  applicationSubCategory: "Continuous Threat Exposure Management (CTEM)",
  operatingSystem: "Linux, macOS, Windows",
  url: SITE_URL,
  downloadUrl: "https://www.npmjs.com/package/@profullstack/threatcrush",
  installUrl: `${SITE_URL}/install.sh`,
  description:
    "Open-source security agent: live attack detection, automatic firewall bans, hardening checks, code scanner, pentest checks, network monitor, and a module marketplace. Ships a CLI, systemd daemon, TUI and desktop app, with a mobile app and browser extension in development.",
  publisher: { "@type": "Organization", name: "ThreatCrush", url: SITE_URL },
  license: "https://opensource.org/license/mit",
  image: `${SITE_URL}/banner.png`,
  screenshot: [
    `${SITE_URL}/images/gallery-cli.png`,
    `${SITE_URL}/images/gallery-tui.png`,
    `${SITE_URL}/images/gallery-desktop.png`,
    `${SITE_URL}/images/gallery-mobile.png`,
  ],
  featureList: [
    "Live attack detection (OWASP CRS rules for SQLi, XSS and more; brute force, port scans, DNS tunneling)",
    "Automatic IP bans via nftables, iptables or fail2ban, escalating for repeat offenders",
    "Host hardening checks",
    "Code vulnerability scanner (secrets, code patterns, OSV dependency advisories, SARIF output)",
    "Pentest checks for URLs and APIs",
    "Inbound-connection monitor — port scans & SYN floods",
    "Email, Slack, Discord, PagerDuty and webhook alerts",
    "Cloud dashboard for linked servers",
    "systemd daemon — runs 24/7",
  ],
  offers: {
    "@type": "Offer",
    availability: "https://schema.org/PreOrder",
    priceCurrency: "USD",
    price: "0",
    description: "Private beta — contact sales for pricing.",
    url: `${SITE_URL}/hire`,
  },
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
        <link rel="openthreat" href="/.well-known/openthreat.json" />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: serializeJsonForHtml(organizationJsonLd) }}
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: serializeJsonForHtml(websiteJsonLd) }}
        />
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: serializeJsonForHtml(softwareApplicationJsonLd) }}
        />
      </head>
      <body className="antialiased">
        <AuthProvider>
          <PwaLifecycle />
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
              <Script data-site="09d382f0-1b98-4d28-b360-78eaf4e030f2" src="https://crawlproof.com/stats.js" strategy="afterInteractive" />
      <FeedbackWidget property="threatcrush.com" />
      </body>
    </html>
  );
}
