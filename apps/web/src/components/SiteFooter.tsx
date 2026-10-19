import { Footer } from "@profullstack/footer/react";

// One row: the site's links, then the copyright + Profullstack ring nav, all
// rendered server-side from the shared @profullstack/footer @latest template.
export default function SiteFooter() {
  return (
    <div className="border-t border-tc-border mt-12 font-mono">
      <Footer
        site="https://threatcrush.com/"
        links={[
          { label: "Docs", href: "/docs" },
          { label: "Module Store", href: "/store" },
          { label: "Blog", href: "/blog" },
          { label: "Hire Us", href: "/hire" },
          { label: "About", href: "/about" },
          { label: "Investors", href: "/investors" },
          { label: "Security", href: "/security" },
          { label: "Terms", href: "/terms" },
          { label: "Privacy", href: "/privacy" },
          { label: "GitHub", href: "https://github.com/profullstack/threatcrush" },
        ]}
      />
    </div>
  );
}
