const linkClass = "hover:text-tc-green transition-colors";

const links = [
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
];

export default function SiteFooter() {
  return (
    <footer className="border-t border-tc-border py-6 mt-12">
      <nav
        aria-label="Footer"
        className="mx-auto max-w-6xl px-6 flex flex-wrap items-center justify-center gap-x-5 gap-y-2 text-sm text-tc-text-dim"
      >
        <span className="font-mono">
          &copy; {new Date().getFullYear()}{" "}
          <a href="https://profullstack.com/" className={linkClass}>Profullstack, Inc.</a>
        </span>
        {links.map((link) => (
          <a key={link.href} href={link.href} className={linkClass}>
            {link.label}
          </a>
        ))}
      </nav>
    </footer>
  );
}
