export default function SiteFooter() {
  return (
    <footer className="border-t border-tc-border py-12">
      <div className="mx-auto max-w-6xl px-6">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-6">
          <div className="font-mono text-tc-green font-bold">⚡ ThreatCrush</div>
          <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2 text-sm text-tc-text-dim">
            <a href="/#features" className="hover:text-tc-green transition-colors">Features</a>
            <a href="/store" className="hover:text-tc-green transition-colors">Module Store</a>
            <a href="/docs" className="hover:text-tc-green transition-colors">Docs</a>
            <a href="/usage" className="hover:text-tc-green transition-colors">Usage</a>
            <a href="/#pricing" className="hover:text-tc-green transition-colors">Pricing</a>
            <a href="/investors" className="hover:text-tc-green transition-colors">Investors</a>
            <a href="/#faq" className="hover:text-tc-green transition-colors">FAQ</a>
            <a href="/affiliates" className="hover:text-tc-green transition-colors">Affiliates</a>
            <a href="/terms" className="hover:text-tc-green transition-colors">Terms</a>
            <a href="/privacy" className="hover:text-tc-green transition-colors">Privacy</a>
            <a
              href="https://github.com/profullstack/threatcrush"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-tc-green transition-colors"
            >
              GitHub
            </a>
            <a
              href="https://www.npmjs.com/package/@profullstack/threatcrush"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-tc-green transition-colors"
            >
              npm
            </a>
          </div>
          <p className="text-xs text-tc-text-dim">
            © {new Date().getFullYear()}{" "}
            <a href="https://profullstack.com" className="hover:text-tc-green transition-colors">
              Profullstack, Inc.
            </a>
          </p>
        </div>
      </div>
    </footer>
  );
}
