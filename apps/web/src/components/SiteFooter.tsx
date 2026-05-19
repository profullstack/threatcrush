const linkClass = "text-sm text-tc-text-dim hover:text-tc-green transition-colors";
const headingClass = "text-xs font-mono uppercase tracking-wider text-tc-text mb-3";

export default function SiteFooter() {
  return (
    <footer className="border-t border-tc-border py-12 mt-12">
      <div className="mx-auto max-w-6xl px-6">
        <div className="grid grid-cols-2 gap-8 md:grid-cols-5">
          <div className="col-span-2 md:col-span-1">
            <div className="font-mono text-tc-green font-bold text-lg">⚡ ThreatCrush</div>
            <p className="mt-2 text-xs text-tc-text-dim max-w-[14rem]">
              Continuous threat exposure management for builders.
            </p>
          </div>

          <div>
            <h3 className={headingClass}>Product</h3>
            <ul className="space-y-2">
              <li><a href="/#features" className={linkClass}>Features</a></li>
              <li><a href="/store" className={linkClass}>Module Store</a></li>
              <li><a href="/blog" className={linkClass}>Blog</a></li>
              <li><a href="/docs" className={linkClass}>Docs</a></li>
              <li><a href="/usage" className={linkClass}>Usage</a></li>
              <li><a href="/pricing" className={linkClass}>Pricing</a></li>
            </ul>
          </div>

          <div>
            <h3 className={headingClass}>Company</h3>
            <ul className="space-y-2">
              <li><a href="/about" className={linkClass}>About</a></li>
              <li><a href="/get-whitepaper" className={linkClass}>CTEM Guide</a></li>
              <li><a href="/investors" className={linkClass}>Investors</a></li>
              <li><a href="/affiliates" className={linkClass}>Affiliates</a></li>
              <li><a href="/#faq" className={linkClass}>FAQ</a></li>
            </ul>
          </div>

          <div>
            <h3 className={headingClass}>Connect</h3>
            <ul className="space-y-2">
              <li>
                <a
                  href="https://github.com/profullstack/threatcrush"
                  target="_blank"
                  rel="noopener noreferrer"
                  className={linkClass}
                >
                  GitHub
                </a>
              </li>
              <li>
                <a
                  href="https://www.npmjs.com/package/@profullstack/threatcrush"
                  target="_blank"
                  rel="noopener noreferrer"
                  className={linkClass}
                >
                  npm
                </a>
              </li>
            </ul>
          </div>

          <div>
            <h3 className={headingClass}>Legal</h3>
            <ul className="space-y-2">
              <li><a href="/terms" className={linkClass}>Terms</a></li>
              <li><a href="/privacy" className={linkClass}>Privacy</a></li>
            </ul>
          </div>
        </div>

        <div className="mt-10 pt-6 border-t border-tc-border flex flex-col sm:flex-row items-center justify-between gap-3">
          <p className="text-xs text-tc-text-dim">
            © {new Date().getFullYear()}{" "}
            <a href="https://profullstack.com" className="hover:text-tc-green transition-colors">
              Profullstack, Inc.
            </a>
            . All rights reserved.
          </p>
          <p className="text-xs text-tc-text-dim font-mono">
            Built with ⚡ in the open
          </p>
        </div>
      </div>
    </footer>
  );
}
