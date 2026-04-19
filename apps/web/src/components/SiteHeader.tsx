"use client";

import { useState, useEffect } from "react";
import { useAuth } from "@/lib/auth-context";
import WaitlistModal from "@/components/WaitlistModal";

export default function SiteHeader() {
  const { signedIn, profile, signOut, loading } = useAuth();
  const [modalOpen, setModalOpen] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [userDropdownOpen, setUserDropdownOpen] = useState(false);
  const openModal = () => setModalOpen(true);

  // Close dropdown on outside click
  useEffect(() => {
    if (!userDropdownOpen) return;
    const handler = () => setUserDropdownOpen(false);
    document.addEventListener("click", handler);
    return () => document.removeEventListener("click", handler);
  }, [userDropdownOpen]);

  const handleSignOut = async () => {
    await signOut();
    window.location.href = "/";
  };

  return (
    <>
      <WaitlistModal open={modalOpen} onClose={() => setModalOpen(false)} />

      <nav className="fixed top-0 left-0 right-0 z-40 border-b border-tc-border/50 bg-tc-darker/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-2 sm:px-6">
          <a href="/" className="flex items-center gap-2">
            <img src="/logo.svg" alt="ThreatCrush" className="w-[120px] h-auto" />
          </a>
          <div className="hidden lg:flex items-center gap-6 text-sm text-tc-text-dim">
            <a href="/store" className="text-tc-green transition-colors">Module Store</a>
            <a href="/docs" className="hover:text-tc-green transition-colors">Docs</a>
            <a href="/#features" className="hover:text-tc-green transition-colors">Features</a>
            <a href="/usage" className="hover:text-tc-green transition-colors">Usage</a>
            <a href="/#pricing" className="hover:text-tc-green transition-colors">Pricing</a>
            <a href="/investors" className="hover:text-tc-green transition-colors">Investors</a>
            <a href="/#faq" className="hover:text-tc-green transition-colors">FAQ</a>
            <a
              href="https://github.com/profullstack/threatcrush"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-tc-green transition-colors flex items-center gap-1"
            >
              <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
              </svg>
              GitHub
            </a>
          </div>
          <div className="flex items-center gap-2 sm:gap-3">
            {!loading && (
              signedIn ? (
                <div className="flex items-center gap-2 relative">
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setUserDropdownOpen((v) => !v);
                    }}
                    className="rounded-lg bg-tc-green/10 border border-tc-green/30 px-3 py-2 text-sm font-bold text-tc-green transition-all hover:bg-tc-green/20 flex items-center gap-2"
                  >
                    <span>{profile?.display_name || profile?.email || "Account"}</span>
                    <span className="text-xs">{userDropdownOpen ? "▲" : "▼"}</span>
                  </button>
                  {userDropdownOpen && (
                    <div
                      className="absolute right-0 top-full mt-2 w-56 bg-tc-card border border-tc-border rounded-xl shadow-xl overflow-hidden z-50"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="px-4 py-3 border-b border-tc-border">
                        <p className="text-sm text-white font-medium truncate">{profile?.display_name || "User"}</p>
                        <p className="text-xs text-tc-text-dim truncate">{profile?.email}</p>
                      </div>
                      <div className="py-1">
                        <a
                          href="/account"
                          className="block px-4 py-2 text-sm text-tc-text-dim hover:text-white hover:bg-tc-darker transition-colors"
                          onClick={() => setUserDropdownOpen(false)}
                        >
                          Account Settings
                        </a>
                        <a
                          href="/usage"
                          className="block px-4 py-2 text-sm text-tc-text-dim hover:text-white hover:bg-tc-darker transition-colors"
                          onClick={() => setUserDropdownOpen(false)}
                        >
                          Usage & Billing
                        </a>
                      </div>
                      <div className="border-t border-tc-border">
                        <button
                          onClick={handleSignOut}
                          className="w-full text-left px-4 py-2 text-sm text-red-400 hover:bg-red-500/10 transition-colors"
                        >
                          Sign Out
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <>
                  <a
                    href="/auth/login"
                    className="hidden lg:inline text-sm text-tc-text-dim hover:text-tc-green transition-colors"
                  >
                    Log In
                  </a>
                  <a
                    href="/auth/signup"
                    className="rounded-lg bg-tc-green px-3 py-2 text-sm font-bold text-black transition-all hover:bg-tc-green-dim sm:px-4"
                  >
                    Sign Up
                  </a>
                </>
              )
            )}
            <button
              type="button"
              onClick={() => setMobileNavOpen((open) => !open)}
              className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-tc-border text-tc-text-dim transition-all hover:border-tc-green/30 hover:text-tc-green lg:hidden"
              aria-label="Toggle navigation menu"
              aria-expanded={mobileNavOpen}
            >
              <span className="text-lg">{mobileNavOpen ? "✕" : "☰"}</span>
            </button>
            <div className="hidden lg:flex items-center gap-3">
              {!signedIn && !loading && (
                <button
                  onClick={openModal}
                  className="rounded-lg border border-tc-green/30 px-4 py-2 text-sm font-bold text-tc-green transition-all hover:bg-tc-green/10"
                >
                  Join Waitlist
                </button>
              )}
            </div>
          </div>
        </div>
        {mobileNavOpen && (
          <div className="border-t border-tc-border/50 bg-tc-darker/95 px-4 py-4 lg:hidden">
            <div className="flex flex-col gap-3 text-sm text-tc-text-dim">
              <a href="/store" className="text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Module Store</a>
              <a href="/docs" className="hover:text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Docs</a>
              <a href="/#features" className="hover:text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Features</a>
              <a href="/usage" className="hover:text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Usage</a>
              <a href="/#pricing" className="hover:text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Pricing</a>
              <a href="/investors" className="hover:text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Investors</a>
              <a href="/#faq" className="hover:text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>FAQ</a>
              {signedIn ? (
                <>
                  <a href="/account" className="text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Account</a>
                  <button
                    onClick={async () => {
                      setMobileNavOpen(false);
                      await signOut();
                      window.location.href = "/";
                    }}
                    className="text-left text-red-400 hover:text-red-300 transition-colors"
                  >
                    Sign Out
                  </button>
                </>
              ) : (
                <>
                  <a href="/auth/login" className="hover:text-tc-green transition-colors" onClick={() => setMobileNavOpen(false)}>Log In</a>
                  <button
                    onClick={() => {
                      setMobileNavOpen(false);
                      openModal();
                    }}
                    className="rounded-lg border border-tc-green/30 px-4 py-2 text-left font-bold text-tc-green transition-all hover:bg-tc-green/10"
                  >
                    Join Waitlist
                  </button>
                </>
              )}
              <a
                href="https://github.com/profullstack/threatcrush"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-tc-green transition-colors"
                onClick={() => setMobileNavOpen(false)}
              >
                GitHub
              </a>
            </div>
          </div>
        )}
      </nav>
    </>
  );
}
