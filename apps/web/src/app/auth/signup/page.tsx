"use client";

import { useState, useEffect, useMemo } from "react";
import Link from "next/link";

export default function SignupPage() {
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [referralCode, setReferralCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const nextPath = useMemo(() => {
    if (typeof window === "undefined") return "/account";
    const raw = new URLSearchParams(window.location.search).get("next") || "/account";
    return raw.startsWith("/") ? raw : "/account";
  }, []);

  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const ref = params.get("ref");
      if (ref) setReferralCode(ref);
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          phone: phone || undefined,
          password,
          display_name: displayName || undefined,
          referral_code: referralCode || undefined,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Signup failed");
        return;
      }

      setSuccess(true);
      // Redirect to verification page
      setTimeout(() => {
        window.location.href = `/auth/verify?email=${encodeURIComponent(email)}&phone=${encodeURIComponent(phone)}&next=${encodeURIComponent(nextPath)}`;
      }, 1500);
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-tc-darker flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <Link href="/" className="text-2xl font-bold text-tc-green glow-green font-mono">
            ⚡ ThreatCrush
          </Link>
          <h1 className="text-2xl font-bold text-white mt-4">Create your account</h1>
          <p className="text-tc-text-dim mt-2">Get lifetime access to threat intelligence</p>
        </div>

        <form onSubmit={handleSubmit} className="bg-tc-card border border-tc-border rounded-xl p-6 space-y-4">
          {error && (
            <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg px-4 py-3 text-sm">
              {error}
            </div>
          )}

          {success && (
            <div className="bg-tc-green/10 border border-tc-green/30 text-tc-green rounded-lg px-4 py-3 text-sm">
              ✅ Account created! Redirecting to verification...
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-tc-text mb-1">Display Name</label>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Your name"
              className="w-full bg-tc-darker border border-tc-border rounded-lg px-4 py-2.5 text-white placeholder:text-tc-text-dim focus:outline-none focus:border-tc-green/50 transition-colors"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-tc-text mb-1">Email *</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              placeholder="you@example.com"
              className="w-full bg-tc-darker border border-tc-border rounded-lg px-4 py-2.5 text-white placeholder:text-tc-text-dim focus:outline-none focus:border-tc-green/50 transition-colors"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-tc-text mb-1">Phone</label>
            <input
              type="tel"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
              placeholder="+1 555 123 4567"
              className="w-full bg-tc-darker border border-tc-border rounded-lg px-4 py-2.5 text-white placeholder:text-tc-text-dim focus:outline-none focus:border-tc-green/50 transition-colors"
            />
            <p className="text-xs text-tc-text-dim mt-1">Required for verification before payment</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-tc-text mb-1">Password *</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
              placeholder="Min 8 characters"
              className="w-full bg-tc-darker border border-tc-border rounded-lg px-4 py-2.5 text-white placeholder:text-tc-text-dim focus:outline-none focus:border-tc-green/50 transition-colors"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-tc-text mb-1">Referral Code</label>
            <input
              type="text"
              value={referralCode}
              onChange={(e) => setReferralCode(e.target.value)}
              placeholder="Optional"
              className="w-full bg-tc-darker border border-tc-border rounded-lg px-4 py-2.5 text-white placeholder:text-tc-text-dim focus:outline-none focus:border-tc-green/50 transition-colors"
            />
            {referralCode && (
              <p className="text-xs text-tc-green mt-1">🎉 $100 off with referral code!</p>
            )}
          </div>

          <button
            type="submit"
            disabled={loading || success}
            className="w-full bg-tc-green text-black font-bold py-3 rounded-lg hover:bg-tc-green-dim transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Creating account..." : "Sign Up"}
          </button>

          <div className="flex items-center gap-3 my-2">
            <span className="h-px flex-1 bg-tc-border" />
            <span className="text-xs text-tc-text-dim">or continue with</span>
            <span className="h-px flex-1 bg-tc-border" />
          </div>

          <a
            href={`/api/auth/github?next=${encodeURIComponent(nextPath)}${referralCode ? `&ref=${encodeURIComponent(referralCode)}` : ''}`}
            className="w-full flex items-center justify-center gap-2 bg-[#24292e] text-white font-medium py-3 rounded-lg hover:bg-[#2f363d] transition-all border border-tc-border"
          >
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
            Continue with GitHub
          </a>

          <p className="text-center text-sm text-tc-text-dim">
            Already have an account?{" "}
            <Link href={`/auth/login?next=${encodeURIComponent(nextPath)}`} className="text-tc-green hover:underline">
              Log in
            </Link>
          </p>
        </form>
      </div>
    </div>
  );
}
