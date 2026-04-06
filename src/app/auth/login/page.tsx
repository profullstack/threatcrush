"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { getSupabaseClient } from "@/lib/supabase";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const nextPath = useMemo(() => {
    if (typeof window === "undefined") return "/account";
    const raw = new URLSearchParams(window.location.search).get("next") || "/account";
    return raw.startsWith("/") ? raw : "/account";
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const supabase = getSupabaseClient();
      const { data, error: authError } = await supabase.auth.signInWithPassword({
        email,
        password,
      });

      if (authError) {
        setError(authError.message);
        return;
      }

      if (data.session) {
        // Check verification status
        const res = await fetch("/api/auth/check", {
          headers: { Authorization: `Bearer ${data.session.access_token}` },
        });
        const check = await res.json();

        if (!check.email_verified || !check.phone_verified) {
          window.location.href = `/auth/verify?next=${encodeURIComponent(nextPath)}`;
        } else {
          window.location.href = nextPath;
        }
      }
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = async () => {
    if (!email) {
      setError("Enter your email first");
      return;
    }
    const supabase = getSupabaseClient();
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/auth/login`,
    });
    if (error) {
      setError(error.message);
    } else {
      setError("");
      alert("Password reset email sent! Check your inbox.");
    }
  };

  return (
    <div className="min-h-screen bg-tc-darker flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <Link href="/" className="text-2xl font-bold text-tc-green glow-green font-mono">
            ⚡ ThreatCrush
          </Link>
          <h1 className="text-2xl font-bold text-white mt-4">Welcome back</h1>
          <p className="text-tc-text-dim mt-2">Log in to your account</p>
        </div>

        <form onSubmit={handleSubmit} className="bg-tc-card border border-tc-border rounded-xl p-6 space-y-4">
          {error && (
            <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg px-4 py-3 text-sm">
              {error}
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-tc-text mb-1">Email</label>
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
            <label className="block text-sm font-medium text-tc-text mb-1">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              placeholder="Your password"
              className="w-full bg-tc-darker border border-tc-border rounded-lg px-4 py-2.5 text-white placeholder:text-tc-text-dim focus:outline-none focus:border-tc-green/50 transition-colors"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-tc-green text-black font-bold py-3 rounded-lg hover:bg-tc-green-dim transition-all disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Logging in..." : "Log In"}
          </button>

          <div className="flex items-center gap-3 my-2">
            <span className="h-px flex-1 bg-tc-border" />
            <span className="text-xs text-tc-text-dim">or continue with</span>
            <span className="h-px flex-1 bg-tc-border" />
          </div>

          <a
            href={`/api/auth/github?next=${encodeURIComponent(nextPath)}`}
            className="w-full flex items-center justify-center gap-2 bg-[#24292e] text-white font-medium py-3 rounded-lg hover:bg-[#2f363d] transition-all border border-tc-border"
          >
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
            Continue with GitHub
          </a>

          <div className="flex justify-between text-sm">
            <button
              type="button"
              onClick={handleForgotPassword}
              className="text-tc-text-dim hover:text-tc-green transition-colors"
            >
              Forgot password?
            </button>
            <Link href={`/auth/signup?next=${encodeURIComponent(nextPath)}`} className="text-tc-green hover:underline">
              Create account
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}
