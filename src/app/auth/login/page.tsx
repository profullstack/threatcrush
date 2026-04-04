"use client";

import { useState } from "react";
import Link from "next/link";
import { getSupabaseClient } from "@/lib/supabase";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

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
          window.location.href = "/auth/verify";
        } else {
          window.location.href = "/account";
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

          <div className="flex justify-between text-sm">
            <button
              type="button"
              onClick={handleForgotPassword}
              className="text-tc-text-dim hover:text-tc-green transition-colors"
            >
              Forgot password?
            </button>
            <Link href="/auth/signup" className="text-tc-green hover:underline">
              Create account
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}
