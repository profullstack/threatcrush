"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { clearUrlHash, parseAuthRedirectHash, setAccessToken } from "@/lib/auth-client";
import { MIN_PASSWORD_LENGTH, passwordPolicyError } from "@/lib/password-policy";

const LINK_INVALID = "This password reset link is invalid or has expired.";

/** Seconds-since-epoch expiry of a JWT, or null when it cannot be read. */
function jwtExpiry(token: string): number | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const json = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
    return typeof json.exp === "number" ? json.exp : null;
  } catch {
    return null;
  }
}

type Stage =
  | { name: "checking" }
  | { name: "ready"; token: string }
  | { name: "invalid"; message: string };

const inputClass =
  "w-full bg-tc-darker border border-tc-border rounded-lg px-4 py-2.5 text-white placeholder:text-tc-text-dim focus:outline-none focus:border-tc-green/50 transition-colors";

export default function ResetPasswordPage() {
  const [stage, setStage] = useState<Stage>({ name: "checking" });
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // The recovery session arrives in the URL hash (AuthProvider forwards it
  // here from wherever GoTrue landed). It is only held in memory for this one
  // request: it is never written to storage, and the hash is dropped at once.
  useEffect(() => {
    const redirect = parseAuthRedirectHash(window.location.hash);
    if (window.location.hash) clearUrlHash();

    if (redirect?.kind === "recovery") {
      const exp = jwtExpiry(redirect.accessToken);
      if (exp !== null && exp * 1000 > Date.now()) {
        setStage({ name: "ready", token: redirect.accessToken });
        return;
      }
      setStage({ name: "invalid", message: LINK_INVALID });
    } else if (redirect?.kind === "error") {
      setStage({ name: "invalid", message: redirect.message });
    } else {
      setStage({ name: "invalid", message: LINK_INVALID });
    }
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (stage.name !== "ready") return;
    setError("");

    const policyError = passwordPolicyError(password);
    if (policyError) {
      setError(policyError);
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);
    try {
      const res = await fetch("/api/auth/reset-password", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${stage.token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ password, confirm_password: confirmPassword }),
      });
      const data = await res.json().catch(() => ({}));

      if (res.status === 401) {
        setStage({ name: "invalid", message: data.error || LINK_INVALID });
        return;
      }
      if (!res.ok) {
        setError(data.error || "Could not update your password. Please try again.");
        return;
      }

      // Every session was ended server-side, so any stored login is dead too.
      setAccessToken(null);
      window.location.replace("/auth/login?reset=success");
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
          <h1 className="text-2xl font-bold text-white mt-4">Set a new password</h1>
          <p className="text-tc-text-dim mt-2">Choose a new password for your account</p>
        </div>

        {stage.name === "checking" && (
          <div className="bg-tc-card border border-tc-border rounded-xl p-6 text-center text-tc-text-dim">
            Checking your reset link...
          </div>
        )}

        {stage.name === "invalid" && (
          <div className="bg-tc-card border border-tc-border rounded-xl p-6 space-y-4">
            <div
              role="alert"
              className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg px-4 py-3 text-sm"
            >
              {stage.message}
            </div>
            <p className="text-sm text-tc-text-dim">
              Reset links work once and expire after an hour. On the log in page, enter your
              email and choose &quot;Forgot password?&quot; to get a new one.
            </p>
            <Link
              href="/auth/login"
              className="block w-full text-center bg-tc-green text-black font-bold py-3 rounded-lg hover:bg-tc-green-dim transition-all"
            >
              Back to log in
            </Link>
          </div>
        )}

        {stage.name === "ready" && (
          <form onSubmit={handleSubmit} className="bg-tc-card border border-tc-border rounded-xl p-6 space-y-4">
            {error && (
              <div
                role="alert"
                className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg px-4 py-3 text-sm"
              >
                {error}
              </div>
            )}

            <div>
              <label htmlFor="new-password" className="block text-sm font-medium text-tc-text mb-1">
                New password
              </label>
              <input
                id="new-password"
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={MIN_PASSWORD_LENGTH}
                placeholder={`Min ${MIN_PASSWORD_LENGTH} characters`}
                className={inputClass}
              />
            </div>

            <div>
              <label htmlFor="confirm-password" className="block text-sm font-medium text-tc-text mb-1">
                Confirm new password
              </label>
              <input
                id="confirm-password"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                minLength={MIN_PASSWORD_LENGTH}
                placeholder="Repeat the new password"
                className={inputClass}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-tc-green text-black font-bold py-3 rounded-lg hover:bg-tc-green-dim transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? "Saving..." : "Set new password"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
