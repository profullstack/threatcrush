"use client";

import { useState, useEffect } from "react";

export default function WaitlistModal({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const [email, setEmail] = useState("");
  const [referralCode, setReferralCode] = useState("");
  const [signedUp, setSignedUp] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const ref = params.get("ref");
      if (ref) setReferralCode(ref);
    }
  }, []);

  if (!open) return null;

  const handleSignup = async () => {
    if (!email) return;
    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/waitlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          referral_code: referralCode || undefined,
        }),
      });

      const data = await res.json();
      if (!res.ok && !data.paid) {
        throw new Error(data.error || "Something went wrong");
      }
      setSignedUp(true);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setEmail("");
    setSignedUp(false);
    setError("");
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-black/80 backdrop-blur-sm"
        onClick={handleClose}
      />

      <div className="relative w-full max-w-md rounded-2xl border border-tc-border bg-tc-card p-8 max-h-[90vh] overflow-y-auto">
        <button
          onClick={handleClose}
          className="absolute top-4 right-4 text-tc-text-dim hover:text-tc-text transition-colors"
        >
          ✕
        </button>

        {signedUp ? (
          <div className="text-center">
            <div className="text-5xl mb-4">🔒</div>
            <h3 className="text-2xl font-bold text-tc-green glow-green mb-2">
              You&apos;re In!
            </h3>
            <p className="text-tc-text-dim text-sm mb-6">
              Your spot on the waitlist is secured. We&apos;ll be in touch with
              pricing and next steps.
            </p>
            <button
              onClick={handleClose}
              className="w-full px-6 py-2 rounded-lg border border-tc-border text-tc-text-dim hover:text-tc-text hover:border-tc-green/30 transition-all text-sm"
            >
              Close
            </button>
          </div>
        ) : (
          <>
            <div className="mb-6">
              <h3 className="text-2xl font-bold text-tc-green glow-green mb-1">
                Join the Waitlist
              </h3>
              <p className="text-tc-text-dim text-sm">
                Secure your spot. We&apos;ll be in touch with pricing and next
                steps.
              </p>
            </div>

            <div className="mb-4">
              <label className="block text-sm font-medium text-tc-text-dim mb-1.5">
                Email Address
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="operator@example.com"
                onKeyDown={(e) => e.key === "Enter" && handleSignup()}
                className="w-full rounded-lg border border-tc-border bg-tc-darker px-4 py-3 text-tc-text placeholder:text-tc-text-dim/50 focus:border-tc-green/50 focus:outline-none focus:ring-1 focus:ring-tc-green/30 transition-all font-mono text-sm"
              />
            </div>

            {error && <p className="text-red-400 text-sm mb-4">{error}</p>}

            <button
              onClick={handleSignup}
              disabled={!email || loading}
              className="w-full rounded-lg bg-tc-green px-6 py-3 font-bold text-black transition-all hover:bg-tc-green-dim disabled:opacity-40 disabled:cursor-not-allowed pulse-glow"
            >
              {loading ? "Joining..." : "Join Waitlist →"}
            </button>

            <p className="text-center text-xs text-tc-text-dim mt-3">
              🔒 No payment required. We&apos;ll follow up by email.
            </p>
          </>
        )}
      </div>
    </div>
  );
}
