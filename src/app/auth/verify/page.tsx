"use client";

import { useState, useEffect, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { getSupabaseClient } from "@/lib/supabase";

function VerifyContent() {
  const searchParams = useSearchParams();
  const emailParam = searchParams.get("email") || "";
  const phoneParam = searchParams.get("phone") || "";

  const [emailVerified, setEmailVerified] = useState(false);
  const [phoneVerified, setPhoneVerified] = useState(false);
  const [phoneCode, setPhoneCode] = useState("");
  const [phone, setPhone] = useState(phoneParam);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [resendCooldown, setResendCooldown] = useState(0);
  const [userId, setUserId] = useState<string | null>(null);
  const [checkingStatus, setCheckingStatus] = useState(true);

  // Check current verification status
  useEffect(() => {
    const checkStatus = async () => {
      const supabase = getSupabaseClient();
      const { data: { session } } = await supabase.auth.getSession();

      if (session?.user) {
        setUserId(session.user.id);

        // Check if email is verified via Supabase auth
        if (session.user.email_confirmed_at) {
          setEmailVerified(true);
        }

        // Check profile verification status
        try {
          const res = await fetch("/api/auth/check", {
            headers: { Authorization: `Bearer ${session.access_token}` },
          });
          if (res.ok) {
            const data = await res.json();
            setEmailVerified(data.email_verified);
            setPhoneVerified(data.phone_verified);
          }
        } catch {
          // Silent fail
        }
      }
      setCheckingStatus(false);
    };

    checkStatus();
    // Poll every 5s for email verification
    const interval = setInterval(checkStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  // Resend cooldown timer
  useEffect(() => {
    if (resendCooldown > 0) {
      const timer = setTimeout(() => setResendCooldown(resendCooldown - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [resendCooldown]);

  const handleResendEmail = async () => {
    if (resendCooldown > 0) return;
    const supabase = getSupabaseClient();
    const { error } = await supabase.auth.resend({
      type: "signup",
      email: emailParam,
    });
    if (error) {
      setError(error.message);
    } else {
      setResendCooldown(60);
    }
  };

  const handleVerifyPhone = async () => {
    if (!phoneCode || phoneCode.length !== 6) {
      setError("Enter a valid 6-digit code");
      return;
    }
    setLoading(true);
    setError("");

    try {
      const supabase = getSupabaseClient();
      const { data: { session } } = await supabase.auth.getSession();

      const res = await fetch("/api/auth/verify-phone", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(session ? { Authorization: `Bearer ${session.access_token}` } : {}),
        },
        body: JSON.stringify({
          phone: phone || phoneParam,
          code: phoneCode,
          user_id: userId,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setError(data.error);
        return;
      }

      setPhoneVerified(true);
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  };

  const canProceed = emailVerified && phoneVerified;

  if (checkingStatus) {
    return (
      <div className="min-h-screen bg-tc-darker flex items-center justify-center">
        <div className="text-tc-text-dim">Checking verification status...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-tc-darker flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <Link href="/" className="text-2xl font-bold text-tc-green glow-green font-mono">
            ⚡ ThreatCrush
          </Link>
          <h1 className="text-2xl font-bold text-white mt-4">Verify your account</h1>
          <p className="text-tc-text-dim mt-2">Complete both steps to continue</p>
        </div>

        <div className="space-y-4">
          {error && (
            <div className="bg-red-500/10 border border-red-500/30 text-red-400 rounded-lg px-4 py-3 text-sm">
              {error}
            </div>
          )}

          {/* Step 1: Email Verification */}
          <div className={`bg-tc-card border rounded-xl p-6 ${emailVerified ? "border-tc-green/50" : "border-tc-border"}`}>
            <div className="flex items-center gap-3 mb-3">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${emailVerified ? "bg-tc-green text-black" : "bg-tc-border text-tc-text-dim"}`}>
                {emailVerified ? "✓" : "1"}
              </div>
              <h2 className="text-lg font-semibold text-white">Email Verification</h2>
            </div>

            {emailVerified ? (
              <p className="text-tc-green text-sm">✅ Email verified!</p>
            ) : (
              <div>
                <p className="text-tc-text-dim text-sm mb-3">
                  We sent a verification link to <span className="text-white">{emailParam}</span>. Check your inbox and click the link.
                </p>
                <button
                  onClick={handleResendEmail}
                  disabled={resendCooldown > 0}
                  className="text-sm text-tc-green hover:underline disabled:text-tc-text-dim disabled:no-underline"
                >
                  {resendCooldown > 0 ? `Resend in ${resendCooldown}s` : "Resend verification email"}
                </button>
              </div>
            )}
          </div>

          {/* Step 2: Phone Verification */}
          <div className={`bg-tc-card border rounded-xl p-6 ${phoneVerified ? "border-tc-green/50" : "border-tc-border"}`}>
            <div className="flex items-center gap-3 mb-3">
              <div className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold ${phoneVerified ? "bg-tc-green text-black" : "bg-tc-border text-tc-text-dim"}`}>
                {phoneVerified ? "✓" : "2"}
              </div>
              <h2 className="text-lg font-semibold text-white">Phone Verification</h2>
            </div>

            {phoneVerified ? (
              <p className="text-tc-green text-sm">✅ Phone verified!</p>
            ) : (
              <div className="space-y-3">
                {!phoneParam && (
                  <div>
                    <label className="block text-sm text-tc-text-dim mb-1">Phone number</label>
                    <input
                      type="tel"
                      value={phone}
                      onChange={(e) => setPhone(e.target.value)}
                      placeholder="+1 555 123 4567"
                      className="w-full bg-tc-darker border border-tc-border rounded-lg px-4 py-2.5 text-white placeholder:text-tc-text-dim focus:outline-none focus:border-tc-green/50 transition-colors"
                    />
                  </div>
                )}
                <p className="text-tc-text-dim text-sm">
                  Enter the 6-digit code sent to <span className="text-white">{phone || phoneParam || "your phone"}</span>
                </p>
                <p className="text-yellow-500/80 text-xs">
                  ⚠️ Beta: Any 6-digit code will work for now
                </p>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={phoneCode}
                    onChange={(e) => setPhoneCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    maxLength={6}
                    placeholder="000000"
                    className="flex-1 bg-tc-darker border border-tc-border rounded-lg px-4 py-2.5 text-white text-center tracking-[0.5em] font-mono text-lg placeholder:text-tc-text-dim focus:outline-none focus:border-tc-green/50 transition-colors"
                  />
                  <button
                    onClick={handleVerifyPhone}
                    disabled={loading || phoneCode.length !== 6}
                    className="bg-tc-green text-black font-bold px-6 py-2.5 rounded-lg hover:bg-tc-green-dim transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {loading ? "..." : "Verify"}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Continue Button */}
          {canProceed ? (
            <Link
              href="/account"
              className="block w-full bg-tc-green text-black font-bold py-3 rounded-lg hover:bg-tc-green-dim transition-all text-center"
            >
              Continue to Account →
            </Link>
          ) : (
            <div className="text-center text-sm text-tc-text-dim">
              Both verifications must be complete before continuing
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function VerifyPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen bg-tc-darker flex items-center justify-center">
        <div className="text-tc-text-dim">Loading...</div>
      </div>
    }>
      <VerifyContent />
    </Suspense>
  );
}
