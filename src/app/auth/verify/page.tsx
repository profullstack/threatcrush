"use client";

import { useState, useEffect, Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { authHeaders, getAccessToken } from "@/lib/auth-client";

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
  const [smsCooldown, setSmsCooldown] = useState(0);
  const [smsSending, setSmsSending] = useState(false);
  const [smsSent, setSmsSent] = useState(false);
  const [checkingStatus, setCheckingStatus] = useState(true);

  // Check current verification status
  useEffect(() => {
    const checkStatus = async () => {
      if (!getAccessToken()) {
        setCheckingStatus(false);
        return;
      }
      try {
        const res = await fetch("/api/auth/check", { headers: authHeaders() });
        if (res.ok) {
          const data = await res.json();
          setEmailVerified(!!data.email_verified);
          setPhoneVerified(!!data.phone_verified);
        }
      } catch {
        // Silent fail
      }
      setCheckingStatus(false);
    };

    checkStatus();
    // Poll every 5s for email verification
    const interval = setInterval(checkStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  // Resend cooldown timers
  useEffect(() => {
    if (resendCooldown > 0) {
      const timer = setTimeout(() => setResendCooldown(resendCooldown - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [resendCooldown]);

  useEffect(() => {
    if (smsCooldown > 0) {
      const timer = setTimeout(() => setSmsCooldown(smsCooldown - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [smsCooldown]);

  const handleSendPhoneCode = async (targetPhone?: string) => {
    const phoneToUse = (targetPhone ?? phone ?? phoneParam).trim();
    if (!phoneToUse) {
      setError("Enter a phone number first");
      return;
    }
    if (smsCooldown > 0 || smsSending) return;
    setSmsSending(true);
    setError("");
    try {
      const res = await fetch("/api/auth/send-phone-code", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ phone: phoneToUse }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Could not send SMS");
        return;
      }
      setSmsSent(true);
      setSmsCooldown(30);
    } catch {
      setError("Network error sending SMS");
    } finally {
      setSmsSending(false);
    }
  };

  // Auto-send the SMS code once on mount if we have a phone from the query string.
  useEffect(() => {
    if (phoneParam && !phoneVerified && !smsSent && getAccessToken()) {
      handleSendPhoneCode(phoneParam);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phoneParam]);

  const handleResendEmail = async () => {
    if (resendCooldown > 0) return;
    try {
      const res = await fetch("/api/auth/resend", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: emailParam, type: "signup" }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Could not resend email");
        return;
      }
      setResendCooldown(60);
    } catch {
      setError("Network error");
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
      const res = await fetch("/api/auth/verify-phone", {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ code: phoneCode }),
      });

      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Verification failed");
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
                    <div className="flex gap-2">
                      <input
                        type="tel"
                        value={phone}
                        onChange={(e) => setPhone(e.target.value)}
                        placeholder="+1 555 123 4567"
                        className="min-w-0 flex-1 bg-tc-darker border border-tc-border rounded-lg px-3 py-2.5 text-white placeholder:text-tc-text-dim focus:outline-none focus:border-tc-green/50 transition-colors"
                      />
                      <button
                        onClick={() => handleSendPhoneCode()}
                        disabled={smsSending || smsCooldown > 0 || !phone.trim()}
                        className="shrink-0 bg-tc-border text-white font-semibold px-4 py-2.5 rounded-lg hover:bg-tc-border/80 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                      >
                        {smsSending ? "..." : smsCooldown > 0 ? `${smsCooldown}s` : "Send code"}
                      </button>
                    </div>
                  </div>
                )}
                <p className="text-tc-text-dim text-sm">
                  {smsSent
                    ? <>Code sent to <span className="text-white">{phone || phoneParam}</span>. Enter it below.</>
                    : <>We&apos;ll text a 6-digit code to <span className="text-white">{phone || phoneParam || "your phone"}</span>.</>
                  }
                </p>
                {phoneParam && (
                  <button
                    type="button"
                    onClick={() => handleSendPhoneCode()}
                    disabled={smsSending || smsCooldown > 0}
                    className="text-sm text-tc-green hover:underline disabled:text-tc-text-dim disabled:no-underline"
                  >
                    {smsSending
                      ? "Sending..."
                      : smsCooldown > 0
                      ? `Resend in ${smsCooldown}s`
                      : smsSent
                      ? "Resend code"
                      : "Send code"}
                  </button>
                )}
                <div className="flex gap-2 w-full">
                  <input
                    type="text"
                    inputMode="numeric"
                    value={phoneCode}
                    onChange={(e) => setPhoneCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    maxLength={6}
                    placeholder="000000"
                    className="min-w-0 flex-1 bg-tc-darker border border-tc-border rounded-lg px-3 py-2.5 text-white text-center tracking-[0.3em] font-mono text-base placeholder:text-tc-text-dim focus:outline-none focus:border-tc-green/50 transition-colors"
                  />
                  <button
                    onClick={handleVerifyPhone}
                    disabled={loading || phoneCode.length !== 6}
                    className="shrink-0 bg-tc-green text-black font-bold px-4 py-2.5 rounded-lg hover:bg-tc-green-dim transition-all disabled:opacity-50 disabled:cursor-not-allowed"
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
