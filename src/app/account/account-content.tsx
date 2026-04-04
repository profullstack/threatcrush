"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";

export default function AccountContent() {
  const { user, profile, loading, signOut, refreshProfile } = useAuth();
  const [editing, setEditing] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [walletAddress, setWalletAddress] = useState("");
  const [payoutCrypto, setPayoutCrypto] = useState("USDT");
  const [notifEmail, setNotifEmail] = useState(true);
  const [notifSms, setNotifSms] = useState(true);
  const [webhookUrl, setWebhookUrl] = useState("");
  const [saving, setSaving] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (profile) {
      setDisplayName(profile.display_name || "");
      setWalletAddress(profile.wallet_address || "");
      setPayoutCrypto(profile.payout_crypto || "USDT");
      setNotifEmail(profile.notification_email);
      setNotifSms(profile.notification_sms);
      setWebhookUrl(profile.notification_webhook_url || "");
    }
  }, [profile]);

  if (loading) {
    return (
      <div className="min-h-screen bg-tc-darker flex items-center justify-center">
        <div className="text-tc-text-dim">Loading...</div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="min-h-screen bg-tc-darker flex items-center justify-center">
        <div className="text-center">
          <p className="text-tc-text-dim mb-4">You need to log in to view your account.</p>
          <Link href="/auth/login" className="text-tc-green hover:underline">
            Log in →
          </Link>
        </div>
      </div>
    );
  }

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await fetch("/api/auth/me", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          display_name: displayName,
          wallet_address: walletAddress,
          payout_crypto: payoutCrypto,
          notification_email: notifEmail,
          notification_sms: notifSms,
          notification_webhook_url: webhookUrl || null,
        }),
      });

      if (res.ok) {
        await refreshProfile();
        setEditing(false);
      }
    } catch {
      // Silent fail
    } finally {
      setSaving(false);
    }
  };

  const referralLink = profile?.referral_code
    ? `${typeof window !== "undefined" ? window.location.origin : ""}/auth/signup?ref=${profile.referral_code}`
    : "";

  const copyReferralLink = () => {
    navigator.clipboard?.writeText(referralLink);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleLogout = async () => {
    await signOut();
    window.location.href = "/";
  };

  return (
    <div className="min-h-screen bg-tc-darker">
      {/* Nav */}
      <nav className="border-b border-tc-border/50 bg-tc-darker/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-6 py-4">
          <Link href="/" className="text-xl font-bold text-tc-green glow-green font-mono">
            ⚡ ThreatCrush
          </Link>
          <div className="flex items-center gap-4 text-sm">
            <Link href="/store" className="text-tc-text-dim hover:text-tc-green transition-colors">Store</Link>
            <Link href="/usage" className="text-tc-text-dim hover:text-tc-green transition-colors">Usage</Link>
            <button onClick={handleLogout} className="text-tc-text-dim hover:text-red-400 transition-colors">
              Logout
            </button>
          </div>
        </div>
      </nav>

      <div className="mx-auto max-w-4xl px-6 py-10">
        <h1 className="text-3xl font-bold text-white mb-8">Account</h1>

        <div className="space-y-6">
          {/* Profile Info */}
          <div className="bg-tc-card border border-tc-border rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-white">Profile</h2>
              {!editing ? (
                <button onClick={() => setEditing(true)} className="text-sm text-tc-green hover:underline">
                  Edit
                </button>
              ) : (
                <div className="flex gap-2">
                  <button onClick={() => setEditing(false)} className="text-sm text-tc-text-dim hover:text-white">
                    Cancel
                  </button>
                  <button
                    onClick={handleSave}
                    disabled={saving}
                    className="text-sm bg-tc-green text-black px-3 py-1 rounded-lg font-semibold hover:bg-tc-green-dim disabled:opacity-50"
                  >
                    {saving ? "Saving..." : "Save"}
                  </button>
                </div>
              )}
            </div>

            <div className="grid gap-4">
              <div>
                <span className="text-sm text-tc-text-dim">Display Name</span>
                {editing ? (
                  <input
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    className="w-full bg-tc-darker border border-tc-border rounded-lg px-3 py-2 text-white mt-1 focus:outline-none focus:border-tc-green/50"
                  />
                ) : (
                  <p className="text-white">{profile?.display_name || "Not set"}</p>
                )}
              </div>
              <div>
                <span className="text-sm text-tc-text-dim">Email</span>
                <p className="text-white flex items-center gap-2">
                  {profile?.email}
                  {profile?.email_verified ? (
                    <span className="text-xs bg-tc-green/10 text-tc-green px-2 py-0.5 rounded">✓ Verified</span>
                  ) : (
                    <span className="text-xs bg-red-500/10 text-red-400 px-2 py-0.5 rounded">Unverified</span>
                  )}
                </p>
              </div>
              <div>
                <span className="text-sm text-tc-text-dim">Phone</span>
                <p className="text-white flex items-center gap-2">
                  {profile?.phone || "Not set"}
                  {profile?.phone_verified ? (
                    <span className="text-xs bg-tc-green/10 text-tc-green px-2 py-0.5 rounded">✓ Verified</span>
                  ) : (
                    <span className="text-xs bg-red-500/10 text-red-400 px-2 py-0.5 rounded">Unverified</span>
                  )}
                </p>
              </div>
            </div>
          </div>

          {/* License Status */}
          <div className="bg-tc-card border border-tc-border rounded-xl p-6">
            <h2 className="text-lg font-semibold text-white mb-4">License</h2>
            <div className="flex items-center gap-3">
              <div className={`w-3 h-3 rounded-full ${profile?.license_status === "active" ? "bg-tc-green" : "bg-tc-text-dim"}`} />
              <span className="text-white capitalize">{profile?.license_status || "None"}</span>
            </div>
            {profile?.license_status !== "active" && (
              <p className="text-tc-text-dim text-sm mt-2">
                {profile?.email_verified && profile?.phone_verified ? (
                  <Link href="/#pricing" className="text-tc-green hover:underline">Get lifetime access →</Link>
                ) : (
                  <Link href="/auth/verify" className="text-yellow-500 hover:underline">Complete verification to purchase →</Link>
                )}
              </p>
            )}
          </div>

          {/* Referral Section */}
          <div className="bg-tc-card border border-tc-border rounded-xl p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Referrals</h2>
            <div className="space-y-3">
              <div>
                <span className="text-sm text-tc-text-dim">Your Referral Code</span>
                <p className="text-tc-green font-mono text-lg">{profile?.referral_code}</p>
              </div>
              <div>
                <span className="text-sm text-tc-text-dim">Share Link</span>
                <div className="flex gap-2 mt-1">
                  <input
                    readOnly
                    value={referralLink}
                    className="flex-1 bg-tc-darker border border-tc-border rounded-lg px-3 py-2 text-white text-sm font-mono"
                  />
                  <button
                    onClick={copyReferralLink}
                    className="bg-tc-green/10 text-tc-green px-4 py-2 rounded-lg text-sm hover:bg-tc-green/20 transition-colors"
                  >
                    {copied ? "Copied!" : "Copy"}
                  </button>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4 mt-4">
                <div>
                  <span className="text-sm text-tc-text-dim">Total Earnings</span>
                  <p className="text-white text-xl font-bold">${profile?.total_referral_earnings_usd?.toFixed(2) || "0.00"}</p>
                </div>
                <div>
                  <span className="text-sm text-tc-text-dim">Payout Wallet</span>
                  {editing ? (
                    <div className="space-y-2 mt-1">
                      <select
                        value={payoutCrypto}
                        onChange={(e) => setPayoutCrypto(e.target.value)}
                        className="w-full bg-tc-darker border border-tc-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-tc-green/50"
                      >
                        <option value="USDT">USDT</option>
                        <option value="BTC">BTC</option>
                        <option value="ETH">ETH</option>
                        <option value="SOL">SOL</option>
                      </select>
                      <input
                        value={walletAddress}
                        onChange={(e) => setWalletAddress(e.target.value)}
                        placeholder="Wallet address"
                        className="w-full bg-tc-darker border border-tc-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-tc-green/50"
                      />
                    </div>
                  ) : (
                    <p className="text-white text-sm truncate">
                      {profile?.wallet_address ? `${profile.payout_crypto}: ${profile.wallet_address}` : "Not set"}
                    </p>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Notification Preferences */}
          <div className="bg-tc-card border border-tc-border rounded-xl p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Notifications</h2>
            {editing ? (
              <div className="space-y-3">
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={notifEmail}
                    onChange={(e) => setNotifEmail(e.target.checked)}
                    className="accent-tc-green w-4 h-4"
                  />
                  <span className="text-white">Email notifications</span>
                </label>
                <label className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={notifSms}
                    onChange={(e) => setNotifSms(e.target.checked)}
                    className="accent-tc-green w-4 h-4"
                  />
                  <span className="text-white">SMS notifications</span>
                </label>
                <div>
                  <label className="block text-sm text-tc-text-dim mb-1">Webhook URL</label>
                  <input
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                    placeholder="https://your-webhook.com/notify"
                    className="w-full bg-tc-darker border border-tc-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-tc-green/50"
                  />
                </div>
              </div>
            ) : (
              <div className="space-y-2">
                <p className="text-white flex items-center gap-2">
                  <span className={notifEmail ? "text-tc-green" : "text-tc-text-dim"}>{notifEmail ? "✓" : "✗"}</span>
                  Email notifications
                </p>
                <p className="text-white flex items-center gap-2">
                  <span className={notifSms ? "text-tc-green" : "text-tc-text-dim"}>{notifSms ? "✓" : "✗"}</span>
                  SMS notifications
                </p>
                {webhookUrl && (
                  <p className="text-tc-text-dim text-sm truncate">Webhook: {webhookUrl}</p>
                )}
              </div>
            )}
          </div>

          {/* Usage Link */}
          <div className="bg-tc-card border border-tc-border rounded-xl p-6">
            <h2 className="text-lg font-semibold text-white mb-2">Usage</h2>
            <p className="text-tc-text-dim text-sm mb-3">View your API usage and top up credits</p>
            <Link href="/usage" className="text-tc-green hover:underline text-sm">
              View Usage →
            </Link>
          </div>

          {/* Logout */}
          <button
            onClick={handleLogout}
            className="w-full border border-red-500/30 text-red-400 py-3 rounded-xl hover:bg-red-500/10 transition-colors"
          >
            Log Out
          </button>
        </div>
      </div>
    </div>
  );
}
