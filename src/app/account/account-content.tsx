"use client";

import { useState, useEffect, useCallback } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { authHeaders } from "@/lib/auth-client";
import { parseWalletPaste, formatWalletCopyText } from "@/lib/wallet-import";

interface ReferralWallet {
  id: string;
  cryptocurrency: string;
  wallet_address: string;
  label: string | null;
  is_primary: boolean;
  created_at: string;
}

export default function AccountContent() {
  const { signedIn, profile, loading, signOut, refreshProfile } = useAuth();
  const [editing, setEditing] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [walletAddress, setWalletAddress] = useState("");
  const [payoutCrypto, setPayoutCrypto] = useState("USDT");
  const [notifEmail, setNotifEmail] = useState(true);
  const [notifSms, setNotifSms] = useState(true);
  const [webhookUrl, setWebhookUrl] = useState("");
  const [saving, setSaving] = useState(false);
  const [copied, setCopied] = useState(false);
  const [walletPasteOpen, setWalletPasteOpen] = useState(false);
  const [walletPasteText, setWalletPasteText] = useState("");
  const [walletImportResult, setWalletImportResult] = useState<{
    imported: Array<{ coin: string; address: string; action: string }>;
    errors: string[];
  } | null>(null);
  const [referralWallets, setReferralWallets] = useState<ReferralWallet[]>([]);
  const [loadingWallets, setLoadingWallets] = useState(false);

  const fetchReferralWallets = useCallback(async () => {
    const token = localStorage.getItem("tc_access_token");
    if (!token) return;
    setLoadingWallets(true);
    try {
      const res = await fetch("/api/referrals/import-wallets", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setReferralWallets(data.wallets || []);
      }
    } catch {
      // ignore
    } finally {
      setLoadingWallets(false);
    }
  }, []);

  useEffect(() => {
    fetchReferralWallets();
  }, [fetchReferralWallets]);

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

  if (!signedIn) {
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
        headers: authHeaders({ "Content-Type": "application/json" }),
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

  const handleWalletImport = async () => {
    const parsed = parseWalletPaste(walletPasteText);
    if (parsed.wallets.length === 0) {
      setWalletImportResult({ imported: [], errors: ["No valid wallet addresses found. Use CoinPay 'Copy All Addresses' format."] });
      return;
    }

    try {
      const token = localStorage.getItem("tc_access_token");
      const res = await fetch("/api/referrals/import-wallets", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ paste_text: walletPasteText }),
      });

      const data = await res.json();

      if (!res.ok) {
        setWalletImportResult({
          imported: [],
          errors: [data.error || "Import failed"],
        });
        return;
      }

      setWalletImportResult({
        imported: data.imported || [],
        errors: data.errors?.map((e: { coin: string; error: string }) => `${e.coin}: ${e.error}`) || [],
      });

      setWalletPasteText("");
      setWalletPasteOpen(false);
      await fetchReferralWallets();
    } catch {
      setWalletImportResult({ imported: [], errors: ["Network error during import"] });
    }
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
                  <span className="text-sm text-tc-text-dim">Payout Wallets</span>
                  {loadingWallets ? (
                    <p className="text-tc-text-dim text-xs mt-1">Loading...</p>
                  ) : referralWallets.length > 0 ? (
                    <div className="space-y-1 mt-1">
                      {referralWallets.slice(0, 3).map((w) => (
                        <p key={w.cryptocurrency} className="text-white text-xs font-mono flex items-center gap-1">
                          <span className="text-tc-green font-bold w-20 shrink-0">{w.cryptocurrency}</span>
                          <span className="truncate">{w.wallet_address}</span>
                          {w.is_primary && <span className="text-[10px] bg-tc-green/10 text-tc-green px-1 rounded">★</span>}
                        </p>
                      ))}
                      {referralWallets.length > 3 && (
                        <p className="text-tc-text-dim text-xs">+{referralWallets.length - 3} more</p>
                      )}
                    </div>
                  ) : (
                    <p className="text-white text-xs mt-1">None — import below</p>
                  )}
                </div>
              </div>

              {/* Bulk Wallet Import */}
              <div className="mt-4 border-t border-tc-border pt-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-semibold text-white">Wallet Addresses</h3>
                  <button
                    type="button"
                    onClick={() => setWalletPasteOpen(!walletPasteOpen)}
                    className="text-xs text-tc-green hover:underline"
                  >
                    {walletPasteOpen ? "▲ Close" : "📋 Import from CoinPay"}
                  </button>
                </div>

                {walletPasteOpen && (
                  <div>
                    <textarea
                      value={walletPasteText}
                      onChange={(e) => setWalletPasteText(e.target.value)}
                      placeholder={`Paste from CoinPay "Copy All Addresses":\nBTC: bc1q...\nETH: 0x...\nUSDC_SOL: FX8Q...\nUSDC_POL: 0x...`}
                      rows={5}
                      className="w-full rounded-lg border border-tc-border bg-tc-darker px-3 py-2 text-white placeholder:text-tc-text-dim/50 focus:outline-none focus:border-tc-green/50 font-mono text-xs"
                    />
                    <div className="flex gap-2 mt-2">
                      <button
                        type="button"
                        onClick={handleWalletImport}
                        disabled={!walletPasteText.trim()}
                        className="bg-tc-green text-black px-4 py-1.5 rounded-lg text-sm font-semibold hover:bg-tc-green-dim disabled:opacity-40 disabled:cursor-not-allowed"
                      >
                        Import All Wallets
                      </button>
                      <button
                        type="button"
                        onClick={() => { setWalletPasteOpen(false); setWalletPasteText(""); setWalletImportResult(null); }}
                        className="text-tc-text-dim text-sm hover:text-white"
                      >
                        Cancel
                      </button>
                    </div>
                    {walletImportResult && (
                      <div className="mt-2 text-xs">
                        {walletImportResult.imported.length > 0 && (
                          <div className="text-tc-green">
                            ✅ Imported {walletImportResult.imported.length} wallet(s):
                            {walletImportResult.imported.map((w, i) => (
                              <span key={i} className="inline-block mr-2 mt-1 px-2 py-0.5 bg-tc-green/10 rounded font-mono">
                                {w.coin}: {w.address.slice(0, 8)}…{w.address.slice(-6)}
                              </span>
                            ))}
                          </div>
                        )}
                        {walletImportResult.errors.length > 0 && (
                          <div className="text-red-400 mt-1">
                            ❌ {walletImportResult.errors.join(", ")}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
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
