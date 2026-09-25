"use client";

import { useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { authHeaders } from "@/lib/auth-client";

type BlockingOrg = { id: string; name: string; slug: string };

const linkClass = "text-tc-green underline underline-offset-4 hover:opacity-80";
const inputClass =
  "w-full bg-tc-darker border border-tc-border rounded-lg px-3 py-2 text-white focus:outline-none focus:border-red-400/60";

/**
 * Self-serve account deletion. Confirmed with the account password, or for
 * accounts without one (GitHub sign-in) by typing the account email.
 */
export default function DeleteAccount() {
  const { signedIn, profile, signOut } = useAuth();
  // null = confirmation form closed; otherwise whether the account has a password.
  const [hasPassword, setHasPassword] = useState<boolean | null>(null);
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [blockingOrgs, setBlockingOrgs] = useState<BlockingOrg[]>([]);

  if (!signedIn) return null;

  async function open() {
    setError(null);
    setBusy(true);
    try {
      const res = await fetch("/api/auth/me", { headers: authHeaders(), cache: "no-store" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || "Could not load your account");
        return;
      }
      setHasPassword(data.has_password !== false);
    } catch {
      setError("Could not load your account");
    } finally {
      setBusy(false);
    }
  }

  function close() {
    setHasPassword(null);
    setConfirmation("");
    setError(null);
    setBlockingOrgs([]);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBlockingOrgs([]);
    setBusy(true);
    try {
      const res = await fetch("/api/auth/me", {
        method: "DELETE",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(hasPassword ? { password: confirmation } : { confirm_email: confirmation }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || "Could not delete your account");
        setBlockingOrgs(Array.isArray(data.organizations) ? data.organizations : []);
        return;
      }
      await signOut();
      window.location.href = "/";
    } catch {
      setError("Could not delete your account");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="mx-auto max-w-3xl px-6 pb-16">
      <div className="rounded-lg border border-red-500/30 bg-black/40 p-6">
        <p className="font-mono text-xs uppercase tracking-widest text-red-400">// danger zone</p>
        <h2 className="mt-2 text-xl font-semibold text-tc-text">Delete account</h2>
        <p className="mt-2 text-sm text-tc-text-dim">
          Permanently deletes your account and profile, and every organization where you are the
          only member, with its servers, detections and alert settings. Organizations you share
          with others are kept; if you are their only owner, make another member an owner first.
          This cannot be undone.
        </p>

        {hasPassword === null ? (
          <button
            type="button"
            onClick={open}
            disabled={busy}
            className="mt-4 rounded-lg border border-red-500/40 px-4 py-2 text-sm text-red-400 transition-colors hover:bg-red-500/10 disabled:opacity-50"
          >
            Delete account…
          </button>
        ) : (
          <form onSubmit={submit} className="mt-4 space-y-3">
            <label className="block text-sm text-tc-text-dim" htmlFor="delete-account-confirmation">
              {hasPassword ? (
                "Enter your password to confirm"
              ) : (
                <>
                  Type <span className="font-mono text-tc-text">{profile?.email}</span> to confirm
                </>
              )}
            </label>
            <input
              id="delete-account-confirmation"
              type={hasPassword ? "password" : "email"}
              autoComplete={hasPassword ? "current-password" : "off"}
              value={confirmation}
              onChange={(e) => setConfirmation(e.target.value)}
              className={inputClass}
              required
            />
            <div className="flex flex-wrap gap-3">
              <button
                type="submit"
                disabled={busy || !confirmation}
                className="rounded-lg bg-red-500 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-red-600 disabled:opacity-50"
              >
                {busy ? "Deleting…" : "Permanently delete account"}
              </button>
              <button
                type="button"
                onClick={close}
                disabled={busy}
                className="rounded-lg border border-tc-border px-4 py-2 text-sm text-tc-text-dim hover:text-tc-text disabled:opacity-50"
              >
                Cancel
              </button>
            </div>
          </form>
        )}

        {error && (
          <div role="alert" className="mt-3 text-sm text-red-400">
            <p>{error}</p>
            {blockingOrgs.length > 0 && (
              <ul className="mt-2 list-disc pl-5">
                {blockingOrgs.map((org) => (
                  <li key={org.id}>
                    <Link href={`/org/${org.slug}/settings`} className={linkClass}>
                      {org.name} settings
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
