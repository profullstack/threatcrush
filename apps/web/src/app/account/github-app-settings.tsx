"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import { authHeaders } from "@/lib/auth-client";

type Installation = {
  installation_id: number;
  account_login: string | null;
  account_type: string | null;
  repository_selection: string | null;
  status: string;
  announce: boolean;
  installed_at: string | null;
};

const linkClass = "text-tc-green underline underline-offset-4 hover:opacity-80";

/**
 * The GitHub App's per-installation settings. One switch today: whether the
 * findings from the installation's public repositories are announced on
 * /discovery. On by default.
 */
export default function GitHubAppSettings() {
  const { signedIn } = useAuth();
  const [installations, setInstallations] = useState<Installation[]>([]);
  const [githubLogin, setGithubLogin] = useState<string | null>(null);
  const [announceColumn, setAnnounceColumn] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch("/api/github/installations", { headers: authHeaders(), cache: "no-store" });
      if (!res.ok) return;
      const data = await res.json();
      setInstallations(data.installations ?? []);
      setGithubLogin(data.githubLogin ?? null);
      setAnnounceColumn(data.announceColumn !== false);
    } catch {
      // ignore
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    if (!signedIn) return;
    load();
  }, [signedIn, load]);

  async function toggle(installation: Installation) {
    setBusy(installation.installation_id);
    setError(null);
    try {
      const res = await fetch("/api/github/installations", {
        method: "PATCH",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          installation_id: installation.installation_id,
          announce: !installation.announce,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || "Could not save");
        return;
      }
      setInstallations((list) =>
        list.map((i) => (i.installation_id === installation.installation_id ? data.installation : i))
      );
    } catch {
      setError("Could not save");
    } finally {
      setBusy(null);
    }
  }

  if (!signedIn || !loaded) return null;

  return (
    <section className="mx-auto max-w-3xl px-6 pb-16">
      <div className="rounded-lg border border-tc-green/20 bg-black/40 p-6">
        <p className="font-mono-green text-xs uppercase tracking-widest">// github app</p>
        <h2 className="mt-2 text-xl font-semibold text-tc-text">Scan announcements</h2>
        <p className="mt-2 text-sm text-tc-text-dim">
          Findings the ThreatCrush GitHub App makes in your <em>public</em> repositories are
          announced on{" "}
          <Link href="/discovery" className={linkClass}>
            Discovery
          </Link>{" "}
          and in the OpenThreat descriptor, on by default. Private repositories are never
          announced. Turn it off per installation here.
        </p>

        {!githubLogin ? (
          <p className="mt-4 text-sm text-tc-text-dim">
            Sign in with GitHub to see the installations you manage. An email sign-in has no
            GitHub login to match against.
          </p>
        ) : installations.length === 0 ? (
          <p className="mt-4 text-sm text-tc-text-dim">
            No installations found for <span className="font-mono text-tc-green">@{githubLogin}</span>.
            Installations show here when the app was installed on your account, or by you on an
            organisation.
          </p>
        ) : (
          <ul className="mt-4 divide-y divide-tc-green/10">
            {installations.map((i) => (
              <li key={i.installation_id} className="flex items-center justify-between gap-4 py-3">
                <div>
                  <div className="font-mono text-tc-text">
                    {i.account_login ?? `installation ${i.installation_id}`}
                    {i.account_type ? (
                      <span className="ml-2 text-xs text-tc-text-dim">{i.account_type}</span>
                    ) : null}
                  </div>
                  <div className="text-xs text-tc-text-dim">
                    {i.repository_selection === "all" ? "all repositories" : "selected repositories"}
                    {" · "}
                    {i.status}
                  </div>
                </div>
                <button
                  type="button"
                  disabled={busy === i.installation_id || !announceColumn}
                  onClick={() => toggle(i)}
                  aria-pressed={i.announce}
                  className={`rounded border px-3 py-1.5 font-mono text-xs uppercase tracking-wide transition ${
                    i.announce
                      ? "border-tc-green bg-tc-green/10 text-tc-green"
                      : "border-tc-text-dim/40 text-tc-text-dim"
                  } disabled:opacity-50`}
                >
                  {i.announce ? "announce: on" : "announce: off"}
                </button>
              </li>
            ))}
          </ul>
        )}

        {!announceColumn && (
          <p className="mt-3 text-xs text-tc-text-dim">
            The announce setting is not available on this deployment yet; every installation
            announces its public findings until it is.
          </p>
        )}
        {error && <p className="mt-3 text-sm text-red-400">{error}</p>}
      </div>
    </section>
  );
}
