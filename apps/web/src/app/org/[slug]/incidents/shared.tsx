"use client";

import { useEffect, useState } from "react";
import { listOrganizations } from "@/lib/organizations";
import { useAuth } from "@/lib/auth-context";

export interface OrgRef { id: string; name: string; slug: string; user_role?: string }

export const SEV_CLS: Record<string, string> = {
  critical: "bg-red-600 text-white", high: "bg-red-500/20 text-red-400", medium: "bg-yellow-500/20 text-yellow-400",
  low: "bg-blue-500/20 text-blue-400", info: "bg-zinc-700 text-zinc-300",
};
export const STATUS_CLS: Record<string, string> = {
  open: "text-red-400", acknowledged: "text-yellow-400", resolved: "text-green-400",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`rounded px-2 py-0.5 text-xs font-semibold uppercase ${SEV_CLS[severity] ?? SEV_CLS.info}`}>{severity}</span>;
}

export const when = (iso: string | null | undefined) => (iso ? new Date(iso).toLocaleString() : "");

/** The org for a slug, from the caller's org list (browser talks only to /api). */
export function useOrg(slug: string): { org: OrgRef | null; ready: boolean } {
  const { signedIn, loading } = useAuth();
  const [org, setOrg] = useState<OrgRef | null>(null);
  const [ready, setReady] = useState(false);
  useEffect(() => {
    if (loading) return;
    if (!signedIn) { setReady(true); return; }
    listOrganizations()
      .then(({ organizations }) => setOrg((organizations as unknown as OrgRef[]).find((o) => o.slug === slug) ?? null))
      .catch(() => setOrg(null))
      .finally(() => setReady(true));
  }, [signedIn, loading, slug]);
  return { org, ready };
}

export function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">{children}</div>
    </div>
  );
}

export function Centered({ text }: { text: string }) {
  return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">{text}</div></div>;
}
