"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useAuth } from "@/lib/auth-context";
import {
  deleteProperty,
  listOrganizations,
  listProperties,
  type Property,
} from "@/lib/organizations";

const KIND_LABEL: Record<Property["kind"], string> = {
  url: "URL",
  api: "API",
  domain: "Domain",
  ip: "IP",
  repo: "Repo",
};

const KIND_COLOR: Record<Property["kind"], string> = {
  url: "bg-blue-500/10 text-blue-400",
  api: "bg-purple-500/10 text-purple-400",
  domain: "bg-cyan-500/10 text-cyan-400",
  ip: "bg-yellow-500/10 text-yellow-400",
  repo: "bg-pink-500/10 text-pink-400",
};

export default function PropertiesContent({ orgSlug }: { orgSlug: string }) {
  const { signedIn, loading: authLoading } = useAuth();
  const [orgId, setOrgId] = useState<string | null>(null);
  const [orgName, setOrgName] = useState("");
  const [properties, setProperties] = useState<Property[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (authLoading || !signedIn) return;

    let active = true;
    (async () => {
      try {
        const { organizations } = await listOrganizations();
        if (!active) return;
        const typed = organizations as unknown as Array<{ id: string; slug: string; name: string }>;
        const org = typed.find((o) => o.slug === orgSlug);
        if (!org) {
          setError("Organization not found");
          setLoading(false);
          return;
        }
        setOrgId(org.id);
        setOrgName(org.name);

        const { properties } = await listProperties(org.id);
        if (!active) return;
        setProperties(properties);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load properties");
      } finally {
        if (active) setLoading(false);
      }
    })();

    return () => { active = false; };
  }, [signedIn, authLoading, orgSlug]);

  const handleDelete = async (property: Property) => {
    if (!orgId) return;
    if (!confirm(`Delete property "${property.name}"?`)) return;
    try {
      await deleteProperty(orgId, property.id);
      setProperties((prev) => prev.filter((p) => p.id !== property.id));
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to delete");
    }
  };

  if (authLoading || loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-zinc-400">Loading...</div>
      </div>
    );
  }

  if (!signedIn) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-center max-w-md px-4">
          <h1 className="text-xl font-bold text-white mb-2">Sign in required</h1>
          <Link href="/auth/login" className="text-green-500 hover:underline">Go to login →</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-5xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <Link href={`/org/${orgSlug}`} className="mt-1 text-zinc-500 hover:text-zinc-300">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-white">Properties</h1>
              <p className="text-sm text-zinc-500">
                Targets ThreatCrush can scan, pentest, and monitor for {orgName || orgSlug}.
              </p>
            </div>
          </div>
          <Link
            href={`/org/${orgSlug}/properties/new`}
            className="shrink-0 rounded-lg bg-green-500 px-4 py-2 text-sm font-medium text-black hover:bg-green-400"
          >
            + Add Property
          </Link>
        </div>

        {error && (
          <div className="mb-6 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {properties.length === 0 ? (
          <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-10 text-center">
            <div className="mx-auto mb-4 h-12 w-12 rounded-full bg-green-500/10 flex items-center justify-center">
              <svg className="h-6 w-6 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
            </div>
            <h2 className="text-lg font-semibold text-white">No properties yet</h2>
            <p className="mt-1 text-sm text-zinc-400">
              Add a URL, API endpoint, domain, IP/CIDR, or source repo so you can run scans against it.
            </p>
            <Link
              href={`/org/${orgSlug}/properties/new`}
              className="mt-4 inline-block rounded-lg bg-green-500 px-4 py-2 text-sm font-medium text-black hover:bg-green-400"
            >
              Add your first property
            </Link>
          </div>
        ) : (
          <div className="overflow-hidden rounded-lg border border-zinc-800">
            <table className="w-full divide-y divide-zinc-800">
              <thead className="bg-zinc-950 text-left text-xs uppercase tracking-wider text-zinc-500">
                <tr>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Kind</th>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">Tags</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800 bg-black">
                {properties.map((p) => (
                  <tr key={p.id} className="text-sm hover:bg-zinc-950/60">
                    <td className="px-4 py-3 font-medium text-white">
                      <Link href={`/org/${orgSlug}/properties/${p.id}`} className="hover:text-green-400">
                        {p.name}
                      </Link>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex rounded px-2 py-0.5 text-xs font-medium ${KIND_COLOR[p.kind]}`}>
                        {KIND_LABEL[p.kind]}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-zinc-400 break-all">{p.target}</td>
                    <td className="px-4 py-3">
                      {p.tags.length === 0 ? (
                        <span className="text-zinc-600">—</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {p.tags.map((t) => (
                            <span key={t} className="rounded bg-zinc-800 px-2 py-0.5 text-xs text-zinc-300">{t}</span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      {p.enabled ? (
                        <span className="text-green-400">● enabled</span>
                      ) : (
                        <span className="text-zinc-500">○ disabled</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => handleDelete(p)}
                        className="text-xs text-red-400 hover:text-red-300"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="mt-6 text-sm text-zinc-500">
          <p>
            Run them all from the CLI:{" "}
            <code className="rounded bg-zinc-900 px-2 py-0.5 text-zinc-300">threatcrush properties run</code>
          </p>
        </div>
      </div>
    </div>
  );
}
