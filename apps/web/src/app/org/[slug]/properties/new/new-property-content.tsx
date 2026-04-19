"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import {
  createProperty,
  listOrganizations,
  type PropertyKind,
} from "@/lib/organizations";

const KINDS: Array<{ value: PropertyKind; label: string; hint: string; placeholder: string }> = [
  { value: "url", label: "URL", hint: "A full URL endpoint we can pentest", placeholder: "https://api.example.com/login" },
  { value: "api", label: "API", hint: "A base API URL (we'll fuzz endpoints)", placeholder: "https://api.example.com" },
  { value: "domain", label: "Domain", hint: "Passive DNS / recon", placeholder: "example.com" },
  { value: "ip", label: "IP / CIDR", hint: "A host or CIDR range", placeholder: "203.0.113.10 or 10.0.0.0/24" },
  { value: "repo", label: "Repo / Path", hint: "Git URL or local path to scan", placeholder: "https://github.com/acme/backend" },
];

export default function NewPropertyContent({ orgSlug }: { orgSlug: string }) {
  const router = useRouter();
  const { signedIn, loading: authLoading } = useAuth();
  const [orgId, setOrgId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const [form, setForm] = useState({
    name: "",
    kind: "url" as PropertyKind,
    target: "",
    description: "",
    tags: "",
    enabled: true,
    schedule: "" as "" | "hourly" | "daily" | "weekly" | "monthly",
  });

  useEffect(() => {
    if (authLoading || !signedIn) return;

    listOrganizations()
      .then(({ organizations }) => {
        const typed = organizations as unknown as Array<{ id: string; slug: string }>;
        const org = typed.find((o) => o.slug === orgSlug);
        if (org) setOrgId(org.id);
        else setError("Organization not found");
      })
      .catch(() => setError("Failed to load organization"))
      .finally(() => setLoading(false));
  }, [signedIn, authLoading, orgSlug]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId) return;
    setError("");
    setSubmitting(true);
    try {
      await createProperty(orgId, {
        name: form.name.trim(),
        kind: form.kind,
        target: form.target.trim(),
        description: form.description.trim() || undefined,
        tags: form.tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean),
        enabled: form.enabled,
        schedule: form.schedule || null,
      });
      router.push(`/org/${orgSlug}/properties`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create property");
    } finally {
      setSubmitting(false);
    }
  };

  const kindMeta = KINDS.find((k) => k.value === form.kind)!;

  if (authLoading || loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-zinc-400">Loading...</div>
      </div>
    );
  }

  if (!orgId) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-center max-w-md px-4">
          <h1 className="text-xl font-bold text-white mb-2">Organization Not Found</h1>
          <p className="text-zinc-400 mb-6">{error}</p>
          <Link href="/dashboard" className="text-green-500 hover:underline">← Back to Dashboard</Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-2xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-start gap-3">
          <Link href={`/org/${orgSlug}/properties`} className="mt-1 text-zinc-500 hover:text-zinc-300">
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-white">Add Property</h1>
            <p className="text-sm text-zinc-500">A target we can scan, pentest, or monitor.</p>
          </div>
        </div>

        {error && (
          <div className="mb-6 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-sm font-medium text-zinc-300 mb-1">
              Name <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              required
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="prod-api"
              className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-white placeholder-zinc-500 focus:border-green-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-zinc-300 mb-1">Kind</label>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
              {KINDS.map((k) => (
                <button
                  key={k.value}
                  type="button"
                  onClick={() => setForm({ ...form, kind: k.value })}
                  className={`rounded-lg border px-3 py-2 text-sm ${
                    form.kind === k.value
                      ? "border-green-500 bg-green-500/10 text-green-300"
                      : "border-zinc-700 bg-zinc-900 text-zinc-300 hover:border-zinc-600"
                  }`}
                >
                  {k.label}
                </button>
              ))}
            </div>
            <p className="mt-2 text-xs text-zinc-500">{kindMeta.hint}</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-zinc-300 mb-1">
              Target <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              required
              value={form.target}
              onChange={(e) => setForm({ ...form, target: e.target.value })}
              placeholder={kindMeta.placeholder}
              className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-white placeholder-zinc-500 font-mono focus:border-green-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-zinc-300 mb-1">Tags</label>
            <input
              type="text"
              value={form.tags}
              onChange={(e) => setForm({ ...form, tags: e.target.value })}
              placeholder="prod, external, pci-dss"
              className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-white placeholder-zinc-500 focus:border-green-500 focus:outline-none"
            />
            <p className="mt-1 text-xs text-zinc-500">Comma-separated.</p>
          </div>

          <div>
            <label className="block text-sm font-medium text-zinc-300 mb-1">Description</label>
            <textarea
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              rows={3}
              className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-white placeholder-zinc-500 focus:border-green-500 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-zinc-300 mb-1">Schedule</label>
            <select
              value={form.schedule}
              onChange={(e) => setForm({ ...form, schedule: e.target.value as typeof form.schedule })}
              className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-white focus:border-green-500 focus:outline-none"
            >
              <option value="">No schedule (run manually)</option>
              <option value="hourly">Hourly</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
            <p className="mt-1 text-xs text-zinc-500">
              Any logged-in <code className="rounded bg-zinc-900 px-1">threatcrushd</code> daemon will pick up scheduled runs.
            </p>
          </div>

          <label className="flex items-center gap-2 text-sm text-zinc-300">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
              className="h-4 w-4 rounded border-zinc-600 bg-zinc-800 text-green-500 focus:ring-green-500"
            />
            Enabled (include in bulk scan/pentest runs)
          </label>

          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={submitting || !form.name || !form.target}
              className="rounded-lg px-6 py-2.5 text-sm font-medium text-black bg-green-500 hover:bg-green-400 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {submitting ? "Adding..." : "Add Property"}
            </button>
            <Link href={`/org/${orgSlug}/properties`} className="rounded-lg px-4 py-2.5 text-sm font-medium text-zinc-300 hover:text-white">
              Cancel
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}
