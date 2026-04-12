"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations, createServer } from "@/lib/organizations";
import Link from "next/link";

export default function NewServerContent({ orgSlug }: { orgSlug: string }) {
  const router = useRouter();
  const { signedIn, loading: authLoading } = useAuth();
  const [orgId, setOrgId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const [formData, setFormData] = useState({
    name: "",
    hostname: "",
    ip_address: "",
    port: "22",
    ssh_username: "",
  });

  // Resolve org on mount
  useEffect(() => {
    if (!signedIn || authLoading) return;

    listOrganizations()
      .then(({ organizations }) => {
        const typedOrgs = organizations as unknown as Array<{ id: string; slug: string }>;
        const found = typedOrgs.find((o) => o.slug === orgSlug);
        if (found) setOrgId(found.id);
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
      const { server } = await createServer(orgId, {
        name: formData.name,
        hostname: formData.hostname || undefined,
        ip_address: formData.ip_address || undefined,
        port: parseInt(formData.port, 10) || 22,
        ssh_username: formData.ssh_username || undefined,
      });
      router.push(`/org/${orgSlug}/servers/${server.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create server");
    } finally {
      setSubmitting(false);
    }
  };

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
          <p className="text-zinc-400 mb-6">{error || "You don't have access to this organization."}</p>
          <Link href="/dashboard" className="text-green-500 hover:underline">
            ← Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-2xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Breadcrumb */}
        <div className="mb-8">
          <div className="flex items-center gap-3">
            <Link href={`/org/${orgSlug}`} className="text-zinc-500 hover:text-zinc-300 transition-colors">
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
            </Link>
            <div>
              <h1 className="text-2xl font-bold text-white">Add Server</h1>
              <p className="text-sm text-zinc-500">Register a new threatcrushd instance</p>
            </div>
          </div>
        </div>

        {error && (
          <div className="mb-6 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Name */}
          <div>
            <label htmlFor="server-name" className="block text-sm font-medium text-zinc-300 mb-1">
              Server Name <span className="text-red-400">*</span>
            </label>
            <input
              id="server-name"
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="prod-web-1"
              required
              className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-white placeholder-zinc-500 focus:border-green-500 focus:outline-none focus:ring-1 focus:ring-green-500"
            />
          </div>

          {/* Hostname / IP */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label htmlFor="server-hostname" className="block text-sm font-medium text-zinc-300 mb-1">
                Hostname
              </label>
              <input
                id="server-hostname"
                type="text"
                value={formData.hostname}
                onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
                placeholder="server.example.com"
                className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-white placeholder-zinc-500 focus:border-green-500 focus:outline-none focus:ring-1 focus:ring-green-500"
              />
            </div>
            <div>
              <label htmlFor="server-ip" className="block text-sm font-medium text-zinc-300 mb-1">
                IP Address
              </label>
              <input
                id="server-ip"
                type="text"
                value={formData.ip_address}
                onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
                placeholder="192.168.1.100"
                className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-white placeholder-zinc-500 focus:border-green-500 focus:outline-none focus:ring-1 focus:ring-green-500"
              />
            </div>
          </div>
          <p className="text-xs text-zinc-500 -mt-4">
            At least one of hostname or IP address is required.
          </p>

          {/* Port + SSH Username */}
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <label htmlFor="server-port" className="block text-sm font-medium text-zinc-300 mb-1">
                SSH Port
              </label>
              <input
                id="server-port"
                type="number"
                value={formData.port}
                onChange={(e) => setFormData({ ...formData, port: e.target.value })}
                placeholder="22"
                min={1}
                max={65535}
                className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-white placeholder-zinc-500 focus:border-green-500 focus:outline-none focus:ring-1 focus:ring-green-500"
              />
            </div>
            <div>
              <label htmlFor="server-ssh-user" className="block text-sm font-medium text-zinc-300 mb-1">
                SSH Username
              </label>
              <input
                id="server-ssh-user"
                type="text"
                value={formData.ssh_username}
                onChange={(e) => setFormData({ ...formData, ssh_username: e.target.value })}
                placeholder="root"
                className="w-full rounded-lg bg-zinc-800 border border-zinc-700 px-3 py-2 text-white placeholder-zinc-500 focus:border-green-500 focus:outline-none focus:ring-1 focus:ring-green-500"
              />
            </div>
          </div>

          {/* Info callout */}
          <div className="rounded-lg bg-blue-500/5 border border-blue-500/20 p-4">
            <p className="text-sm text-blue-400/70">
              <strong className="text-blue-300">How connecting works:</strong>
              <br />
              The web app stores this server's metadata. To actually connect and manage the server,
              use the <strong>Desktop app</strong> or <strong>CLI</strong>, which use your{" "}
              <code className="bg-blue-500/10 px-1 rounded">~/.ssh</code> keys for SSH access.
            </p>
          </div>

          {/* Submit */}
          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={submitting || !formData.name || (!formData.hostname && !formData.ip_address)}
              className="rounded-lg px-6 py-2.5 text-sm font-medium text-black bg-green-500 hover:bg-green-400 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {submitting ? "Adding..." : "Add Server"}
            </button>
            <Link
              href={`/org/${orgSlug}`}
              className="rounded-lg px-4 py-2.5 text-sm font-medium text-zinc-300 hover:text-white transition-colors"
            >
              Cancel
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}
