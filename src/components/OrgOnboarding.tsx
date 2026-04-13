"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { createOrganization } from "@/lib/organizations";
import CreateOrgModal from "./CreateOrgModal";

export default function OrgOnboarding() {
  const { setCurrentOrgId } = useAuth();
  const [showModal, setShowModal] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const router = useRouter();

  const handleQuickCreate = async () => {
    setError("");
    setLoading(true);
    try {
      const { organization } = await createOrganization("My Organization");
      await setCurrentOrgId(organization.id as string);
      router.push(`/org/${organization.slug}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create organization");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-black flex items-center justify-center px-4">
      <div className="max-w-lg w-full text-center">
        {/* Logo / Icon */}
        <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full bg-green-500/10 border border-green-500/20">
          <svg
            className="h-8 w-8 text-green-500"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"
            />
          </svg>
        </div>

        <h1 className="text-2xl font-bold text-white mb-2">
          Welcome to ThreatCrush
        </h1>
        <p className="text-zinc-400 mb-8">
          Get started by creating your first organization. Organizations let you group
          and manage servers with your team.
        </p>

        <div className="space-y-4">
          {/* Quick create */}
          <button
            onClick={handleQuickCreate}
            disabled={loading}
            className="w-full rounded-lg px-6 py-3 text-sm font-medium text-black bg-green-500 hover:bg-green-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
          >
            {loading ? "Creating..." : "Create your first organization"}
          </button>

          {/* Custom name */}
          <button
            onClick={() => setShowModal(true)}
            className="w-full rounded-lg px-6 py-3 text-sm font-medium text-zinc-300 bg-zinc-800 border border-zinc-700 hover:bg-zinc-700 transition-all"
          >
            Create with custom name
          </button>
        </div>

        {error && (
          <p className="text-sm text-red-400 mt-4">{error}</p>
        )}

        {/* Info cards */}
        <div className="mt-12 grid grid-cols-1 gap-4 text-left">
          <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4">
            <div className="flex items-start gap-3">
              <div className="flex-shrink-0 mt-0.5">
                <svg className="h-5 w-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01" />
                </svg>
              </div>
              <div>
                <h3 className="text-sm font-medium text-white">Manage Servers</h3>
                <p className="text-sm text-zinc-400 mt-1">
                  Add and monitor your ThreatCrushd instances from a central dashboard.
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4">
            <div className="flex items-start gap-3">
              <div className="flex-shrink-0 mt-0.5">
                <svg className="h-5 w-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                </svg>
              </div>
              <div>
                <h3 className="text-sm font-medium text-white">Invite Your Team</h3>
                <p className="text-sm text-zinc-400 mt-1">
                  Add members with different roles: owner, admin, or member.
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4">
            <div className="flex items-start gap-3">
              <div className="flex-shrink-0 mt-0.5">
                <svg className="h-5 w-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                </svg>
              </div>
              <div>
                <h3 className="text-sm font-medium text-white">Connect via CLI or Desktop</h3>
                <p className="text-sm text-zinc-400 mt-1">
                  Use the CLI or desktop app to connect to servers via SSH for real-time management.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <CreateOrgModal
        isOpen={showModal}
        onClose={() => setShowModal(false)}
        onSuccess={async (org) => {
          await setCurrentOrgId(org.id as string);
          router.push(`/org/${org.slug}`);
        }}
      />
    </div>
  );
}
