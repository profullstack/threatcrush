"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations } from "@/lib/organizations";
import OrgOnboarding from "@/components/OrgOnboarding";
import CreateOrgModal from "@/components/CreateOrgModal";
import Link from "next/link";
import FleetPanel from "./fleet-panel";

interface Organization {
  id: string;
  name: string;
  slug: string;
  user_role: string;
  created_at: string;
}

export default function DashboardContent() {
  const { signedIn, loading: authLoading, currentOrgId, setCurrentOrgId } = useAuth();
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreateOrg, setShowCreateOrg] = useState(false);
  const [error, setError] = useState("");

  const handleOrgCreated = async (org: Record<string, unknown>) => {
    const orgId = org.id as string;
    await setCurrentOrgId(orgId);
    setOrganizations(prev => [...prev, { ...org, user_role: "owner" } as Organization]);
    setShowCreateOrg(false);
  };

  useEffect(() => {
    if (!signedIn || authLoading) return;

    async function fetchData() {
      try {
        const { organizations: orgs } = await listOrganizations();
        const typedOrgs = orgs as unknown as Organization[];
        setOrganizations(typedOrgs);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load data");
      } finally {
        setLoading(false);
      }
    }

    fetchData();
  }, [signedIn, authLoading]);

  if (authLoading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-zinc-400">Loading...</div>
      </div>
    );
  }

  if (!signedIn) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-center">
          <h1 className="text-2xl font-bold text-white mb-2">Sign In Required</h1>
          <p className="text-zinc-400">
            Please <Link href="/auth/login" className="text-green-500 hover:underline">sign in</Link> to access your dashboard.
          </p>
        </div>
      </div>
    );
  }

  // If no organizations, show onboarding
  if (organizations.length === 0) {
    return <OrgOnboarding />;
  }

  if (loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-zinc-400">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-white">Dashboard</h1>
            <p className="text-zinc-400 mt-1">
              Your organizations and every ThreatCrush install across them
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowCreateOrg(true)}
              className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 transition-colors"
            >
              New Organization
            </button>
          </div>
        </div>

        {error && (
          <div className="mb-6 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {/* Organizations */}
        <div className="mb-8">
          <h2 className="text-lg font-semibold text-white mb-4">Your Organizations</h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {organizations.map((org) => (
              <Link
                key={org.id}
                href={`/org/${org.slug}`}
                className="block rounded-lg bg-zinc-900 border border-zinc-800 p-5 hover:border-zinc-700 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h3 className="text-base font-medium text-white">{org.name}</h3>
                    <p className="text-sm text-zinc-500 mt-1">{org.slug}</p>
                  </div>
                  <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                    org.user_role === "owner"
                      ? "bg-green-500/10 text-green-400"
                      : org.user_role === "admin"
                        ? "bg-blue-500/10 text-blue-400"
                        : "bg-zinc-700 text-zinc-400"
                  }`}>
                    {org.user_role}
                  </span>
                </div>
                <p className="text-xs text-zinc-500 mt-3">
                  Created {new Date(org.created_at).toLocaleDateString()}
                </p>
              </Link>
            ))}
          </div>
        </div>

        <FleetPanel addServerHref={`/org/${organizations.find(o => o.id === currentOrgId)?.slug || organizations[0].slug}/servers/new`} />
      </div>

      <CreateOrgModal
        isOpen={showCreateOrg}
        onClose={() => setShowCreateOrg(false)}
        onSuccess={handleOrgCreated}
      />
    </div>
  );
}
