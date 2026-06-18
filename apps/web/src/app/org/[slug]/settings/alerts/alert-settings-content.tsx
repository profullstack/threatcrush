"use client";

import { useEffect, useState, useCallback } from "react";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations } from "@/lib/organizations";
import { authHeaders } from "@/lib/auth-client";
import Link from "next/link";

interface AlertDestination {
  id: string;
  name: string;
  type: string;
  enabled: boolean;
  created_at: string;
}

interface AlertRule {
  id: string;
  name: string;
  min_severity: string;
  server_scope: string[];
  destination_id: string;
  rate_limit_per_hour: number;
  enabled: boolean;
}

interface Organization { id: string; name: string; slug: string; }

const DEST_TYPES = [
  { value: "slack", label: "Slack", fields: [{ key: "webhook_url", label: "Webhook URL", type: "url" }] },
  { value: "discord", label: "Discord", fields: [{ key: "webhook_url", label: "Webhook URL", type: "url" }] },
  { value: "email", label: "Email", fields: [{ key: "to", label: "To Address", type: "email" }, { key: "host", label: "SMTP Host", type: "text" }, { key: "from", label: "From Address", type: "email" }] },
  { value: "webhook", label: "Webhook", fields: [{ key: "url", label: "URL", type: "url" }, { key: "secret", label: "Secret (optional)", type: "text" }] },
  { value: "pagerduty", label: "PagerDuty", fields: [{ key: "routing_key", label: "Routing Key", type: "text" }] },
];

export default function AlertSettingsContent({ slug }: { slug: string }) {
  const { signedIn, loading: authLoading } = useAuth();
  const [org, setOrg] = useState<Organization | null>(null);
  const [destinations, setDestinations] = useState<AlertDestination[]>([]);
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<"destinations" | "rules">("destinations");

  // Add destination form
  const [showAddDest, setShowAddDest] = useState(false);
  const [newDestName, setNewDestName] = useState("");
  const [newDestType, setNewDestType] = useState("slack");
  const [newDestConfig, setNewDestConfig] = useState<Record<string, string>>({});

  // Add rule form
  const [showAddRule, setShowAddRule] = useState(false);
  const [newRuleName, setNewRuleName] = useState("");
  const [newRuleSeverity, setNewRuleSeverity] = useState("high");
  const [newRuleDestId, setNewRuleDestId] = useState("");

  const fetchData = useCallback(async (orgId: string) => {
    const [destRes, rulesRes] = await Promise.all([
      fetch(`/api/orgs/${orgId}/alert-destinations`, { headers: authHeaders() }),
      fetch(`/api/orgs/${orgId}/alert-rules`, { headers: authHeaders() }),
    ]);
    if (destRes.ok) { const d = await destRes.json(); setDestinations(d.destinations || []); }
    if (rulesRes.ok) { const d = await rulesRes.json(); setRules(d.rules || []); }
  }, []);

  useEffect(() => {
    if (!signedIn || authLoading) return;
    (async () => {
      try {
        const { organizations } = await listOrganizations();
        const found = (organizations as unknown as Organization[]).find(o => o.slug === slug);
        if (!found) return;
        setOrg(found);
        await fetchData(found.id);
      } catch { /* ignore */ }
      finally { setLoading(false); }
    })();
  }, [signedIn, authLoading, slug, fetchData]);

  const addDestination = async () => {
    if (!org || !newDestName || !newDestType) return;
    await fetch(`/api/orgs/${org.id}/alert-destinations`, {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ name: newDestName, type: newDestType, config: newDestConfig }),
    });
    setShowAddDest(false);
    setNewDestName("");
    setNewDestConfig({});
    await fetchData(org.id);
  };

  const deleteDest = async (destId: string) => {
    if (!org) return;
    await fetch(`/api/orgs/${org.id}/alert-destinations/${destId}`, {
      method: "DELETE", headers: authHeaders(),
    });
    await fetchData(org.id);
  };

  const testDest = async (destId: string) => {
    if (!org) return;
    const res = await fetch(`/api/orgs/${org.id}/alert-destinations/${destId}`, {
      method: "POST", headers: authHeaders(),
    });
    const data = await res.json();
    alert(data.success ? "Test alert sent!" : `Test failed: ${data.error || "Unknown error"}`);
  };

  const addRule = async () => {
    if (!org || !newRuleName || !newRuleDestId) return;
    await fetch(`/api/orgs/${org.id}/alert-rules`, {
      method: "POST",
      headers: { ...authHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ name: newRuleName, min_severity: newRuleSeverity, destination_id: newRuleDestId }),
    });
    setShowAddRule(false);
    setNewRuleName("");
    await fetchData(org.id);
  };

  const deleteRule = async (ruleId: string) => {
    if (!org) return;
    await fetch(`/api/orgs/${org.id}/alert-rules?rule_id=${ruleId}`, {
      method: "DELETE", headers: authHeaders(),
    });
    await fetchData(org.id);
  };

  if (authLoading || loading) {
    return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Loading...</div></div>;
  }
  if (!org) {
    return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">Organization not found</div></div>;
  }

  const selectedType = DEST_TYPES.find(t => t.value === newDestType);

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="flex items-center gap-3 mb-6">
          <Link href={`/org/${slug}/settings`} className="text-zinc-500 hover:text-zinc-300">
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <div>
            <h1 className="text-2xl font-bold text-white">Alert Settings</h1>
            <p className="text-sm text-zinc-500">{org.name}</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 bg-zinc-900 rounded-lg p-1 w-fit border border-zinc-800">
          <button onClick={() => setTab("destinations")}
            className={`px-4 py-2 rounded-md text-sm font-medium ${tab === "destinations" ? "bg-zinc-700 text-white" : "text-zinc-400 hover:text-zinc-300"}`}>
            Destinations ({destinations.length})
          </button>
          <button onClick={() => setTab("rules")}
            className={`px-4 py-2 rounded-md text-sm font-medium ${tab === "rules" ? "bg-zinc-700 text-white" : "text-zinc-400 hover:text-zinc-300"}`}>
            Rules ({rules.length})
          </button>
        </div>

        {/* Destinations */}
        {tab === "destinations" && (
          <div>
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-lg font-semibold text-white">Alert Destinations</h2>
              <button onClick={() => setShowAddDest(!showAddDest)}
                className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400">
                Add Destination
              </button>
            </div>

            {showAddDest && (
              <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4 mb-4 space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <input value={newDestName} onChange={e => setNewDestName(e.target.value)} placeholder="Destination name"
                    className="rounded-lg bg-zinc-800 border border-zinc-700 text-white px-3 py-2 text-sm" />
                  <select value={newDestType} onChange={e => { setNewDestType(e.target.value); setNewDestConfig({}); }}
                    className="rounded-lg bg-zinc-800 border border-zinc-700 text-zinc-300 px-3 py-2 text-sm">
                    {DEST_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                  </select>
                </div>
                {selectedType?.fields.map(f => (
                  <input key={f.key} value={newDestConfig[f.key] || ""} onChange={e => setNewDestConfig({ ...newDestConfig, [f.key]: e.target.value })}
                    placeholder={f.label} type={f.type}
                    className="w-full rounded-lg bg-zinc-800 border border-zinc-700 text-white px-3 py-2 text-sm" />
                ))}
                <div className="flex gap-2 justify-end">
                  <button onClick={() => setShowAddDest(false)} className="rounded-lg px-4 py-2 text-sm text-zinc-400 hover:text-zinc-300">Cancel</button>
                  <button onClick={addDestination} disabled={!newDestName}
                    className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 disabled:opacity-40">Save</button>
                </div>
              </div>
            )}

            <div className="space-y-3">
              {destinations.length === 0 ? (
                <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-8 text-center">
                  <p className="text-zinc-400">No alert destinations configured</p>
                  <p className="text-zinc-600 text-sm mt-1">Add Slack, Discord, PagerDuty, or webhook destinations to receive alerts.</p>
                </div>
              ) : destinations.map(d => (
                <div key={d.id} className="rounded-lg bg-zinc-900 border border-zinc-800 p-4 flex items-center justify-between">
                  <div>
                    <span className="text-white font-medium">{d.name}</span>
                    <span className="text-zinc-500 text-sm ml-2 capitalize">{d.type}</span>
                    <span className={`text-xs ml-2 ${d.enabled ? "text-green-400" : "text-zinc-600"}`}>
                      {d.enabled ? "Active" : "Disabled"}
                    </span>
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => testDest(d.id)}
                      className="rounded px-3 py-1 text-xs bg-zinc-800 text-blue-400 border border-zinc-700 hover:bg-zinc-700">Test</button>
                    <button onClick={() => deleteDest(d.id)}
                      className="rounded px-3 py-1 text-xs bg-zinc-800 text-red-400 border border-zinc-700 hover:bg-zinc-700">Delete</button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Rules */}
        {tab === "rules" && (
          <div>
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-lg font-semibold text-white">Alert Rules</h2>
              <button onClick={() => setShowAddRule(!showAddRule)} disabled={destinations.length === 0}
                className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 disabled:opacity-40">
                Add Rule
              </button>
            </div>

            {destinations.length === 0 && (
              <div className="rounded-lg bg-yellow-500/10 border border-yellow-500/20 p-4 mb-4 text-sm text-yellow-400">
                Add a destination first before creating alert rules.
              </div>
            )}

            {showAddRule && (
              <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-4 mb-4 space-y-3">
                <input value={newRuleName} onChange={e => setNewRuleName(e.target.value)} placeholder="Rule name"
                  className="w-full rounded-lg bg-zinc-800 border border-zinc-700 text-white px-3 py-2 text-sm" />
                <div className="grid grid-cols-2 gap-3">
                  <select value={newRuleSeverity} onChange={e => setNewRuleSeverity(e.target.value)}
                    className="rounded-lg bg-zinc-800 border border-zinc-700 text-zinc-300 px-3 py-2 text-sm">
                    <option value="info">Info and above</option>
                    <option value="low">Low and above</option>
                    <option value="medium">Medium and above</option>
                    <option value="high">High and above</option>
                    <option value="critical">Critical only</option>
                  </select>
                  <select value={newRuleDestId} onChange={e => setNewRuleDestId(e.target.value)}
                    className="rounded-lg bg-zinc-800 border border-zinc-700 text-zinc-300 px-3 py-2 text-sm">
                    <option value="">Select destination...</option>
                    {destinations.map(d => <option key={d.id} value={d.id}>{d.name} ({d.type})</option>)}
                  </select>
                </div>
                <div className="flex gap-2 justify-end">
                  <button onClick={() => setShowAddRule(false)} className="rounded-lg px-4 py-2 text-sm text-zinc-400">Cancel</button>
                  <button onClick={addRule} disabled={!newRuleName || !newRuleDestId}
                    className="rounded-lg px-4 py-2 text-sm font-medium text-black bg-green-500 hover:bg-green-400 disabled:opacity-40">Save</button>
                </div>
              </div>
            )}

            <div className="space-y-3">
              {rules.length === 0 ? (
                <div className="rounded-lg bg-zinc-900 border border-zinc-800 p-8 text-center">
                  <p className="text-zinc-400">No alert rules configured</p>
                  <p className="text-zinc-600 text-sm mt-1">Rules route detections to destinations based on severity and server scope.</p>
                </div>
              ) : rules.map(r => (
                <div key={r.id} className="rounded-lg bg-zinc-900 border border-zinc-800 p-4 flex items-center justify-between">
                  <div>
                    <span className="text-white font-medium">{r.name}</span>
                    <span className="text-zinc-500 text-sm ml-2">min: {r.min_severity}</span>
                    <span className="text-zinc-600 text-sm ml-2">
                      → {destinations.find(d => d.id === r.destination_id)?.name || "unknown"}
                    </span>
                    <span className={`text-xs ml-2 ${r.enabled ? "text-green-400" : "text-zinc-600"}`}>
                      {r.enabled ? "Active" : "Disabled"}
                    </span>
                  </div>
                  <button onClick={() => deleteRule(r.id)}
                    className="rounded px-3 py-1 text-xs bg-zinc-800 text-red-400 border border-zinc-700 hover:bg-zinc-700">Delete</button>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
