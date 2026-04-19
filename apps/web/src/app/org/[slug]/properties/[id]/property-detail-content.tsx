"use client";

import { Fragment, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import {
  deleteProperty,
  enqueueRun,
  getProperty,
  listOrganizations,
  listRuns,
  updateProperty,
  type Property,
  type PropertyRun,
  type PropertySchedule,
  type RunStatus,
  type RunType,
} from "@/lib/organizations";

const STATUS_STYLE: Record<RunStatus, string> = {
  queued: "bg-zinc-800 text-zinc-300",
  running: "bg-yellow-500/10 text-yellow-400",
  succeeded: "bg-green-500/10 text-green-400",
  failed: "bg-red-500/10 text-red-400",
  cancelled: "bg-zinc-800 text-zinc-500",
};

const KIND_COLOR: Record<Property["kind"], string> = {
  url: "bg-blue-500/10 text-blue-400",
  api: "bg-purple-500/10 text-purple-400",
  domain: "bg-cyan-500/10 text-cyan-400",
  ip: "bg-yellow-500/10 text-yellow-400",
  repo: "bg-pink-500/10 text-pink-400",
};

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

function duration(a: string | null, b: string | null): string {
  if (!a || !b) return "—";
  const ms = new Date(b).getTime() - new Date(a).getTime();
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m ${Math.floor((ms % 60_000) / 1000)}s`;
}

type Finding = {
  type: string;
  severity: string;
  message: string;
  location?: string;
  details?: Record<string, unknown>;
};

function toFindings(raw: unknown): Finding[] {
  if (!Array.isArray(raw)) return [];
  return raw.map((f) => {
    const obj = f as Record<string, unknown>;
    return {
      type: String(obj.type ?? "Finding"),
      severity: String(obj.severity ?? "info"),
      message: String(obj.message ?? ""),
      location: typeof obj.location === "string" ? obj.location : undefined,
      details: (obj.details && typeof obj.details === "object")
        ? obj.details as Record<string, unknown>
        : undefined,
    };
  });
}

function csvEscape(value: unknown): string {
  const s = value === null || value === undefined ? "" : String(value);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function findingsToCsv(findings: Finding[], meta: { property: string; runId: string }): string {
  const header = ["property", "run_id", "severity", "type", "message", "location", "details"];
  const rows = findings.map((f) => [
    meta.property,
    meta.runId,
    f.severity,
    f.type,
    f.message,
    f.location || "",
    f.details ? JSON.stringify(f.details) : "",
  ]);
  return [header, ...rows].map((row) => row.map(csvEscape).join(",")).join("\n");
}

function downloadCsv(content: string, filename: string): void {
  const blob = new Blob([content], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-red-500/10 text-red-300 border-red-500/20",
  medium: "bg-yellow-500/10 text-yellow-300 border-yellow-500/20",
  low: "bg-zinc-500/10 text-zinc-300 border-zinc-500/20",
  info: "bg-blue-500/10 text-blue-300 border-blue-500/20",
};

const SCHEDULE_OPTIONS: Array<{ value: "" | NonNullable<PropertySchedule>; label: string }> = [
  { value: "", label: "Manual only" },
  { value: "hourly", label: "Hourly" },
  { value: "daily", label: "Daily" },
  { value: "weekly", label: "Weekly" },
  { value: "monthly", label: "Monthly" },
];

export default function PropertyDetailContent({
  orgSlug,
  propertyId,
}: {
  orgSlug: string;
  propertyId: string;
}) {
  const router = useRouter();
  const { signedIn, loading: authLoading } = useAuth();
  const [orgId, setOrgId] = useState<string | null>(null);
  const [property, setProperty] = useState<Property | null>(null);
  const [runs, setRuns] = useState<PropertyRun[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [enqueuing, setEnqueuing] = useState<RunType | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [expandedRunId, setExpandedRunId] = useState<string | null>(null);
  const [savingSchedule, setSavingSchedule] = useState(false);

  const refresh = async (id: string) => {
    const [propRes, runsRes] = await Promise.all([
      getProperty(id, propertyId),
      listRuns(id, propertyId, 50),
    ]);
    setProperty(propRes.property);
    setRuns(runsRes.runs);
  };

  useEffect(() => {
    if (authLoading || !signedIn) return;

    let active = true;
    (async () => {
      try {
        const { organizations } = await listOrganizations();
        if (!active) return;
        const typed = organizations as unknown as Array<{ id: string; slug: string }>;
        const org = typed.find((o) => o.slug === orgSlug);
        if (!org) {
          setError("Organization not found");
          setLoading(false);
          return;
        }
        setOrgId(org.id);
        await refresh(org.id);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load property");
      } finally {
        if (active) setLoading(false);
      }
    })();

    return () => { active = false; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signedIn, authLoading, orgSlug, propertyId]);

  // Auto-refresh while a run is queued/running
  useEffect(() => {
    if (!orgId) return;
    const hasLive = runs.some((r) => r.status === "queued" || r.status === "running");
    if (!hasLive) return;
    const timer = setInterval(() => { void refresh(orgId); }, 4000);
    return () => clearInterval(timer);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [runs, orgId]);

  const handleRunNow = async (type: RunType) => {
    if (!orgId) return;
    setEnqueuing(type);
    try {
      await enqueueRun(orgId, propertyId, type);
      await refresh(orgId);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to enqueue run");
    } finally {
      setEnqueuing(null);
    }
  };

  const handleScheduleChange = async (value: string) => {
    if (!orgId) return;
    setSavingSchedule(true);
    try {
      const next = value === "" ? null : (value as NonNullable<PropertySchedule>);
      await updateProperty(orgId, propertyId, { schedule: next });
      await refresh(orgId);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to update schedule");
    } finally {
      setSavingSchedule(false);
    }
  };

  const handleToggleEnabled = async () => {
    if (!orgId || !property) return;
    try {
      await updateProperty(orgId, propertyId, { enabled: !property.enabled });
      await refresh(orgId);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to toggle enabled");
    }
  };

  const handleDelete = async () => {
    if (!orgId || !property) return;
    if (!confirm(`Delete property "${property.name}"? This will remove its run history too.`)) return;
    setDeleting(true);
    try {
      await deleteProperty(orgId, propertyId);
      router.push(`/org/${orgSlug}/properties`);
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to delete");
      setDeleting(false);
    }
  };

  if (authLoading || loading) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-zinc-400">Loading...</div>
      </div>
    );
  }

  if (!property || !orgId) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-center max-w-md px-4">
          <h1 className="text-xl font-bold text-white mb-2">Property not found</h1>
          <p className="text-zinc-400 mb-6">{error || "This property doesn't exist or you don't have access."}</p>
          <Link href={`/org/${orgSlug}/properties`} className="text-green-500 hover:underline">
            ← Back to properties
          </Link>
        </div>
      </div>
    );
  }

  const defaultRunType: RunType = property.kind === "repo" ? "scan" : "pentest";
  const altRunType: RunType = defaultRunType === "scan" ? "pentest" : "scan";

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-4xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-8 flex items-start gap-3">
          <Link href={`/org/${orgSlug}/properties`} className="mt-1 text-zinc-500 hover:text-zinc-300">
            <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
          </Link>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold text-white">{property.name}</h1>
              <span className={`rounded px-2 py-0.5 text-xs font-medium ${KIND_COLOR[property.kind]}`}>
                {property.kind.toUpperCase()}
              </span>
              {!property.enabled && (
                <span className="rounded bg-zinc-800 px-2 py-0.5 text-xs text-zinc-400">disabled</span>
              )}
            </div>
            <p className="mt-1 font-mono text-sm text-zinc-400 break-all">{property.target}</p>
            {property.description && (
              <p className="mt-2 text-sm text-zinc-500">{property.description}</p>
            )}
          </div>
        </div>

        {error && (
          <div className="mb-6 rounded-lg bg-red-500/10 border border-red-500/20 px-4 py-3">
            <p className="text-sm text-red-400">{error}</p>
          </div>
        )}

        {/* Meta + actions */}
        <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-4">
          <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
            <div className="text-xs uppercase tracking-wider text-zinc-500">Last run</div>
            <div className="mt-1 text-sm text-white">{formatDate(property.last_run_at)}</div>
            {property.last_run_status && (
              <div className={`mt-1 inline-block rounded px-2 py-0.5 text-xs ${STATUS_STYLE[property.last_run_status as RunStatus] || "bg-zinc-800 text-zinc-300"}`}>
                {property.last_run_status}
              </div>
            )}
          </div>
          <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
            <div className="text-xs uppercase tracking-wider text-zinc-500">Schedule</div>
            <select
              value={property.schedule || ""}
              disabled={savingSchedule}
              onChange={(e) => handleScheduleChange(e.target.value)}
              className="mt-1 w-full rounded bg-zinc-800 border border-zinc-700 px-2 py-1 text-sm text-white focus:border-green-500 focus:outline-none disabled:opacity-60"
            >
              {SCHEDULE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
            <div className="mt-1 text-xs text-zinc-500">
              {property.schedule ? `Next: ${formatDate(property.next_run_at)}` : "No schedule"}
            </div>
          </div>
          <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
            <div className="text-xs uppercase tracking-wider text-zinc-500">Tags</div>
            <div className="mt-1 flex flex-wrap gap-1">
              {property.tags.length === 0 ? (
                <span className="text-sm text-zinc-600">—</span>
              ) : property.tags.map((t) => (
                <span key={t} className="rounded bg-zinc-800 px-2 py-0.5 text-xs text-zinc-300">{t}</span>
              ))}
            </div>
          </div>
          <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-4">
            <div className="text-xs uppercase tracking-wider text-zinc-500">Created</div>
            <div className="mt-1 text-sm text-white">{formatDate(property.created_at)}</div>
          </div>
        </div>

        {/* Actions */}
        <div className="mb-8 flex flex-wrap items-center gap-2">
          <button
            type="button"
            disabled={enqueuing !== null}
            onClick={() => handleRunNow(defaultRunType)}
            className="rounded-lg bg-green-500 px-4 py-2 text-sm font-medium text-black hover:bg-green-400 disabled:opacity-60"
          >
            {enqueuing === defaultRunType ? "Enqueuing..." : `Run ${defaultRunType} now`}
          </button>
          <button
            type="button"
            disabled={enqueuing !== null}
            onClick={() => handleRunNow(altRunType)}
            className="rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm font-medium text-zinc-200 hover:border-zinc-600 disabled:opacity-60"
          >
            {enqueuing === altRunType ? "Enqueuing..." : `Run ${altRunType}`}
          </button>
          <button
            type="button"
            onClick={handleToggleEnabled}
            className="rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm font-medium text-zinc-200 hover:border-zinc-600"
          >
            {property.enabled ? "Disable" : "Enable"}
          </button>
          <button
            type="button"
            disabled={deleting}
            onClick={handleDelete}
            className="ml-auto rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-2 text-sm font-medium text-red-400 hover:bg-red-500/20 disabled:opacity-60"
          >
            {deleting ? "Deleting..." : "Delete Property"}
          </button>
        </div>

        <div className="rounded-lg bg-blue-500/5 border border-blue-500/10 p-3 mb-8">
          <p className="text-xs text-blue-300/70">
            Enqueued runs are picked up by any <code className="rounded bg-blue-500/10 px-1">threatcrushd</code> daemon logged in to your account.
            Run locally immediately with <code className="rounded bg-blue-500/10 px-1">threatcrush properties run -n {property.name}</code>.
          </p>
        </div>

        {/* Runs history */}
        <div>
          <h2 className="text-lg font-semibold text-white mb-3">Run history</h2>
          {runs.length === 0 ? (
            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-8 text-center text-sm text-zinc-500">
              No runs yet. Click <strong className="text-zinc-300">Run now</strong> above to kick one off.
            </div>
          ) : (
            <div className="overflow-hidden rounded-lg border border-zinc-800">
              <table className="w-full divide-y divide-zinc-800">
                <thead className="bg-zinc-950 text-left text-xs uppercase tracking-wider text-zinc-500">
                  <tr>
                    <th className="px-4 py-3 w-8"></th>
                    <th className="px-4 py-3">When</th>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Duration</th>
                    <th className="px-4 py-3">Findings</th>
                    <th className="px-4 py-3">Source</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800 bg-black text-sm">
                  {runs.map((run) => {
                    const sev = (run.severity_summary || {}) as Record<string, number>;
                    const findings = toFindings(run.findings);
                    const isOpen = expandedRunId === run.id;
                    const expandable = findings.length > 0 || !!run.output || !!run.error;

                    return (
                      <Fragment key={run.id}>
                        <tr className={expandable ? "hover:bg-zinc-950/60 cursor-pointer" : ""}
                          onClick={() => expandable && setExpandedRunId(isOpen ? null : run.id)}>
                          <td className="px-4 py-3 text-zinc-500">
                            {expandable ? (isOpen ? "▾" : "▸") : ""}
                          </td>
                          <td className="px-4 py-3 text-zinc-300">{formatDate(run.completed_at || run.started_at || run.queued_at)}</td>
                          <td className="px-4 py-3 text-zinc-300">{run.type}</td>
                          <td className="px-4 py-3">
                            <span className={`rounded px-2 py-0.5 text-xs font-medium ${STATUS_STYLE[run.status]}`}>
                              {run.status}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-zinc-400">{duration(run.started_at, run.completed_at)}</td>
                          <td className="px-4 py-3 text-zinc-300">
                            {run.findings_count > 0 ? (
                              <div className="flex items-center gap-2">
                                <span>{run.findings_count}</span>
                                <span className="font-mono text-xs text-zinc-500">
                                  {sev.critical || 0}C/{sev.high || 0}H/{sev.medium || 0}M/{sev.low || 0}L
                                </span>
                              </div>
                            ) : run.status === "succeeded" ? (
                              <span className="text-green-400">clean</span>
                            ) : (
                              <span className="text-zinc-600">—</span>
                            )}
                            {run.summary && (
                              <div className="mt-0.5 text-xs text-zinc-500">{run.summary}</div>
                            )}
                            {run.error && (
                              <div className="mt-0.5 text-xs text-red-400">{run.error}</div>
                            )}
                          </td>
                          <td className="px-4 py-3 text-zinc-500">
                            <div>{run.source || run.trigger}</div>
                            {run.worker_id && <div className="text-xs text-zinc-600">{run.worker_id}</div>}
                          </td>
                        </tr>
                        {isOpen && expandable && (
                          <tr>
                            <td colSpan={7} className="bg-zinc-950/60 px-6 py-4">
                              <div className="mb-3 flex items-center justify-between">
                                <h3 className="text-sm font-semibold text-white">
                                  Findings ({findings.length})
                                </h3>
                                {findings.length > 0 && (
                                  <button
                                    type="button"
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      const csv = findingsToCsv(findings, {
                                        property: property.name,
                                        runId: run.id,
                                      });
                                      const ts = (run.completed_at || run.queued_at || "").replace(/[^0-9]/g, "").slice(0, 14);
                                      downloadCsv(csv, `${property.name}-${run.type}-${ts || "run"}.csv`);
                                    }}
                                    className="rounded-md border border-zinc-700 bg-zinc-900 px-3 py-1 text-xs font-medium text-zinc-200 hover:border-green-500 hover:text-green-400"
                                  >
                                    Download CSV
                                  </button>
                                )}
                              </div>

                              {findings.length === 0 && run.output && (
                                <pre className="max-h-64 overflow-auto rounded-md border border-zinc-800 bg-black p-3 text-xs text-zinc-300">
{run.output}
                                </pre>
                              )}

                              {findings.length > 0 && (
                                <div className="space-y-2">
                                  {findings.map((f, i) => (
                                    <div
                                      key={i}
                                      className={`rounded-md border px-3 py-2 ${SEVERITY_COLOR[f.severity] || SEVERITY_COLOR.info}`}
                                    >
                                      <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2">
                                          <span className="rounded bg-black/40 px-2 py-0.5 text-xs font-semibold uppercase tracking-wide">
                                            {f.severity}
                                          </span>
                                          <span className="text-sm font-medium">{f.type}</span>
                                        </div>
                                        {f.location && (
                                          <span className="font-mono text-xs opacity-80">{f.location}</span>
                                        )}
                                      </div>
                                      <div className="mt-1 text-sm">{f.message}</div>
                                      {f.details && Object.keys(f.details).length > 0 && (
                                        <pre className="mt-2 max-h-40 overflow-auto rounded bg-black/40 p-2 text-xs opacity-90">
{JSON.stringify(f.details, null, 2)}
                                        </pre>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              )}

                              {run.error && findings.length === 0 && !run.output && (
                                <div className="rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
                                  {run.error}
                                </div>
                              )}
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
