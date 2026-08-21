"use client";

import { useCallback, useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";

const DOCS_HREF =
  "https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app";

type Installation = {
  id: string;
  installation_id: number;
  account_login: string | null;
  account_type: string | null;
  repository_selection: string | null;
  status: string;
  installed_at: string;
  updated_at: string;
};

type Scan = {
  id: string;
  installation_id: number;
  full_name: string;
  ref: string | null;
  trigger: string;
  status: string;
  error: string | null;
  files_considered: number;
  files_scanned: number;
  findings_count: number;
  peak_severity: string | null;
  truncated: boolean;
  truncation_reason: string | null;
  started_at: string;
  finished_at: string | null;
};

type ScanData = {
  configured: boolean;
  migrationApplied: boolean;
  installations: Installation[];
  scans: Scan[];
};

function fmtTime(value: string | null): string {
  if (!value) return "—";
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return "—";
  return new Date(ms).toISOString().slice(0, 16).replace("T", " ");
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-tc-text-dim",
};

export default function GitHubScansPanel() {
  const [data, setData] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/admin/github-scans", { headers: authHeaders() });
      if (!res.ok) {
        setError(res.status === 403 ? "Forbidden" : "Failed to load GitHub App data");
        return;
      }
      setData((await res.json()) as ScanData);
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const installations = data?.installations ?? [];
  const scans = data?.scans ?? [];
  const activeInstalls = installations.filter((i) => i.status === "active").length;

  return (
    <section className="mt-8 rounded-lg border border-tc-border/50 bg-tc-dark p-6">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">
          GitHub App scans
          <a
            href={DOCS_HREF}
            target="_blank"
            rel="noreferrer"
            className="ml-2 text-xs font-normal text-tc-text-dim hover:text-tc-green"
          >
            docs ↗
          </a>
        </h2>
        <button
          onClick={load}
          disabled={loading}
          className="text-sm text-tc-text-dim hover:text-tc-green disabled:opacity-50"
        >
          {loading ? "Loading..." : "Refresh"}
        </button>
      </div>

      {error && (
        <div className="mb-4 rounded border border-red-500/50 bg-red-500/10 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {data && !data.configured && (
        <div className="mb-4 rounded border border-yellow-500/50 bg-yellow-500/10 px-4 py-3 text-sm text-yellow-200">
          <code className="text-tc-green">GITHUB_APP_ID</code> and{" "}
          <code className="text-tc-green">GITHUB_APP_PRIVATE_KEY</code> are not both set, so
          installs are recorded but nothing is scanned.
        </div>
      )}

      {data && !data.migrationApplied && (
        <div className="mb-4 rounded border border-yellow-500/50 bg-yellow-500/10 px-4 py-3 text-sm text-yellow-200">
          The <code className="text-tc-green">github_installations</code> tables do not exist yet —
          apply <code>20260821190000_github_installations.sql</code>.
        </div>
      )}

      <div className="mb-5 flex gap-6 text-sm text-tc-text-dim">
        <span>
          <span className="text-white">{installations.length}</span> installations
        </span>
        <span>
          <span className="text-white">{activeInstalls}</span> active
        </span>
        <span>
          <span className="text-white">{scans.length}</span> recent scans
        </span>
      </div>

      <h3 className="mb-2 text-sm font-semibold text-tc-text-dim">Installations</h3>
      {installations.length === 0 ? (
        <p className="mb-6 text-sm text-tc-text-dim">No installations recorded yet.</p>
      ) : (
        <div className="mb-6 overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-tc-text-dim">
              <tr>
                <th className="py-1 pr-4">Account</th>
                <th className="py-1 pr-4">Repos</th>
                <th className="py-1 pr-4">Status</th>
                <th className="py-1 pr-4">Installed</th>
              </tr>
            </thead>
            <tbody className="text-tc-text">
              {installations.map((install) => (
                <tr key={install.id} className="border-t border-tc-border/30">
                  <td className="py-1 pr-4">
                    {install.account_login ?? `#${install.installation_id}`}
                    {install.account_type && (
                      <span className="ml-1 text-xs text-tc-text-dim">{install.account_type}</span>
                    )}
                  </td>
                  <td className="py-1 pr-4 text-tc-text-dim">
                    {install.repository_selection ?? "—"}
                  </td>
                  <td className="py-1 pr-4">
                    <span
                      className={
                        install.status === "active" ? "text-tc-green" : "text-tc-text-dim"
                      }
                    >
                      {install.status}
                    </span>
                  </td>
                  <td className="py-1 pr-4 text-tc-text-dim">{fmtTime(install.installed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <h3 className="mb-2 text-sm font-semibold text-tc-text-dim">Recent scans</h3>
      {scans.length === 0 ? (
        <p className="text-sm text-tc-text-dim">No scans yet.</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-tc-text-dim">
              <tr>
                <th className="py-1 pr-4">Repository</th>
                <th className="py-1 pr-4">Trigger</th>
                <th className="py-1 pr-4">Status</th>
                <th className="py-1 pr-4">Files</th>
                <th className="py-1 pr-4">Findings</th>
                <th className="py-1 pr-4">Peak</th>
                <th className="py-1 pr-4">Started</th>
              </tr>
            </thead>
            <tbody className="text-tc-text">
              {scans.map((scan) => (
                <tr key={scan.id} className="border-t border-tc-border/30">
                  <td className="py-1 pr-4 font-mono text-xs">{scan.full_name}</td>
                  <td className="py-1 pr-4 text-tc-text-dim">{scan.trigger}</td>
                  <td className="py-1 pr-4">
                    <span
                      className={
                        scan.status === "complete"
                          ? "text-tc-green"
                          : scan.status === "failed"
                            ? "text-red-400"
                            : "text-yellow-400"
                      }
                      title={scan.error ?? undefined}
                    >
                      {scan.status}
                    </span>
                    {scan.truncated && (
                      <span
                        className="ml-1 text-xs text-yellow-400"
                        title={scan.truncation_reason ?? "Partial scan"}
                      >
                        partial
                      </span>
                    )}
                  </td>
                  <td className="py-1 pr-4 text-tc-text-dim">
                    {scan.files_scanned}/{scan.files_considered}
                  </td>
                  <td className="py-1 pr-4">{scan.findings_count}</td>
                  <td className={`py-1 pr-4 ${SEVERITY_COLOR[scan.peak_severity ?? ""] ?? "text-tc-text-dim"}`}>
                    {scan.peak_severity ?? "clean"}
                  </td>
                  <td className="py-1 pr-4 text-tc-text-dim">{fmtTime(scan.started_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
