"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { authHeaders } from "@/lib/auth-client";

// Incident pages: a new incident on one of your teams emails you (when email
// notifications are on) and texts you (when your phone is verified and SMS
// notifications are on). Mute a team here; channels are in Notifications.

interface Settings {
  email: string | null;
  phone: string | null;
  phone_verified: boolean;
  notification_email: boolean;
  notification_sms: boolean;
  sms_reachable: boolean;
  teams: Array<{ team_id: string; team_name: string | null; org_name: string | null; org_slug: string | null; notify_incidents: boolean }>;
}

export default function IncidentAlertsCard() {
  const [s, setS] = useState<Settings | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/settings/incident-alerts", { headers: authHeaders() })
      .then(async (r) => (r.ok ? setS(await r.json()) : setError("Could not load incident alert settings")))
      .catch(() => setError("Could not load incident alert settings"));
  }, []);

  const toggle = async (teamId: string, on: boolean) => {
    if (!s) return;
    setS({ ...s, teams: s.teams.map((t) => (t.team_id === teamId ? { ...t, notify_incidents: on } : t)) });
    const res = await fetch("/api/settings/incident-alerts", {
      method: "PATCH",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ team_id: teamId, notify_incidents: on }),
    });
    if (!res.ok) {
      setError("Could not save");
      setS((cur) => cur && { ...cur, teams: cur.teams.map((t) => (t.team_id === teamId ? { ...t, notify_incidents: !on } : t)) });
    }
  };

  return (
    <div className="bg-tc-card border border-tc-border rounded-xl p-6">
      <h2 className="text-lg font-semibold text-white mb-2">Incident alerts</h2>
      <p className="text-tc-text-dim text-sm mb-4">
        When an incident is raised on one of your teams (by <code>threatcrush investigate --raise</code> or a critical daemon detection) you are paged once by email and SMS. Email and routine SMS pages are limited to 5 per hour; critical and high SMS pages bypass that limit when SMS alerts are enabled.
      </p>
      {error && <p className="text-sm text-red-400 mb-2">{error}</p>}
      {s && (
        <>
          <ul className="text-sm space-y-1 mb-4">
            <li className="text-white">
              <span className={s.notification_email && s.email ? "text-tc-green" : "text-tc-text-dim"}>{s.notification_email && s.email ? "✓" : "✗"}</span>{" "}
              Email {s.email ? `to ${s.email}` : "(no address)"}{!s.notification_email && " — email notifications are off"}
            </li>
            <li className="text-white">
              <span className={s.sms_reachable ? "text-tc-green" : "text-tc-text-dim"}>{s.sms_reachable ? "✓" : "✗"}</span>{" "}
              SMS {s.phone ? `to ${s.phone}` : "(no phone)"}
              {s.phone && !s.phone_verified && " — verify your phone to get texts"}
              {s.phone_verified && !s.notification_sms && " — SMS notifications are off"}
            </li>
          </ul>
          {s.teams.length === 0 ? (
            <p className="text-sm text-tc-text-dim">You are not on any team. Org owners and admins are paged for incidents with no team.</p>
          ) : (
            <ul className="space-y-2">
              {s.teams.map((t) => (
                <li key={t.team_id}>
                  <label className="flex items-center gap-3 cursor-pointer">
                    <input type="checkbox" checked={t.notify_incidents} onChange={(e) => toggle(t.team_id, e.target.checked)} className="accent-tc-green w-4 h-4" />
                    <span className="text-white">{t.team_name ?? "Team"}</span>
                    {t.org_slug && (
                      <Link href={`/org/${t.org_slug}/incidents`} className="text-xs text-tc-text-dim hover:underline">{t.org_name} incidents</Link>
                    )}
                  </label>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
}
