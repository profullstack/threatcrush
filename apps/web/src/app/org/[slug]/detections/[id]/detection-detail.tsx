"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { listOrganizations } from "@/lib/organizations";
import { authHeaders } from "@/lib/auth-client";
import {
  applyExpectedKeys, buildTimeline, detailModel, fingerprintOf, sshContextOf, type EventLike, type Relation,
} from "@threatcrush/event-detail";
import { EventDetailView, type EventDetailAction } from "@threatcrush/event-detail/react";
import { loadExpectedKeys, saveExpectedKeys } from "@/lib/expected-keys";

interface History {
  detection: EventLike & { server_name: string | null };
  related: Array<EventLike & { server_name: string | null }>;
  origin: string | null;
  incident: { id: string; status: string; assignee_id: string | null } | null;
  window_days: number;
}

/**
 * One detection with its full history (same IP, same key, same host, same
 * rule), in the view the desktop app shares (@threatcrush/event-detail).
 */
export default function DetectionDetail({ slug, id }: { slug: string; id: string }) {
  const { signedIn, loading: authLoading } = useAuth();
  const router = useRouter();
  const [orgId, setOrgId] = useState<string | null>(null);
  const [data, setData] = useState<History | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<Relation | "all">("all");
  const [notice, setNotice] = useState<string | null>(null);
  const [expected, setExpected] = useState<Set<string>>(() => new Set());

  useEffect(() => { setExpected(loadExpectedKeys()); }, []);

  const load = useCallback(async (org: string) => {
    const res = await fetch(`/api/orgs/${org}/detections/${id}/history`, { headers: authHeaders() });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { setError(body.error || `Could not load this detection (${res.status})`); return; }
    setData(body as History);
  }, [id]);

  useEffect(() => {
    if (!signedIn || authLoading || !id) return;
    (async () => {
      const { organizations } = await listOrganizations();
      const found = (organizations as unknown as Array<{ id: string; slug: string }>).find((o) => o.slug === slug);
      if (!found) { setError("Organization not found"); return; }
      setOrgId(found.id);
      await load(found.id);
    })().catch((e) => setError((e as Error).message));
  }, [signedIn, authLoading, slug, id, load]);

  const view = useMemo(() => {
    if (!data) return null;
    const primary = applyExpectedKeys(data.detection, expected);
    const related = data.related.map((r) => applyExpectedKeys(r, expected));
    return {
      primary,
      model: detailModel(primary, { originLabel: data.origin, viewerTime: (ms) => new Date(ms).toLocaleString() }),
      timeline: buildTimeline(primary, related),
    };
  }, [data, expected]);

  if (!id) return <Centered>Not a detection id</Centered>;
  if (error) return <Centered>{error}</Centered>;
  if (authLoading || !view || !data) return <Centered>Loading…</Centered>;

  const fp = fingerprintOf(view.primary);
  const isExpected = !!fp && expected.has(fp);
  const flash = (t: string) => { setNotice(t); setTimeout(() => setNotice(null), 2500); };
  const actions: EventDetailAction[] = [
    {
      id: "copy",
      label: "Copy event JSON",
      onClick: () => { void navigator.clipboard.writeText(JSON.stringify(data.detection, null, 2)).then(() => flash("Copied")); },
    },
  ];
  if (fp && sshContextOf(view.primary)) {
    actions.push({
      id: "expected",
      label: isExpected ? "Unmark expected CI key" : "Mark this key as expected CI",
      primary: !isExpected,
      title: "Future logins with this key show as a quiet info row in this browser. To quiet the agent itself, add the fingerprint to [ssh_context] expected_keys in threatcrushd.conf.",
      onClick: () => {
        const next = new Set(expected);
        if (isExpected) next.delete(fp); else next.add(fp);
        saveExpectedKeys(next);
        setExpected(next);
        flash(isExpected ? "Removed from expected keys" : `Marked. For the agent: [ssh_context] expected_keys = ["${fp}"]`);
      },
    });
  }
  if (data.incident) actions.push({ id: "incident", label: `Open incident (${data.incident.status})`, onClick: () => router.push(`/org/${slug}/incidents/${data.incident!.id}`) });

  return (
    <div className="min-h-screen bg-black">
      <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
        <div className="mb-4 flex items-center gap-3 text-sm">
          <Link href={`/org/${slug}/detections`} className="text-zinc-500 hover:text-zinc-300">← Detections</Link>
          {orgId && <span className="text-zinc-700">·</span>}
          <span className="text-zinc-500">history covers the last {data.window_days} days</span>
        </div>
        <EventDetailView
          model={view.model}
          timeline={view.timeline}
          filter={filter}
          onFilter={setFilter}
          onSelect={(item) => router.push(`/org/${slug}/detections/${item.event.id}`)}
          actions={actions}
          notice={notice}
        />
      </div>
    </div>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return <div className="min-h-screen bg-black flex items-center justify-center"><div className="text-zinc-400">{children}</div></div>;
}
