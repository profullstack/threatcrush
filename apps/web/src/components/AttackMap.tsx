"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  type AttackMapData,
  MAP_ASPECT,
  MAP_COLORS,
  flag,
  severityColor,
  topCountries,
} from "@threatcrush/attack-map";
import { type AttackMapRenderer, type MapHit, createAttackMap } from "@threatcrush/attack-map/canvas";
import { authHeaders } from "@/lib/auth-client";
import { useVisiblePolling } from "@/lib/use-visible-polling";

const WINDOWS = [
  { minutes: 15, label: "15m" },
  { minutes: 60, label: "1h" },
  { minutes: 360, label: "6h" },
  { minutes: 1440, label: "24h" },
];

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

export interface AttackMapProps {
  /** "public": the homepage feed of our own servers. Otherwise the signed-in caller's servers. */
  source: "public" | "account";
  /** Narrow an account map to one organization. */
  orgId?: string;
  title?: string;
  /** Poll interval. Daemons flush detections every ~10s, so 3s keeps it live. */
  refreshMs?: number;
  /** Hide the side panel (top countries + feed). */
  compact?: boolean;
}

function ago(iso: string, now: number): string {
  const s = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export default function AttackMap({ source, orgId, title = "Live attack map", refreshMs = 3000, compact = false }: AttackMapProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rendererRef = useRef<AttackMapRenderer | null>(null);
  const [data, setData] = useState<AttackMapData | null>(null);
  const [error, setError] = useState("");
  const [windowMinutes, setWindowMinutes] = useState(60);
  const [hover, setHover] = useState<{ hit: MapHit; x: number; y: number } | null>(null);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!canvasRef.current) return;
    const r = createAttackMap(canvasRef.current);
    rendererRef.current = r;
    return () => {
      r.destroy();
      rendererRef.current = null;
    };
  }, []);

  const load = useCallback(async () => {
    const params = new URLSearchParams({ window: String(windowMinutes) });
    if (orgId) params.set("org", orgId);
    const url = source === "public" ? `/api/attack-map/public?${params}` : `/api/attack-map?${params}`;
    try {
      const res = await fetch(url, source === "public" ? undefined : { headers: authHeaders() });
      if (!res.ok) throw new Error(res.status === 401 ? "Sign in to see your map" : `Map unavailable (${res.status})`);
      const next = (await res.json()) as AttackMapData;
      setData(next);
      setError("");
      setNow(Date.now());
      rendererRef.current?.setData(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Map unavailable");
    }
  }, [source, orgId, windowMinutes]);

  useEffect(() => {
    void load();
  }, [load]);
  useVisiblePolling(load, refreshMs);

  const totals = data
    ? {
        attacks: data.origins.reduce((n, o) => n + o.count, 0),
        sources: data.origins.length,
        countries: new Set(data.origins.map((o) => o.countryCode || o.country)).size,
      }
    : null;
  const recent = data ? [...data.origins].sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : -1)).slice(0, 7) : [];
  const countries = data ? topCountries(data.origins, 6) : [];
  const maxCountry = countries[0]?.count || 1;
  const hasArcs = data ? data.origins.some((o) => now - Date.parse(o.lastSeen) < 15 * 60_000) : false;

  return (
    <section className="rounded-xl border border-tc-border bg-tc-darker overflow-hidden" aria-label={title}>
      <header className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-tc-border px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2.5 w-2.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-tc-green opacity-60" />
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-tc-green" />
          </span>
          <span className="font-mono text-xs font-semibold tracking-widest text-tc-green">LIVE</span>
          <h2 className="text-sm font-semibold text-white">{title}</h2>
          {data?.demo && (
            <span className="rounded border border-amber-500/40 px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-amber-400">
              demo
            </span>
          )}
        </div>
        <div className="flex rounded-md border border-tc-border p-0.5" role="group" aria-label="Time window">
          {WINDOWS.map((w) => (
            <button
              key={w.minutes}
              type="button"
              onClick={() => setWindowMinutes(w.minutes)}
              aria-pressed={windowMinutes === w.minutes}
              className={`rounded px-2 py-0.5 font-mono text-xs transition-colors ${
                windowMinutes === w.minutes ? "bg-tc-green/15 text-tc-green" : "text-tc-text-dim hover:text-white"
              }`}
            >
              {w.label}
            </button>
          ))}
        </div>
        {totals && (
          <dl className="ml-auto flex gap-5 font-mono text-xs">
            <div className="flex items-baseline gap-1.5">
              <dt className="text-tc-text-dim">attacks</dt>
              <dd className="font-semibold text-white">{totals.attacks.toLocaleString()}</dd>
            </div>
            <div className="flex items-baseline gap-1.5">
              <dt className="text-tc-text-dim">sources</dt>
              <dd className="font-semibold text-white">{totals.sources.toLocaleString()}</dd>
            </div>
            <div className="flex items-baseline gap-1.5">
              <dt className="text-tc-text-dim">countries</dt>
              <dd className="font-semibold text-white">{totals.countries}</dd>
            </div>
          </dl>
        )}
      </header>

      <div className={compact ? "" : "grid lg:grid-cols-[minmax(0,1fr)_17rem]"}>
        <div className="relative min-w-0" style={{ aspectRatio: String(MAP_ASPECT) }}>
          <canvas
            ref={canvasRef}
            className="absolute inset-0 h-full w-full"
            onMouseMove={(e) => {
              const rect = e.currentTarget.getBoundingClientRect();
              const x = e.clientX - rect.left;
              const y = e.clientY - rect.top;
              const hit = rendererRef.current?.hitTest(x, y);
              setHover(hit ? { hit, x, y } : null);
            }}
            onMouseLeave={() => setHover(null)}
            role="img"
            aria-label={
              totals
                ? `${totals.attacks} attacks from ${totals.sources} sources in ${totals.countries} countries`
                : "Attack map loading"
            }
          />
          {hover && <Tooltip hover={hover} now={now} />}
          {data && !hasArcs && !error && (
            <p className="pointer-events-none absolute inset-x-0 bottom-3 text-center font-mono text-xs text-tc-text-dim">
              {data.servers.length === 0
                ? "No server placed yet: link one with `threatcrush servers link` and it appears on its next heartbeat"
                : "All quiet: no attacks in this window"}
            </p>
          )}
          {error && (
            <p className="absolute inset-x-0 bottom-3 text-center font-mono text-xs text-red-400">{error}</p>
          )}
        </div>

        {!compact && (
          <aside className="relative border-t border-tc-border lg:border-l lg:border-t-0">
            <div className="p-4 lg:absolute lg:inset-0 lg:overflow-y-auto">
            <h3 className="mb-2 font-mono text-[11px] uppercase tracking-widest text-tc-text-dim">Top sources</h3>
            <ul className="mb-5 space-y-1.5">
              {countries.length === 0 && <li className="text-xs text-tc-text-dim">Nothing yet</li>}
              {countries.map((c) => (
                <li key={c.code ?? c.country} className="text-xs">
                  <div className="flex justify-between gap-2">
                    <span className="truncate text-tc-text">
                      <span aria-hidden className="mr-1.5">{flag(c.code)}</span>
                      {c.country}
                    </span>
                    <span className="font-mono text-white">{c.count.toLocaleString()}</span>
                  </div>
                  <div className="mt-1 h-1 rounded bg-tc-border">
                    <div
                      className="h-1 rounded bg-gradient-to-r from-[#ff6b35] to-[#ff2d55]"
                      style={{ width: `${Math.max(4, (c.count / maxCountry) * 100)}%` }}
                    />
                  </div>
                </li>
              ))}
            </ul>
            <h3 className="mb-2 font-mono text-[11px] uppercase tracking-widest text-tc-text-dim">Latest</h3>
            <ul className="space-y-2">
              {recent.map((o) => (
                <li key={o.ip} className="flex items-start gap-2 text-xs">
                  <span className="mt-1 h-2 w-2 shrink-0 rounded-full" style={{ background: severityColor(o.severity) }} />
                  <div className="min-w-0 flex-1">
                    <div className="flex justify-between gap-2">
                      <span className="truncate font-mono text-tc-text">{o.ip}</span>
                      <span className="shrink-0 text-tc-text-dim">{ago(o.lastSeen, now)}</span>
                    </div>
                    <div className="truncate text-tc-text-dim">
                      <span aria-hidden className="mr-1">{flag(o.countryCode)}</span>
                      {[o.city, o.country].filter(Boolean).join(", ")}
                      {o.category ? ` · ${o.category}` : ""}
                    </div>
                  </div>
                </li>
              ))}
            </ul>
            </div>
          </aside>
        )}
      </div>

      <footer className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-tc-border px-4 py-2 font-mono text-[11px] text-tc-text-dim">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rotate-45" style={{ background: MAP_COLORS.server }} />
          our servers
        </span>
        {SEVERITIES.map((s) => (
          <span key={s} className="flex items-center gap-1.5">
            <span className="inline-block h-2 w-2 rounded-full" style={{ background: severityColor(s) }} />
            {s}
          </span>
        ))}
        <a href="https://db-ip.com" target="_blank" rel="noopener" className="ml-auto hover:text-tc-text">
          IP Geolocation by DB-IP
        </a>
      </footer>
    </section>
  );
}

function Tooltip({ hover, now }: { hover: { hit: MapHit; x: number; y: number }; now: number }) {
  const { hit, x, y } = hover;
  return (
    <div
      className="pointer-events-none absolute z-10 min-w-44 rounded-md border border-tc-border bg-black/90 px-3 py-2 text-xs shadow-xl backdrop-blur"
      style={{ left: x + 14, top: y + 14, transform: x > 500 ? "translateX(calc(-100% - 28px))" : undefined }}
    >
      {hit.kind === "server" ? (
        <>
          <div className="font-mono font-semibold text-tc-green">◆ {hit.server.name}</div>
          <div className="text-tc-text-dim">
            {[hit.server.city, hit.server.country].filter(Boolean).join(", ")} ·{" "}
            {hit.server.online === false ? "offline" : "online"}
          </div>
        </>
      ) : (
        <>
          <div className="font-mono font-semibold" style={{ color: severityColor(hit.origin.severity) }}>
            {hit.origin.ip}
          </div>
          <div className="text-tc-text">
            {flag(hit.origin.countryCode)} {[hit.origin.city, hit.origin.country].filter(Boolean).join(", ")}
          </div>
          <div className="mt-1 text-tc-text-dim">
            {hit.origin.count.toLocaleString()} events · {hit.origin.severity}
            {hit.origin.category ? ` · ${hit.origin.category}` : ""}
          </div>
          <div className="text-tc-text-dim">last seen {ago(hit.origin.lastSeen, now)}</div>
        </>
      )}
    </div>
  );
}
