import React, { useEffect, useRef, useState } from 'react';
import { MAP_ASPECT, flag, severityColor, topCountries } from '@threatcrush/attack-map';
import { createAttackMap } from '@threatcrush/attack-map/canvas';
import { getAttackMap } from '../../lib/api';
import { useAuthStore } from '../../store/auth';

const REFRESH_MS = 5000;

function ago(iso) {
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  return `${Math.floor(s / 3600)}h`;
}

/**
 * Live attack map in the popup: your servers when signed in, otherwise the
 * public map of attacks on threatcrush.com. Polls only while the popup is open.
 */
export default function AttackMapView() {
  const user = useAuthStore((s) => s.user);
  const canvasRef = useRef(null);
  const mapRef = useRef(null);
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!canvasRef.current) return undefined;
    mapRef.current = createAttackMap(canvasRef.current, { dotPitch: 4, maxArcs: 20 });
    return () => mapRef.current?.destroy();
  }, []);

  useEffect(() => {
    let stopped = false;
    const load = async () => {
      try {
        const next = await getAttackMap({ signedIn: !!user });
        if (stopped) return;
        setData(next);
        setError('');
        mapRef.current?.setData(next);
      } catch (err) {
        if (!stopped) setError(err.message || 'Map unavailable');
      }
    };
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [user]);

  const total = data ? data.origins.reduce((n, o) => n + o.count, 0) : 0;
  const countries = data ? topCountries(data.origins, 4) : [];
  const latest = data ? [...data.origins].sort((a, b) => (a.lastSeen < b.lastSeen ? 1 : -1)).slice(0, 5) : [];

  return (
    <div className="flex-1 flex flex-col min-h-0 overflow-y-auto">
      <div className="flex items-center gap-2 px-4 py-2">
        <span className="relative flex h-2 w-2">
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#00ff41] opacity-60" />
          <span className="relative inline-flex h-2 w-2 rounded-full bg-[#00ff41]" />
        </span>
        <span className="text-xs font-bold text-white">{user ? 'Attacks on your servers' : 'Attacks on threatcrush.com'}</span>
        {data?.demo && <span className="text-[9px] uppercase text-yellow-500 border border-yellow-500/40 rounded px-1">demo</span>}
        <span className="ml-auto text-[10px] text-gray-500 font-mono">
          {data ? `${data.origins.length} src · ${total} ev` : ''}
        </span>
      </div>
      <div className="relative border-y border-[#222]" style={{ aspectRatio: String(MAP_ASPECT) }}>
        <canvas ref={canvasRef} className="absolute inset-0 w-full h-full" />
        {error && <p className="absolute inset-x-0 bottom-1 text-center text-[10px] text-red-400">{error}</p>}
      </div>
      <div className="grid grid-cols-2 gap-3 px-4 py-3">
        <div>
          <div className="text-[9px] uppercase tracking-widest text-gray-500 mb-1">Top sources</div>
          {countries.length === 0 && <div className="text-[11px] text-gray-600">Nothing yet</div>}
          {countries.map((c) => (
            <div key={c.code || c.country} className="flex justify-between text-[11px]">
              <span className="truncate text-gray-300">
                {flag(c.code)} {c.country}
              </span>
              <span className="font-mono text-white">{c.count}</span>
            </div>
          ))}
        </div>
        <div>
          <div className="text-[9px] uppercase tracking-widest text-gray-500 mb-1">Latest</div>
          {latest.map((o) => (
            <div key={o.ip} className="flex items-center gap-1.5 text-[11px]">
              <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: severityColor(o.severity) }} />
              <span className="truncate font-mono text-gray-300 flex-1">{o.ip}</span>
              <span className="text-gray-600">{ago(o.lastSeen)}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="mt-auto px-4 pb-2 text-[9px] text-gray-600 text-right">IP Geolocation by DB-IP</div>
    </div>
  );
}
