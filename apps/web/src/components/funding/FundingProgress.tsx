'use client';

import { useEffect, useState } from 'react';

type Total = { total_usd: number; contributors: number };

export function FundingProgress({ goal }: { goal: number }) {
  const [data, setData] = useState<Total | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/funding/total')
      .then((r) => r.json())
      .then((d: Total) => {
        if (!cancelled) setData(d);
      })
      .catch(() => {})
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading || !data) {
    return (
      <div className="rounded-2xl border border-tc-border bg-tc-card p-6">
        <div className="h-6 w-1/3 animate-pulse rounded bg-tc-border" />
        <div className="mt-3 h-2 w-full animate-pulse rounded bg-tc-border" />
      </div>
    );
  }

  const pct = Math.min(100, (data.total_usd / goal) * 100);

  return (
    <div className="rounded-2xl border border-tc-border bg-tc-card p-6 glow-box">
      <div className="flex items-baseline justify-between">
        <span className="text-3xl font-semibold text-tc-green glow-green">
          ${data.total_usd.toLocaleString(undefined, { maximumFractionDigits: 0 })}
        </span>
        <span className="text-sm text-tc-text-dim">
          of ${goal.toLocaleString()} goal
        </span>
      </div>
      <div className="mt-3 h-2 w-full overflow-hidden rounded-full bg-tc-border">
        <div
          className="h-full bg-tc-green transition-all duration-500"
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="mt-2 text-xs text-tc-text-dim">
        {pct.toFixed(1)}% raised &middot; {data.contributors}{' '}
        {data.contributors === 1 ? 'backer' : 'backers'}
      </p>
    </div>
  );
}
