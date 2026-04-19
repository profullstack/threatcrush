'use client';

import { useEffect, useState } from 'react';

interface Tx {
  id: string;
  name: string;
  amount_usd: number;
  currency: string;
  paid_at: string;
}

export function TopContributors() {
  const [transactions, setTransactions] = useState<Tx[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      fetch('/api/funding/contributors')
        .then((r) => r.json())
        .then((d: { transactions?: Tx[] }) => {
          if (!cancelled) setTransactions(d.transactions ?? []);
        })
        .catch(() => {})
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    };
    load();
    const interval = setInterval(load, 60_000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  if (loading) {
    return (
      <div className="space-y-2">
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-12 animate-pulse rounded-xl bg-tc-card" />
        ))}
      </div>
    );
  }

  if (transactions.length === 0) {
    return (
      <p className="text-sm text-tc-text-dim">
        No contributions yet. Be the first founding backer.
      </p>
    );
  }

  return (
    <ul className="space-y-2">
      {transactions.map((tx) => (
        <li
          key={tx.id}
          className="flex items-center justify-between rounded-xl border border-tc-border bg-tc-card px-4 py-3"
        >
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-tc-text">{tx.name}</p>
            <p className="text-xs text-tc-text-dim">
              {new Date(tx.paid_at).toLocaleDateString()} &middot;{' '}
              {tx.currency === 'card'
                ? 'Credit Card (via CoinPay)'
                : `${tx.currency.toUpperCase()} (via CoinPay)`}
            </p>
          </div>
          <span className="text-sm font-semibold text-tc-green">
            ${tx.amount_usd.toFixed(2)}
          </span>
        </li>
      ))}
    </ul>
  );
}
