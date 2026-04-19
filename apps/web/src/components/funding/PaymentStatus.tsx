'use client';

import { Suspense } from 'react';
import { useSearchParams } from 'next/navigation';

function Inner() {
  const sp = useSearchParams();
  const payment = sp.get('payment');
  if (payment === 'success') {
    return (
      <div className="rounded-xl border border-tc-green/40 bg-tc-green/10 p-4 text-sm text-tc-green">
        Payment received. Thank you for backing threatcrush. Your contribution will appear in the
        recent backers list shortly.
      </div>
    );
  }
  if (payment === 'cancelled') {
    return (
      <div className="rounded-xl border border-tc-border bg-tc-card p-4 text-sm text-tc-text-dim">
        Payment was cancelled. No charges were made.
      </div>
    );
  }
  return null;
}

export function PaymentStatus() {
  return (
    <Suspense fallback={null}>
      <Inner />
    </Suspense>
  );
}
