'use client';

import { useCallback, useEffect, useState } from 'react';
import { QRCodeCanvas } from '@/components/funding/QRCode';
import { SUPPORTED_CURRENCIES, type CoinpayCurrency } from '@/lib/coinpay-client';

type TierId = 'backer' | 'founder' | 'custom';

const TIERS: Array<{
  id: TierId;
  label: string;
  amount: number;
  description: string;
  highlight?: boolean;
}> = [
  {
    id: 'backer',
    label: 'Backer',
    amount: 25,
    description: 'Founding backer recognition on the launch page.',
  },
  {
    id: 'founder',
    label: 'Founder',
    amount: 250,
    description: 'Founder badge, early access, and a direct line to the team.',
    highlight: true,
  },
];

type Step = 'tier' | 'currency' | 'payment';
type Status = 'idle' | 'pending' | 'paid' | 'expired' | 'error';

type CryptoPayment = {
  payment_id: string;
  address: string | null;
  amount_crypto: number | null;
  currency: string;
  expires_at: string | null;
  checkout_url: string | null;
};

function tierAmount(tier: TierId, custom: number): number {
  if (tier === 'backer') return 25;
  if (tier === 'founder') return 250;
  return custom;
}

export function FundingClient() {
  const [step, setStep] = useState<Step>('tier');
  const [tier, setTier] = useState<TierId | null>(null);
  const [customAmount, setCustomAmount] = useState<number>(50);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [currency, setCurrency] = useState<CoinpayCurrency | null>(null);
  const [payment, setPayment] = useState<CryptoPayment | null>(null);
  const [status, setStatus] = useState<Status>('idle');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const reset = () => {
    setStep('tier');
    setTier(null);
    setCurrency(null);
    setPayment(null);
    setStatus('idle');
    setError(null);
    setCopied(null);
  };

  const selectCurrency = async (cur: CoinpayCurrency) => {
    if (!tier) return;
    setCurrency(cur);
    setError(null);
    setLoading(true);
    const amount = tierAmount(tier, customAmount);
    try {
      const res = await fetch('/api/funding/create-invoice', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          amount_usd: amount,
          currency: cur,
          contributor_name: name || undefined,
          contributor_email: email || undefined,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(data.error || 'Failed to create payment');
        setLoading(false);
        return;
      }
      if (data.checkout_url) {
        window.location.href = data.checkout_url;
        return;
      }
      if (data.address) {
        setPayment({
          payment_id: data.payment_id,
          address: data.address,
          amount_crypto: data.amount_crypto,
          currency: data.currency,
          expires_at: data.expires_at,
          checkout_url: data.checkout_url,
        });
        setStep('payment');
        setStatus('pending');
      } else {
        setError('No payment address returned');
      }
    } catch {
      setError('Network error. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const poll = useCallback(async () => {
    if (!payment?.payment_id) return;
    try {
      const res = await fetch(`/api/funding/status?payment_id=${payment.payment_id}`);
      if (!res.ok) return;
      const data = await res.json();
      if (data.status === 'forwarded' || data.status === 'confirmed') setStatus('paid');
      else if (data.status === 'expired') setStatus('expired');
      else if (data.status === 'failed') {
        setStatus('error');
        setError('Payment failed.');
      }
    } catch {
      /* ignore */
    }
  }, [payment]);

  useEffect(() => {
    if (status !== 'pending' || !payment) return;
    const id = setInterval(poll, 5000);
    return () => clearInterval(id);
  }, [status, payment, poll]);

  const copy = async (text: string, field: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(field);
      setTimeout(() => setCopied(null), 2000);
    } catch {
      /* ignore */
    }
  };

  const cardBase =
    'rounded-2xl border border-tc-border bg-tc-card p-6 text-tc-text';
  const btnPrimary =
    'inline-flex items-center justify-center rounded-lg border border-tc-green bg-tc-green/10 px-4 py-2 text-sm font-semibold text-tc-green hover:bg-tc-green/20 glow-box-hover transition-colors disabled:opacity-50';
  const inputCls =
    'w-full rounded-xl border border-tc-border bg-tc-darker px-4 py-3 text-sm text-tc-text placeholder-tc-text-dim/70 focus:border-tc-green focus:outline-none';

  if (status === 'paid') {
    return (
      <div className={`${cardBase} text-center`}>
        <h3 className="text-2xl font-semibold text-tc-green glow-green">Payment received</h3>
        <p className="mt-2 text-sm text-tc-text-dim">Thank you for backing threatcrush.</p>
        <button onClick={reset} className={`${btnPrimary} mt-4`}>
          Make another contribution
        </button>
      </div>
    );
  }

  if (status === 'expired') {
    return (
      <div className={`${cardBase} text-center`}>
        <h3 className="text-xl font-semibold text-tc-text">Payment expired</h3>
        <p className="mt-2 text-sm text-tc-text-dim">
          The payment window closed before funds were received.
        </p>
        <button onClick={reset} className={`${btnPrimary} mt-4`}>
          Try again
        </button>
      </div>
    );
  }

  if (step === 'payment' && payment) {
    const info = SUPPORTED_CURRENCIES[currency as CoinpayCurrency];
    return (
      <div className={`${cardBase} space-y-4`}>
        <div className="flex items-baseline justify-between">
          <h3 className="text-lg font-semibold text-tc-text">
            Pay with {info?.name ?? payment.currency}
          </h3>
          <span className="text-sm font-medium text-tc-green">
            {payment.amount_crypto} {info?.symbol}
          </span>
        </div>

        {payment.address && (
          <div className="flex justify-center py-2">
            <QRCodeCanvas value={payment.address} size={224} />
          </div>
        )}

        <div>
          <p className="text-xs text-tc-text-dim">Amount</p>
          <div className="mt-1 flex items-center gap-2">
            <code className="flex-1 rounded-lg bg-tc-darker px-3 py-2 text-sm text-tc-text">
              {payment.amount_crypto} {info?.symbol}
            </code>
            <button
              type="button"
              onClick={() => copy(String(payment.amount_crypto), 'amt')}
              className="rounded-lg border border-tc-border px-3 py-2 text-xs text-tc-text-dim hover:border-tc-green hover:text-tc-green"
            >
              {copied === 'amt' ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>

        {payment.address && (
          <div>
            <p className="text-xs text-tc-text-dim">Send to address</p>
            <div className="mt-1 flex items-center gap-2">
              <code className="flex-1 break-all rounded-lg bg-tc-darker px-3 py-2 text-xs text-tc-text">
                {payment.address}
              </code>
              <button
                type="button"
                onClick={() => copy(payment.address!, 'addr')}
                className="rounded-lg border border-tc-border px-3 py-2 text-xs text-tc-text-dim hover:border-tc-green hover:text-tc-green"
              >
                {copied === 'addr' ? 'Copied' : 'Copy'}
              </button>
            </div>
          </div>
        )}

        {payment.expires_at && (
          <p className="text-xs text-tc-text-dim">
            Expires at {new Date(payment.expires_at).toLocaleTimeString()}
          </p>
        )}

        <p className="text-xs text-tc-text-dim">Listening for confirmation...</p>

        <button
          onClick={reset}
          className="w-full rounded-lg border border-tc-border px-4 py-2 text-sm text-tc-text-dim hover:border-tc-green hover:text-tc-green"
        >
          Cancel
        </button>
      </div>
    );
  }

  if (step === 'currency' && tier) {
    const amount = tierAmount(tier, customAmount);
    return (
      <div className={`${cardBase} space-y-5`}>
        {error && (
          <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-400">
            {error}
          </div>
        )}

        <div className="flex items-baseline justify-between">
          <div>
            <h3 className="text-lg font-semibold text-tc-text">
              {TIERS.find((t) => t.id === tier)?.label ?? 'Custom'}
            </h3>
            <p className="text-sm text-tc-text-dim">${amount.toFixed(2)} USD</p>
          </div>
          <button
            onClick={() => setStep('tier')}
            className="text-sm text-tc-text-dim underline hover:text-tc-green"
          >
            Back
          </button>
        </div>

        <div className="grid gap-3 sm:grid-cols-2">
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Display name (optional)"
            className={inputCls}
          />
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="Email (optional)"
            className={inputCls}
          />
        </div>

        <div>
          <p className="mb-2 text-sm text-tc-text-dim">Pay with credit / debit card:</p>
          <button
            type="button"
            onClick={() => selectCurrency('card')}
            disabled={loading}
            className={`w-full rounded-xl border border-tc-border bg-tc-darker p-4 text-center transition-colors hover:border-tc-green disabled:opacity-50 ${
              loading && currency === 'card' ? 'border-tc-green' : ''
            }`}
          >
            <span className="block text-sm font-semibold text-tc-text">Credit / Debit Card</span>
            <span className="block text-xs text-tc-text-dim">Visa, Mastercard, Amex</span>
          </button>
        </div>

        <div>
          <p className="mb-2 text-sm text-tc-text-dim">Or pay with crypto:</p>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {(Object.entries(SUPPORTED_CURRENCIES) as [
              CoinpayCurrency,
              (typeof SUPPORTED_CURRENCIES)[CoinpayCurrency],
            ][])
              .filter(([key]) => key !== 'card')
              .map(([key, info]) => (
                <button
                  key={key}
                  type="button"
                  onClick={() => selectCurrency(key)}
                  disabled={loading}
                  className={`rounded-xl border border-tc-border bg-tc-darker p-4 text-center transition-colors hover:border-tc-green disabled:opacity-50 ${
                    loading && currency === key ? 'border-tc-green' : ''
                  }`}
                >
                  <span className="block text-sm font-semibold text-tc-text">{info.symbol}</span>
                  <span className="block text-xs text-tc-text-dim">{info.name}</span>
                </button>
              ))}
          </div>
        </div>
      </div>
    );
  }

  // tier step
  return (
    <div className="space-y-5">
      {error && (
        <div className="rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-400">
          {error}
        </div>
      )}
      <div className="grid gap-4 sm:grid-cols-3">
        {TIERS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => {
              setTier(t.id);
              setStep('currency');
            }}
            className={`rounded-2xl border p-6 text-left transition-colors hover:border-tc-green ${
              t.highlight
                ? 'border-tc-green bg-tc-green/5 glow-box'
                : 'border-tc-border bg-tc-card'
            }`}
          >
            <h3 className="font-semibold text-tc-text">{t.label}</h3>
            <p className="mt-1 text-2xl font-bold text-tc-green">${t.amount}</p>
            <p className="mt-2 text-sm text-tc-text-dim">{t.description}</p>
          </button>
        ))}

        <div className="rounded-2xl border border-tc-border bg-tc-card p-6">
          <h3 className="font-semibold text-tc-text">Custom amount</h3>
          <div className="mt-2 flex items-center gap-2">
            <span className="text-2xl font-bold text-tc-green">$</span>
            <input
              type="number"
              min={1}
              max={1_000_000}
              value={customAmount}
              onChange={(e) => setCustomAmount(Math.max(1, Number(e.target.value) || 0))}
              className="w-24 rounded-lg border border-tc-border bg-tc-darker px-2 py-1 text-2xl font-bold text-tc-green focus:border-tc-green focus:outline-none"
            />
          </div>
          <p className="mt-2 text-sm text-tc-text-dim">Pick any amount you want to contribute.</p>
          <button
            type="button"
            onClick={() => {
              setTier('custom');
              setStep('currency');
            }}
            className={`${btnPrimary} mt-3`}
          >
            Continue
          </button>
        </div>
      </div>
    </div>
  );
}
