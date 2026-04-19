import { NextRequest, NextResponse } from 'next/server';
import {
  createCoinpayPayment,
  SUPPORTED_CURRENCIES,
  type CoinpayCurrency,
} from '@/lib/coinpay-client';
import { getSupabaseAdmin } from '@/lib/supabase';

const SUPPORTED_KEYS = Object.keys(SUPPORTED_CURRENCIES) as CoinpayCurrency[];

function isSchemaCacheError(err: unknown): boolean {
  if (err && typeof err === 'object' && 'code' in err) {
    return (err as { code?: string }).code === 'PGRST205';
  }
  return false;
}

interface Body {
  amount_usd?: unknown;
  currency?: unknown;
  contributor_name?: unknown;
  contributor_email?: unknown;
}

export async function POST(req: NextRequest) {
  let body: Body;
  try {
    body = (await req.json()) as Body;
  } catch {
    return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });
  }

  const amount_usd = Number(body.amount_usd);
  if (!Number.isFinite(amount_usd) || amount_usd < 1 || amount_usd > 1_000_000) {
    return NextResponse.json({ error: 'amount_usd must be between 1 and 1000000' }, { status: 400 });
  }
  const currency = body.currency as CoinpayCurrency;
  if (!SUPPORTED_KEYS.includes(currency)) {
    return NextResponse.json({ error: 'Unsupported currency' }, { status: 400 });
  }
  const contributor_name =
    typeof body.contributor_name === 'string' && body.contributor_name.trim()
      ? body.contributor_name.trim().slice(0, 120)
      : null;
  const contributor_email =
    typeof body.contributor_email === 'string' && body.contributor_email.trim()
      ? body.contributor_email.trim().slice(0, 200)
      : null;

  const cp = await createCoinpayPayment({
    amount_usd,
    currency,
    description: `threatcrush funding ($${amount_usd})`,
    metadata: { contributor_name, contributor_email },
  });

  const payment = cp.payment ?? {};
  const paymentId = cp.payment_id ?? payment.id;
  const address = cp.address ?? payment.payment_address ?? null;
  const amountCrypto =
    cp.amount_crypto ?? payment.amount_crypto ?? payment.crypto_amount ?? null;
  const expiresAt = cp.expires_at ?? payment.expires_at ?? null;
  const checkoutUrl =
    payment.stripe_checkout_url ?? cp.checkout_url ?? payment.checkout_url ?? null;
  const respCurrency = cp.currency ?? payment.currency ?? currency;

  if (!paymentId) {
    return NextResponse.json({ error: 'CoinPay did not return a payment id' }, { status: 502 });
  }

  try {
    const supabase = getSupabaseAdmin();
    const { error } = await supabase.from('funding_payments').insert({
      coinpay_payment_id: paymentId,
      amount_usd,
      amount_crypto: amountCrypto,
      // Preserve the user's chosen rail. CoinPay returns usdc_pol for
      // card payments (routed through Stripe), but we want the
      // contributors list to show "Credit Card (via CoinPay)".
      currency: currency === 'card' ? 'card' : respCurrency,
      status: 'pending',
      contributor_name,
      contributor_email,
      metadata: { checkout_url: checkoutUrl, expires_at: expiresAt },
    });
    if (error) {
      if (isSchemaCacheError(error)) {
        console.error('[funding/create-invoice] schema cache error (table missing):', error);
        return NextResponse.json(
          { error: 'Service unavailable' },
          { status: 503 }
        );
      }
      console.error('[funding/create-invoice] insert failed:', error);
    }
  } catch (e) {
    if (isSchemaCacheError(e)) {
      console.error('[funding/create-invoice] schema cache error (table missing):', e);
      return NextResponse.json(
        { error: 'Service unavailable' },
        { status: 503 }
      );
    }
    console.error('[funding/create-invoice] supabase unavailable:', e);
  }

  return NextResponse.json({
    payment_id: paymentId,
    address,
    amount_crypto: amountCrypto,
    currency: respCurrency,
    expires_at: expiresAt,
    checkout_url: checkoutUrl,
  });
}
