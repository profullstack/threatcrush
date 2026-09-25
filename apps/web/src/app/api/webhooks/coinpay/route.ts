import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';
import { verifyCoinpayWebhook, type CoinpayWebhookPayload } from '@/lib/coinpay-client';
import { isSettledStatus, SETTLED_STATUS_LIST } from '@/lib/payment-status';

/**
 * Webhook fields land in log lines, and a value containing CRLF can forge a
 * whole extra entry — enough to fake a settlement in an audit trail. Strip the
 * control characters and cap the length so a field can only ever be one token.
 */
export function logSafe(value: unknown): string {
  const collapsed = String(value ?? '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .slice(0, 200);
  // The range above has already removed CR and LF, so this pass changes
  // nothing at runtime. It stays because it is the form static analysis
  // recognises as neutralising log injection, and it is the last thing applied
  // to the returned value.
  return collapsed.replace(/\n|\r/g, ' ');
}

function getSupabase() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error('Supabase not configured');
  return createClient(url, key);
}

/**
 * Unified CoinPay webhook handler.
 *
 * Dispatches to the appropriate handler based on which table contains
 * the payment_id: funding_payments, license_purchases, or waitlist.
 */
export async function POST(request: NextRequest) {
  const rawBody = await request.text();
  const signature = request.headers.get('x-coinpay-signature');
  const secret = process.env.COINPAY_WEBHOOK_SECRET;
  const signatureValid =
    !!signature && !!secret && verifyCoinpayWebhook(rawBody, signature, secret);

  let payload: CoinpayWebhookPayload;
  try {
    payload = JSON.parse(rawBody) as CoinpayWebhookPayload;
  } catch {
    return NextResponse.json({ error: 'Invalid payload' }, { status: 400 });
  }

  console.log('[coinpay webhook] received', {
    type: logSafe(payload.type),
    signed: signatureValid,
  });

  const data = payload.data || ({} as CoinpayWebhookPayload['data']);
  const eventType = payload.type || (payload as { event?: string }).event || '';
  const paymentId =
    data.payment_id || (data as { id?: string }).id || (payload as { id?: string }).id;

  if (!paymentId) {
    return NextResponse.json({ error: 'Missing payment_id' }, { status: 400 });
  }

  let supabase;
  try {
    supabase = getSupabase();
  } catch (e) {
    console.error('[coinpay webhook] no supabase:', e);
    return NextResponse.json({ received: true, persisted: false });
  }

  // Check funding payments first.
  const { data: fundingRow } = await supabase
    .from('funding_payments')
    .select('id')
    .eq('coinpay_payment_id', paymentId)
    .maybeSingle();

  if (fundingRow) {
    if (!signatureValid) {
      return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
    }
    return handleFundingWebhook(supabase, data, eventType, paymentId);
  }

  // Check credit deposits (usage top-ups).
  const { data: creditRow } = await supabase
    .from('credit_deposits')
    .select('id, user_id, email, amount_usd')
    .eq('coinpay_payment_id', paymentId)
    .maybeSingle();

  if (creditRow) {
    if (!signatureValid) {
      console.warn('[coinpay webhook] credit deposit - invalid signature, skipping');
      return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
    }
    console.log('[coinpay webhook] processing credit deposit', {
      paymentId: logSafe(paymentId),
      eventType: logSafe(eventType),
      status: logSafe(data.status),
    });
    return handleCreditDepositWebhook(supabase, creditRow, data, eventType, paymentId);
  }

  // Check license purchases.
  const { data: licenseRow } = await supabase
    .from('license_purchases')
    .select('id, user_id, email')
    .eq('coinpay_payment_id', paymentId)
    .maybeSingle();

  if (licenseRow) {
    if (!signatureValid) {
      return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
    }
    return handleLicenseWebhook(supabase, licenseRow, data, eventType, paymentId);
  }

  // TC-09: the waitlist branch used to accept unsigned callbacks, so anyone who
  // could guess or observe a payment id could mark a waitlist row paid. Every
  // branch now requires a valid signature.
  if (!signatureValid) {
    return NextResponse.json({ error: 'Invalid signature' }, { status: 401 });
  }
  return handleWaitlistWebhook(supabase, data, eventType, paymentId);
}

/**
 * Writes a new payment status, refusing a settled → unsettled regression (TC-10)
 * atomically: the condition is part of the UPDATE, so a concurrent settle that
 * commits first makes this write match zero rows instead of overwriting it.
 * Returns whether the row was updated.
 */
async function updatePaymentStatus(
  supabase: ReturnType<typeof getSupabase>,
  table: 'funding_payments' | 'credit_deposits' | 'license_purchases',
  paymentId: string,
  nextStatus: string,
  patch: Record<string, unknown>,
): Promise<{ applied: boolean; error: unknown }> {
  let query = supabase
    .from(table)
    .update({ ...patch, status: nextStatus })
    .eq('coinpay_payment_id', paymentId);
  if (!isSettledStatus(nextStatus)) {
    query = query.not('status', 'in', SETTLED_STATUS_LIST);
  }
  const { data, error } = await query.select('id');
  if (error) return { applied: false, error };
  if (!data || data.length === 0) {
    console.warn(
      `[coinpay webhook] ignoring out-of-order ${nextStatus} for already-settled ${table} row ${logSafe(paymentId)}`,
    );
    return { applied: false, error: null };
  }
  return { applied: true, error: null };
}

const STALE_EVENT = { received: true, ignored: 'stale event' } as const;

async function handleFundingWebhook(
  supabase: ReturnType<typeof getSupabase>,
  data: CoinpayWebhookPayload['data'],
  eventType: string,
  paymentId: string,
) {
  const now = new Date().toISOString();
  const amountCrypto =
    typeof data.amount_crypto === 'string'
      ? parseFloat(data.amount_crypto)
      : (data.amount_crypto ?? null);

  let nextStatus: string | null = null;
  switch (eventType) {
    case 'payment.confirmed':
      nextStatus = 'confirmed';
      break;
    case 'payment.forwarded':
      nextStatus = 'forwarded';
      break;
    case 'payment.expired':
      nextStatus = 'expired';
      break;
    case 'payment.failed':
      nextStatus = 'failed';
      break;
    default:
      return NextResponse.json({ received: true, ignored: eventType });
  }

  const update: Record<string, unknown> = {
    updated_at: now,
    tx_hash: data.tx_hash ?? null,
  };
  if (amountCrypto !== null) update.amount_crypto = amountCrypto;
  if (isSettledStatus(nextStatus)) update.paid_at = now;

  const { applied, error } = await updatePaymentStatus(
    supabase,
    'funding_payments',
    paymentId,
    nextStatus,
    update,
  );

  if (error) {
    console.error('[coinpay webhook] funding update failed:', error);
    return NextResponse.json({ error: 'DB update failed' }, { status: 500 });
  }
  if (!applied) return NextResponse.json(STALE_EVENT);
  return NextResponse.json({ received: true });
}

async function handleCreditDepositWebhook(
  supabase: ReturnType<typeof getSupabase>,
  creditRow: { id: string; user_id: string; email: string; amount_usd: unknown },
  data: CoinpayWebhookPayload['data'],
  eventType: string,
  paymentId: string,
) {
  const now = new Date().toISOString();

  let nextStatus: string | null = null;
  switch (eventType) {
    case 'payment.confirmed':
      nextStatus = 'confirmed';
      break;
    case 'payment.forwarded':
      nextStatus = 'forwarded';
      break;
    case 'payment.expired':
      nextStatus = 'expired';
      break;
    case 'payment.failed':
      nextStatus = 'failed';
      break;
    default:
      console.log(`[coinpay webhook] ignoring event type: ${logSafe(eventType)}`);
      return NextResponse.json({ received: true, ignored: eventType });
  }

  const update: Record<string, unknown> = { updated_at: now };
  if (isSettledStatus(nextStatus)) update.confirmed_at = now;

  const { applied, error } = await updatePaymentStatus(
    supabase,
    'credit_deposits',
    paymentId,
    nextStatus,
    update,
  );

  if (error) {
    console.error('[coinpay webhook] credit deposit update failed:', JSON.stringify(error));
    return NextResponse.json({ error: 'DB update failed' }, { status: 500 });
  }
  if (!applied) return NextResponse.json(STALE_EVENT);
  if (isSettledStatus(nextStatus)) {
    // TC-26: the deposit amount and account email used to be logged in the
    // clear on every settlement.
    console.log(`[coinpay webhook] credited deposit ${creditRow.id} (status: ${nextStatus})`);
  }
  console.log(`[coinpay webhook] credit_deposits updated: ${logSafe(paymentId)} -> ${nextStatus}`);
  return NextResponse.json({ received: true });
}

async function handleLicenseWebhook(
  supabase: ReturnType<typeof getSupabase>,
  licenseRow: { id: string; user_id: string; email: string },
  data: CoinpayWebhookPayload['data'],
  eventType: string,
  paymentId: string,
) {
  const now = new Date().toISOString();

  let status: string;
  switch (eventType) {
    case 'payment.confirmed':
    case 'payment.forwarded':
      status = 'confirmed';
      break;
    case 'payment.expired':
      status = 'expired';
      break;
    case 'payment.failed':
      status = 'failed';
      break;
    default:
      return NextResponse.json({ received: true, ignored: eventType });
  }

  const { applied, error } = await updatePaymentStatus(
    supabase,
    'license_purchases',
    paymentId,
    status,
    { updated_at: now },
  );
  if (error) {
    console.error('[coinpay webhook] license purchase update failed:', error);
    return NextResponse.json({ error: 'DB update failed' }, { status: 500 });
  }
  if (!applied) return NextResponse.json(STALE_EVENT);

  // If confirmed, activate the license
  if (status === 'confirmed') {
    const { error: profileErr } = await supabase
      .from('user_profiles')
      .update({
        license_status: 'active',
        updated_at: now,
      })
      .eq('id', licenseRow.user_id);

    if (profileErr) {
      console.error('[coinpay webhook] license activation failed:', profileErr);
      return NextResponse.json({ error: 'License activation failed' }, { status: 500 });
    }

    console.log(`[coinpay webhook] License activated for purchase ${logSafe(licenseRow.id)}`);
  }

  return NextResponse.json({ received: true, status });
}

async function handleWaitlistWebhook(
  supabase: ReturnType<typeof getSupabase>,
  data: CoinpayWebhookPayload['data'],
  eventType: string,
  paymentId: string,
) {
  const status = data.status;
  if (
    !['payment.confirmed', 'payment.forwarded'].includes(eventType) &&
    !['confirmed', 'forwarded'].includes(status as string)
  ) {
    console.log(`[coinpay webhook] Ignoring waitlist event: ${logSafe(eventType)} / ${logSafe(status)}`);
    return NextResponse.json({ ok: true });
  }

  const { data: entry } = await supabase
    .from('waitlist')
    .select('id, email, paid')
    .eq('payment_id', paymentId)
    .maybeSingle();

  if (!entry) {
    console.warn(`[coinpay webhook] No funding or waitlist row for ${logSafe(paymentId)}`);
    return NextResponse.json({ ok: true });
  }

  if (entry.paid) {
    return NextResponse.json({ ok: true });
  }

  await supabase
    .from('waitlist')
    .update({
      paid: true,
      paid_at: new Date().toISOString(),
      payment_status: 'confirmed',
    })
    .eq('id', entry.id);

  const { data: fullEntry } = await supabase
    .from('waitlist')
    .select('referred_by')
    .eq('id', entry.id)
    .single();

  if (fullEntry?.referred_by) {
    await supabase
      .from('waitlist')
      .update({ amount_usd: 399 })
      .eq('referral_code', fullEntry.referred_by)
      .eq('paid', false);
  }

  return NextResponse.json({ ok: true, email: entry.email });
}
