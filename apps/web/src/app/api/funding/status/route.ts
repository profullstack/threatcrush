import { NextRequest, NextResponse } from 'next/server';
import { getCoinpayPaymentStatus } from '@/lib/coinpay-client';
import { getSupabaseAdmin } from '@/lib/supabase';
import { isSettledStatus, SETTLED_STATUS_LIST } from '@/lib/payment-status';

function isSchemaCacheError(err: unknown): boolean {
  if (err && typeof err === 'object' && 'code' in err) {
    return (err as { code?: string }).code === 'PGRST205';
  }
  return false;
}

export async function GET(req: NextRequest) {
  const paymentId = req.nextUrl.searchParams.get('payment_id');
  if (!paymentId) {
    return NextResponse.json({ error: 'payment_id required' }, { status: 400 });
  }

  let supabase;
  try {
    supabase = getSupabaseAdmin();
  } catch {
    supabase = null;
  }

  if (supabase) {
    try {
      const { data, error } = await supabase
        .from('funding_payments')
        .select('status, tx_hash, updated_at')
        .eq('coinpay_payment_id', paymentId)
        .maybeSingle();
      if (error) {
        if (isSchemaCacheError(error)) {
          // Fall through to live CoinPay check
        } else {
          console.error('[funding/status] query error:', error);
        }
      } else if (data && ['forwarded', 'failed', 'expired'].includes(data.status as string)) {
        return NextResponse.json(data);
      }
    } catch (e) {
      if (isSchemaCacheError(e)) {
        // Fall through to live CoinPay check
      } else {
        console.error('[funding/status] supabase error:', e);
      }
    }
  }

  const live = await getCoinpayPaymentStatus(paymentId);

  if (supabase && live.status) {
    try {
      const settled = isSettledStatus(live.status);
      let update = supabase
        .from('funding_payments')
        .update({
          status: live.status,
          tx_hash: live.tx_hash ?? null,
          updated_at: new Date().toISOString(),
          ...(settled ? { paid_at: new Date().toISOString() } : {}),
        })
        .eq('coinpay_payment_id', paymentId);
      // TC-10: a lagging or defaulted ('pending') live status must not
      // regress a payment the webhook has already settled.
      if (!settled) update = update.not('status', 'in', SETTLED_STATUS_LIST);
      await update;
    } catch (e) {
      if (!isSchemaCacheError(e)) {
        console.error('[funding/status] update error:', e);
      }
      // Still return the live status even if DB update fails
    }
  }

  return NextResponse.json({ status: live.status, tx_hash: live.tx_hash });
}
