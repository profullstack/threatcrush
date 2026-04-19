import { NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase';

function isSchemaCacheError(err: unknown): boolean {
  if (err && typeof err === 'object' && 'code' in err) {
    return (err as { code?: string }).code === 'PGRST205';
  }
  return false;
}

/**
 * Public funding total. Sums confirmed/forwarded payments from our
 * funding_payments table (populated by the CoinPay webhook).
 */
export async function GET() {
  let total = 0;
  let contributors = 0;
  try {
    const supabase = getSupabaseAdmin();
    const { data, error } = await supabase
      .from('funding_payments')
      .select('amount_usd')
      .in('status', ['confirmed', 'forwarded']);
    if (error) {
      if (isSchemaCacheError(error)) {
        return NextResponse.json(
          { error: 'Service unavailable', total_usd: 0, contributors: 0 },
          { status: 503 }
        );
      }
      console.error('[funding/total] query error:', error);
    }
    if (data) {
      contributors = data.length;
      total = data.reduce((sum, row) => sum + Number(row.amount_usd ?? 0), 0);
    }
  } catch (e) {
    if (isSchemaCacheError(e)) {
      return NextResponse.json(
        { error: 'Service unavailable', total_usd: 0, contributors: 0 },
        { status: 503 }
      );
    }
    console.error('[funding/total] supabase error:', e);
  }

  return NextResponse.json(
    {
      total_usd: Math.round(total * 100) / 100,
      contributors,
    },
    {
      headers: {
        'Cache-Control': 'public, s-maxage=60, stale-while-revalidate=120',
      },
    }
  );
}
