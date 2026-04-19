import { NextResponse } from 'next/server';
import { getSupabaseAdmin } from '@/lib/supabase';

function isSchemaCacheError(err: unknown): boolean {
  if (err && typeof err === 'object' && 'code' in err) {
    return (err as { code?: string }).code === 'PGRST205';
  }
  return false;
}

/**
 * Public list of recent confirmed contributions.
 * Returns at most 10 entries, anonymized to display name only.
 */
export async function GET() {
  try {
    const supabase = getSupabaseAdmin();
    const { data, error } = await supabase
      .from('funding_payments')
      .select('id, contributor_name, amount_usd, currency, paid_at, created_at, status')
      .in('status', ['confirmed', 'forwarded'])
      .order('paid_at', { ascending: false, nullsFirst: false })
      .limit(10);

    if (error) {
      console.error('[funding/contributors] query failed:', error);
      if (isSchemaCacheError(error)) {
        return NextResponse.json(
          { error: 'Service unavailable', transactions: [] },
          { status: 503 }
        );
      }
      return NextResponse.json({ transactions: [] });
    }

    const transactions = (data ?? []).map((p) => ({
      id: p.id,
      name: (p.contributor_name as string) || 'Anonymous',
      amount_usd: Number(p.amount_usd) || 0,
      currency: p.currency,
      paid_at: p.paid_at || p.created_at,
    }));

    return NextResponse.json(
      { transactions },
      {
        headers: {
          'Cache-Control': 'public, s-maxage=60, stale-while-revalidate=120',
        },
      }
    );
  } catch (e) {
    console.error('[funding/contributors] supabase error:', e);
    if (isSchemaCacheError(e)) {
      return NextResponse.json(
        { error: 'Service unavailable', transactions: [] },
        { status: 503 }
      );
    }
    return NextResponse.json({ transactions: [] });
  }
}
