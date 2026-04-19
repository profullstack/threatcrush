import { NextRequest, NextResponse } from "next/server";
import { getSupabaseClient, getSupabaseAdmin } from "@/lib/supabase";

interface UsageEvent {
  timestamp: string;
  module: string;
  action: string;
  cost_usd: number;
  status: string;
  id?: string;
}

/** Compute daily_spend and module_breakdown from real usage history */
function computeBreakdowns(history: UsageEvent[], now: Date) {
  const monthAgo = new Date(now);
  monthAgo.setDate(monthAgo.getDate() - 30);
  const monthEvents = history.filter((h) => new Date(h.timestamp) >= monthAgo);
  const monthUsd = monthEvents.reduce((s, e) => s + (e.cost_usd || 0), 0);

  // Daily breakdown (last 30 days)
  const dailySpend: Array<{ date: string; amount: number; requests: number }> = [];
  for (let d = 29; d >= 0; d--) {
    const day = new Date(now);
    day.setDate(day.getDate() - d);
    const dateStr = day.toISOString().slice(0, 10);
    const dayEvents = history.filter((h) => h.timestamp?.startsWith(dateStr));
    dailySpend.push({
      date: dateStr,
      amount: +dayEvents.reduce((s, e) => s + (e.cost_usd || 0), 0).toFixed(2),
      requests: dayEvents.length,
    });
  }

  // Module breakdown
  const moduleMap = new Map<string, { module: string; action: string; requests: number; cost: number }>();
  for (const evt of monthEvents) {
    const key = `${evt.module || "unknown"}|${evt.action || "unknown"}`;
    const existing = moduleMap.get(key) || { module: evt.module || "unknown", action: evt.action || "unknown", requests: 0, cost: 0 };
    existing.requests += 1;
    existing.cost += evt.cost_usd || 0;
    moduleMap.set(key, existing);
  }
  const moduleBreakdown = Array.from(moduleMap.values())
    .map((m) => ({
      ...m,
      cost: +m.cost.toFixed(2),
      percentage: monthUsd > 0 ? +((m.cost / monthUsd) * 100).toFixed(0) : 0,
    }))
    .sort((a, b) => b.cost - a.cost);

  return { daily_spend: dailySpend, module_breakdown: moduleBreakdown };
}

export async function GET(request: NextRequest) {
  try {
    // Authenticate via Bearer token
    const authHeader = request.headers.get("authorization");
    const token = authHeader?.replace("Bearer ", "");

    if (!token) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const supabase = getSupabaseClient();
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError || !user?.email) {
      return NextResponse.json({ error: "Invalid or expired token" }, { status: 401 });
    }

    const admin = getSupabaseAdmin();

    // Compute balance = confirmed credits - usage costs
    const { data: deposits, error: depositErr } = await admin
      .from("credit_deposits")
      .select("amount_usd, status")
      .eq("user_id", user.id)
      .in("status", ["confirmed", "forwarded"]);

    if (depositErr) {
      console.error("[usage] deposit query error:", depositErr);
    }

    const totalCredits = (deposits || []).reduce((sum, d) => sum + Number(d.amount_usd || 0), 0);

    // Fetch usage events (last 30 days)
    const now = new Date();
    const monthAgo = new Date(now);
    monthAgo.setDate(monthAgo.getDate() - 30);

    const { data: events, error: eventsErr } = await admin
      .from("usage_events")
      .select("id, module, action, cost_usd, created_at")
      .eq("user_id", user.id)
      .gte("created_at", monthAgo.toISOString())
      .order("created_at", { ascending: false })
      .limit(1000);

    if (eventsErr) {
      console.error("[usage] events query error:", eventsErr);
    }

    const totalUsage = (events || []).reduce((sum, e) => sum + Number(e.cost_usd || 0), 0);
    const balanceUsd = +(totalCredits - totalUsage).toFixed(2);

    // Transform events to the expected format
    const history: UsageEvent[] = (events || []).map((e) => ({
      id: e.id,
      timestamp: e.created_at,
      module: e.module,
      action: e.action,
      cost_usd: Number(e.cost_usd || 0),
      status: "completed",
    }));

    const todayStr = now.toISOString().slice(0, 10);
    const weekAgo = new Date(now);
    weekAgo.setDate(weekAgo.getDate() - 7);

    const todayEvents = history.filter((h) => h.timestamp?.startsWith(todayStr));
    const weekEvents = history.filter((h) => new Date(h.timestamp) >= weekAgo);

    const sum = (evts: UsageEvent[]) => +evts.reduce((s, e) => s + (e.cost_usd || 0), 0).toFixed(2);

    const todayUsd = sum(todayEvents);
    const weekUsd = sum(weekEvents);
    const monthUsd = sum(history);
    const burnRateDaily = +(monthUsd / 30).toFixed(2);

    const breakdowns = computeBreakdowns(history, now);

    // Fetch payment/deposit history
    const { data: payments, error: paymentsErr } = await admin
      .from("credit_deposits")
      .select("id, coinpay_payment_id, amount_usd, status, created_at")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false })
      .limit(50);

    if (paymentsErr) {
      console.error("[usage] payments query error:", paymentsErr);
    }

    const paymentHistory = (payments || []).map((p) => ({
      id: p.id,
      coinpay_payment_id: p.coinpay_payment_id,
      amount_usd: Number(p.amount_usd || 0),
      status: p.status,
      created_at: p.created_at,
    }));

    return NextResponse.json({
      balance_usd: balanceUsd,
      today_usd: todayUsd,
      today_requests: todayEvents.length,
      week_usd: weekUsd,
      week_requests: weekEvents.length,
      month_usd: monthUsd,
      month_requests: history.length,
      burn_rate_daily: burnRateDaily,
      estimated_days_remaining: burnRateDaily > 0 ? Math.floor(balanceUsd / burnRateDaily) : 999,
      projected_monthly_usd: +(burnRateDaily * 30).toFixed(2),
      payment_history: paymentHistory,
      ...breakdowns,
      history: history.slice(0, 20),
      demo: false,
    });
  } catch (error) {
    console.error("[usage] Error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
