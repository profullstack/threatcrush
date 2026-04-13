import { NextRequest, NextResponse } from "next/server";

const COINPAY_API_URL = process.env.COINPAYPORTAL_API_URL || "https://api.coinpayportal.com";
const COINPAY_API_KEY = process.env.COINPAYPORTAL_API_KEY;
const COINPAY_BUSINESS_ID = process.env.COINPAYPORTAL_BUSINESS_ID;

interface UsageEvent {
  timestamp: string;
  module: string;
  action: string;
  cost_usd: number;
  status: string;
  id?: string;
}

/** Compute daily_spend and module_breakdown from real API history */
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
    const email = request.nextUrl.searchParams.get("email");

    if (!email) {
      return NextResponse.json({ error: "email required" }, { status: 400 });
    }

    if (!COINPAY_API_KEY || !COINPAY_BUSINESS_ID) {
      return NextResponse.json({
        error: "Usage API not configured. Set COINPAYPORTAL_API_KEY and COINPAYPORTAL_BUSINESS_ID.",
      }, { status: 503 });
    }

    const headers = {
      Authorization: `Bearer ${COINPAY_API_KEY}`,
      "Content-Type": "application/json",
    };

    const now = new Date();
    const monthAgo = new Date(now);
    monthAgo.setDate(monthAgo.getDate() - 30);

    // Fetch balance and history in parallel
    const [creditsRes, historyRes] = await Promise.all([
      fetch(`${COINPAY_API_URL}/api/businesses/${COINPAY_BUSINESS_ID}/usage/credits?email=${encodeURIComponent(email)}`, { headers }),
      fetch(`${COINPAY_API_URL}/api/businesses/${COINPAY_BUSINESS_ID}/usage/history?email=${encodeURIComponent(email)}&from=${monthAgo.toISOString()}&to=${now.toISOString()}`, { headers }),
    ]);

    if (!creditsRes.ok || !historyRes.ok) {
      console.error("[usage] API error", creditsRes.status, historyRes.status);
      return NextResponse.json({ error: "Failed to fetch usage data from billing provider" }, { status: 502 });
    }

    const credits = await creditsRes.json();
    const historyData = await historyRes.json();

    const balanceUsd = credits.balance_usd || 0;
    const history: UsageEvent[] = historyData.events || historyData.history || [];

    const todayStr = now.toISOString().slice(0, 10);
    const weekAgo = new Date(now);
    weekAgo.setDate(weekAgo.getDate() - 7);

    const todayEvents = history.filter((h) => h.timestamp?.startsWith(todayStr));
    const weekEvents = history.filter((h) => new Date(h.timestamp) >= weekAgo);

    const sum = (events: UsageEvent[]) => +events.reduce((s, e) => s + (e.cost_usd || 0), 0).toFixed(2);

    const todayUsd = sum(todayEvents);
    const weekUsd = sum(weekEvents);
    const monthUsd = sum(history);
    const burnRateDaily = +(monthUsd / 30).toFixed(2);

    const breakdowns = computeBreakdowns(history, now);

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
      ...breakdowns,
      history: history.slice(0, 20),
      demo: false,
    });
  } catch (error) {
    console.error("[usage] Error:", error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
