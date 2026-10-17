import { NextResponse, type NextRequest } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { takeLookupShared } from "@/lib/reputation";
import { allowanceHeaders, KEY_REQUIRED, reputationCaller } from "@/lib/reputation-auth";
import { lookupIndicator, parseIndicator, type AnyReport } from "@/lib/reputation-service";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** Indicators per request: a free key checks a page of logs, Pro a whole day's. */
const BULK_LIMIT ={ free: 100, pro: 1000 } as const;
const CONCURRENCY = 10;

/**
 * POST /api/v1/reputation/bulk { indicators: ["1.2.3.4", "evil.example", …], org? }
 * Every indicator counts against the daily allowance. Unparseable entries come
 * back as errors in place; the order of `results` matches the request.
 */
export async function POST(req: NextRequest) {
  let body: { indicators?: unknown; org?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Send JSON: { "indicators": ["1.2.3.4", …] }' }, { status: 400 });
  }
  const who = await reputationCaller(req, typeof body.org === "string" ? body.org : null);
  if (!who) return unauthorized(KEY_REQUIRED);
  const list = Array.isArray(body.indicators) ? body.indicators.map((v) => String(v ?? "")) : [];
  if (list.length === 0) return NextResponse.json({ error: "indicators must be a non-empty array" }, { status: 400 });
  const max = BULK_LIMIT[who.tier];
  if (list.length > max) {
    return NextResponse.json(
      { error: `At most ${max} indicators per request on ${who.tier === "pro" ? "Reputation Pro" : "a free key"}.` },
      { status: 413 },
    );
  }

  const parsed = list.map((raw) => ({ raw, ind: parseIndicator(raw) }));
  const valid = parsed.filter((p) => p.ind).length;
  const allowance = await takeLookupShared(who.admin, who.caller, who.tier, valid);
  const headers = allowanceHeaders(who.tier, allowance);
  if (!allowance.ok) {
    return NextResponse.json(
      { error: `This request needs ${valid} lookups; the daily allowance of ${allowance.limit} would be exceeded.` },
      { status: 429, headers },
    );
  }

  const results: Array<AnyReport | { query: string; error: string }> = new Array(parsed.length);
  let next = 0;
  async function worker() {
    while (next < parsed.length) {
      const i = next++;
      const { raw, ind } = parsed[i];
      if (!ind) {
        results[i] = { query: raw, error: "not a public IP address or a domain" };
        continue;
      }
      try {
        results[i] = await lookupIndicator(who!.admin, ind, who!.tier);
      } catch (err) {
        results[i] = { query: raw, error: (err as Error).message || "lookup failed" };
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, parsed.length) }, worker));
  const listed = results.filter((r) => "listed" in r && r.listed).length;
  return NextResponse.json({ count: results.length, listed, results }, { headers });
}
