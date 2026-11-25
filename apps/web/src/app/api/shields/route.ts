import { NextResponse, type NextRequest } from "next/server";
import { clientIpv4, scanClientPorts, type ShieldsTest } from "@/lib/shields";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/**
 * POST /api/shields — the Shields firewall self-test (free, no auth).
 *
 * It scans ONLY the caller's own public IPv4, derived from the connection. It
 * deliberately does not accept a target in the body: you can only test your own
 * connection, exactly like the classic ShieldsUP! service. That constraint is
 * the whole safety model, so do not add a `target` parameter here.
 */

const TESTS: Record<string, ShieldsTest> = { common: "common", "file-sharing": "file-sharing", all: "all" };

// Best-effort per-IP throttle: one in-flight scan per IP, and a short cooldown.
const lastScan = new Map<string, number>();
const COOLDOWN_MS = 4000;

export async function POST(req: NextRequest) {
  const ip = clientIpv4(req.headers);
  if (!ip) {
    return NextResponse.json(
      { error: "Shields could not determine your public IPv4. If you are on an IPv6-only connection or behind a corporate proxy, this self-test is not available." },
      { status: 400 },
    );
  }

  let body: { test?: string } = {};
  try {
    body = (await req.json()) as { test?: string };
  } catch {
    // empty body is fine — defaults to the common-ports test
  }
  const test = TESTS[String(body.test ?? "common")] ?? "common";

  const now = Date.now();
  const prev = lastScan.get(ip) ?? 0;
  if (now - prev < COOLDOWN_MS) {
    return NextResponse.json({ error: "A scan for your connection is already in progress. Try again in a few seconds." }, { status: 429 });
  }
  lastScan.set(ip, now);

  try {
    // The full 0–1055 sweep is heavier, so probe it faster and wider.
    const scan = await scanClientPorts(ip, test, test === "all"
      ? { concurrency: 128, timeoutMs: 1500 }
      : { concurrency: 64, timeoutMs: 3000 });
    return NextResponse.json({
      target: scan.target,
      test: scan.test,
      ...scan.summary,
      ports: scan.ports,
    });
  } catch (err) {
    return NextResponse.json({ error: err instanceof Error ? err.message : "scan failed" }, { status: 502 });
  } finally {
    lastScan.delete(ip);
  }
}

export function GET() {
  return NextResponse.json(
    { service: "ThreatCrush Shields", method: "POST", note: "Scans only your own connection's public IPv4. POST { test: 'common' | 'file-sharing' | 'all' }." },
    { status: 405, headers: { allow: "POST" } },
  );
}
