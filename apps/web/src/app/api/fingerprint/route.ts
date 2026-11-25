import { NextResponse, type NextRequest } from "next/server";
import { cleanHost, getFingerprint, isForbiddenHost } from "@/lib/fingerprint";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Only well-known TLS ports, so this can't be used as an arbitrary port scanner.
const ALLOWED_PORTS = new Set([443, 8443, 993, 995, 465, 990, 563]);

/**
 * POST /api/fingerprint { host, port? } — read a public site's TLS certificate
 * fingerprint so a visitor can compare it to their browser's. Reading a public
 * cert is safe; private/loopback hosts and non-TLS ports are refused.
 */
export async function POST(req: NextRequest) {
  let body: { host?: string; port?: number } = {};
  try { body = (await req.json()) as { host?: string; port?: number }; } catch { /* */ }

  const host = cleanHost(String(body.host ?? ""));
  if (!host || !/^[a-z0-9.-]+$/i.test(host)) {
    return NextResponse.json({ error: "A valid public hostname is required." }, { status: 400 });
  }
  if (isForbiddenHost(host)) {
    return NextResponse.json({ error: "Fingerprint only reads public hosts, not private or loopback addresses." }, { status: 400 });
  }
  const port = Number(body.port ?? 443);
  if (!ALLOWED_PORTS.has(port)) {
    return NextResponse.json({ error: `Port ${port} is not an allowed TLS port.` }, { status: 400 });
  }

  try {
    const fp = await getFingerprint(host, port);
    return NextResponse.json(fp);
  } catch (err) {
    return NextResponse.json({ error: err instanceof Error ? err.message : "could not read certificate" }, { status: 502 });
  }
}

export function GET() {
  return NextResponse.json(
    { service: "ThreatCrush TLS Fingerprint", method: "POST", note: "POST { host, port? } to read a public site's cert fingerprint." },
    { status: 405, headers: { allow: "POST" } },
  );
}
