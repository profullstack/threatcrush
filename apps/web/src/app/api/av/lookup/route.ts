import { NextRequest, NextResponse } from "next/server";
import { LOOKUP_BATCH, SHA256_RE, type HashReputation } from "@threatcrush/av";
import { lookupReputations } from "@/lib/av-reputation";

// CrushAV hash reputation, for every CrushAV surface: the CLI, the desktop
// app, the mobile app and the in-browser scanner on /antivirus. Browsers can't
// ask CIRCL directly (its CORS allows only its own origin), so they ask here.
//
// POST /api/av/lookup {hashes: string[]}  (up to 100 lower-case SHA-256)
// -> {results: {[sha256]: HashReputation}}  only hashes something is known about
//
// Only hashes are accepted: no file names, no contents. Nothing is stored or
// logged beyond an in-memory cache. Unauthenticated and rate limited (middleware).

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS });
}

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Body must be JSON" }, { status: 400, headers: CORS });
  }
  const raw = (body as { hashes?: unknown } | null)?.hashes;
  if (!Array.isArray(raw)) return NextResponse.json({ error: "hashes array is required" }, { status: 400, headers: CORS });
  const hashes = [
    ...new Set(raw.filter((x): x is string => typeof x === "string").map((x) => x.trim().toLowerCase()).filter((x) => SHA256_RE.test(x))),
  ];
  if (hashes.length > LOOKUP_BATCH) {
    return NextResponse.json({ error: `at most ${LOOKUP_BATCH} hashes per request` }, { status: 413, headers: CORS });
  }
  const found = await lookupReputations(hashes);
  const results: Record<string, HashReputation> = {};
  for (const [h, rep] of found) results[h] = rep;
  return NextResponse.json(
    { results, sources: ["hashlookup.circl.lu", ...(malwareBazaarKey() ? ["MalwareBazaar"] : [])] },
    { headers: CORS },
  );
}

/** Read at request time: Next.js inlines `process.env.NAME` at build. */
function malwareBazaarKey(): string {
  const name = "ABUSECH_AUTH_KEY";
  return process.env[name] ?? "";
}
