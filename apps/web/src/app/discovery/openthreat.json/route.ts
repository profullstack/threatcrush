import { NextResponse } from "next/server";
import { loadOpenThreat } from "@/lib/open-threats";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

/** GET /discovery/openthreat.json: the same descriptor as /.well-known/openthreat.json, beside the page. */
export async function GET() {
  try {
    const descriptor = await loadOpenThreat();
    return NextResponse.json(descriptor, {
      headers: {
        "cache-control": "public, max-age=300",
        "access-control-allow-origin": "*",
      },
    });
  } catch (err) {
    console.error("[openthreat] could not build descriptor", (err as Error).message);
    return NextResponse.json({ error: "descriptor unavailable" }, { status: 503 });
  }
}
