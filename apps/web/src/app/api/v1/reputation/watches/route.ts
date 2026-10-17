import { NextResponse, type NextRequest } from "next/server";
import { unauthorized } from "@/lib/api-auth";
import { KEY_REQUIRED, reputationCaller } from "@/lib/reputation-auth";
import { parseIndicator } from "@/lib/reputation-service";
import { MAX_WATCHES_PER_ORG } from "@/lib/reputation-watches";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const COLUMNS =
  "id, indicator, kind, destination_id, note, last_listed, last_score, last_reasons, last_checked_at, last_changed_at, created_at";

/** GET: the org's watch list. */
export async function GET(req: NextRequest) {
  const who = await reputationCaller(req);
  if (!who) return unauthorized(KEY_REQUIRED);
  if (!who.orgId) return NextResponse.json({ error: "Name the org with ?org=<id>." }, { status: 400 });
  const { data, error } = await who.admin
    .from("reputation_watches")
    .select(COLUMNS)
    .eq("org_id", who.orgId)
    .order("created_at", { ascending: true });
  if (error) return NextResponse.json({ error: "watches unavailable" }, { status: 503 });
  return NextResponse.json({ tier: who.tier, max: MAX_WATCHES_PER_ORG, watches: data ?? [] });
}

/**
 * POST { indicator, note?, destination_id?, org? } — watch an IP or domain.
 * Reputation Pro only; an agent key needs write. Alerts go to
 * `destination_id`, or every enabled alert destination of the org.
 */
export async function POST(req: NextRequest) {
  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Send JSON: { indicator, note?, destination_id? }" }, { status: 400 });
  }
  const who = await reputationCaller(req, typeof body.org === "string" ? body.org : null);
  if (!who) return unauthorized(KEY_REQUIRED);
  if (!who.orgId) return NextResponse.json({ error: "Name the org as org." }, { status: 400 });
  if (who.principal.kind === "agent" && who.principal.role === "read") {
    return NextResponse.json({ error: "Adding a watch needs a write or admin key." }, { status: 403 });
  }
  if (who.tier !== "pro") {
    return NextResponse.json(
      { error: "Watch lists are part of Reputation Pro.", upgrade: "https://threatcrush.com/reputation" },
      { status: 402 },
    );
  }
  const ind = parseIndicator(String(body.indicator ?? ""));
  if (!ind) return NextResponse.json({ error: "indicator must be a public IP address or a domain" }, { status: 400 });

  const { count } = await who.admin
    .from("reputation_watches")
    .select("id", { count: "exact", head: true })
    .eq("org_id", who.orgId);
  if ((count ?? 0) >= MAX_WATCHES_PER_ORG) {
    return NextResponse.json({ error: `At most ${MAX_WATCHES_PER_ORG} watches per org.` }, { status: 409 });
  }

  const destination = typeof body.destination_id === "string" ? body.destination_id : null;
  if (destination) {
    const { data: dest } = await who.admin
      .from("alert_destinations")
      .select("id")
      .eq("id", destination)
      .eq("organization_id", who.orgId)
      .maybeSingle();
    if (!dest) return NextResponse.json({ error: "No such alert destination in this org." }, { status: 404 });
  }
  const note = typeof body.note === "string" ? body.note.slice(0, 200) : null;
  const { data, error } = await who.admin
    .from("reputation_watches")
    .upsert(
      { org_id: who.orgId, indicator: ind.value, kind: ind.type, destination_id: destination, note },
      { onConflict: "org_id,indicator" },
    )
    .select(COLUMNS)
    .single();
  if (error) return NextResponse.json({ error: "Could not save the watch" }, { status: 500 });
  return NextResponse.json({ watch: data }, { status: 201 });
}

/** DELETE ?indicator=<ip-or-domain>[&org=] — stop watching. */
export async function DELETE(req: NextRequest) {
  const who = await reputationCaller(req);
  if (!who) return unauthorized(KEY_REQUIRED);
  if (!who.orgId) return NextResponse.json({ error: "Name the org with ?org=<id>." }, { status: 400 });
  if (who.principal.kind === "agent" && who.principal.role === "read") {
    return NextResponse.json({ error: "Removing a watch needs a write or admin key." }, { status: 403 });
  }
  const ind = parseIndicator(new URL(req.url).searchParams.get("indicator") ?? "");
  if (!ind) return NextResponse.json({ error: "indicator is required" }, { status: 400 });
  const { data } = await who.admin
    .from("reputation_watches")
    .delete()
    .eq("org_id", who.orgId)
    .eq("indicator", ind.value)
    .select("id");
  return NextResponse.json({ removed: (data ?? []).length });
}
