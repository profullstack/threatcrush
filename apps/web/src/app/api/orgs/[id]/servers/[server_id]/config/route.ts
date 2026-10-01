import { NextRequest, NextResponse } from "next/server";
import { requireServer } from "@/lib/route-access";
import { MAX_CONFIG_BYTES, isPlainObject, redactConfig } from "@/lib/server-config";

// PUT /api/orgs/[org_id]/servers/[id]/config — `threatcrush save` stores the
// machine's daemon config (secrets redacted) on its server row. Write access:
// it is something the machine reports, like a heartbeat.
export async function PUT(
  req: NextRequest,
  { params }: { params: Promise<{ id: string; server_id: string }> }
) {
  try {
    const { id: orgId, server_id } = await params;
    const access = await requireServer(req, orgId, server_id, "write", "id, org_id, fleet_id");
    if ("error" in access) return access.error;

    const raw = await req.text();
    if (Buffer.byteLength(raw) > MAX_CONFIG_BYTES) {
      return NextResponse.json({ error: `Config is larger than ${MAX_CONFIG_BYTES} bytes` }, { status: 413 });
    }

    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
    }
    if (!isPlainObject(body) || !isPlainObject(body.config)) {
      return NextResponse.json({ error: "config must be an object" }, { status: 400 });
    }

    const savedAt = new Date().toISOString();
    const { data: server, error } = await access.admin
      .from("servers")
      .update({ config: redactConfig(body.config), config_saved_at: savedAt })
      .eq("org_id", orgId)
      .eq("id", server_id)
      .select("id, name, config_saved_at")
      .maybeSingle();

    if (error) {
      console.error("Failed to save server config:", error);
      return NextResponse.json({ error: "Failed to save config" }, { status: 500 });
    }
    if (!server) {
      return NextResponse.json({ error: "Server not found" }, { status: 404 });
    }

    return NextResponse.json({ server });
  } catch (err) {
    console.error("Save server config error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
