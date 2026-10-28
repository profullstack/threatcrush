import { NextRequest, NextResponse } from "next/server";
import { fleetCost, parseInventory, validateInventory } from "@profullstack/fleet";
import { unauthorized } from "@/lib/api-auth";
import { getSupabaseAdmin } from "@/lib/supabase";
import { getPrincipal } from "@/lib/access";
import { canReadInventory, canWriteInventory, INVENTORY_MAX_BYTES, inventoryRoleOf } from "@/lib/fleet-inventory";

// The org's OpenDevice inventory (https://logicsrc.com/docs/opendevice): every
// machine it runs, daemon or not, and what each one costs. GET for owners,
// admins and members; PUT/DELETE for owners and admins. `threatcrush fleet
// import <file|url>` is the CLI for PUT.

type Params = { params: Promise<{ id: string }> };

async function access(req: NextRequest, orgId: string) {
  const admin = getSupabaseAdmin();
  const p = await getPrincipal(req, admin);
  if (!p) return { error: unauthorized() };
  if (p.kind !== "user") {
    return { error: NextResponse.json({ error: "Inventories belong to people: sign in with `threatcrush login`, not an agent key" }, { status: 403 }) };
  }
  const role = await inventoryRoleOf(admin, p, orgId);
  if (!canReadInventory(role)) {
    return { error: NextResponse.json({ error: "Not a member of this organization" }, { status: 403 }) };
  }
  return { admin, p, role };
}

function summarize(document: unknown) {
  const cost = fleetCost(document as object);
  return {
    devices: cost.devices.length,
    monthly: cost.monthly,
    counted: cost.counted,
    unstated: cost.unstated,
  };
}

export async function GET(req: NextRequest, { params }: Params) {
  try {
    const { id: orgId } = await params;
    const a = await access(req, orgId);
    if ("error" in a) return a.error;
    const { data, error } = await a.admin
      .from("fleet_inventories")
      .select("document, updated_at, updated_by")
      .eq("org_id", orgId)
      .maybeSingle();
    if (error) {
      console.error("Inventory GET failed:", error);
      return NextResponse.json({ error: "Failed to load the inventory" }, { status: 500 });
    }
    if (!data) return NextResponse.json({ inventory: null, updated_at: null, cost: null });
    return NextResponse.json({ inventory: data.document, updated_at: data.updated_at, cost: summarize(data.document) });
  } catch (err) {
    console.error("Inventory GET error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// PUT — replace the inventory. Body: the OpenDevice document itself (or
// { document }). Errors reject it (422); warnings are returned and it is stored.
export async function PUT(req: NextRequest, { params }: Params) {
  try {
    const { id: orgId } = await params;
    const a = await access(req, orgId);
    if ("error" in a) return a.error;
    if (!canWriteInventory(a.role)) {
      return NextResponse.json({ error: "Only owners and admins can change the inventory" }, { status: 403 });
    }

    const text = await req.text();
    if (Buffer.byteLength(text) > INVENTORY_MAX_BYTES) {
      return NextResponse.json({ error: `Inventory is larger than ${INVENTORY_MAX_BYTES} bytes` }, { status: 413 });
    }
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      return NextResponse.json({ error: "Body is not JSON" }, { status: 400 });
    }
    const document =
      body && typeof body === "object" && !Array.isArray(body) && "document" in body && !("devices" in body)
        ? (body as { document: unknown }).document
        : body;
    if (!document || typeof document !== "object" || Array.isArray(document)) {
      return NextResponse.json({ error: "Expected an OpenDevice inventory object" }, { status: 400 });
    }

    const { valid, errors, warnings } = validateInventory(document as object);
    if (!valid) return NextResponse.json({ error: "Invalid OpenDevice inventory", errors, warnings }, { status: 422 });
    parseInventory(document as object); // throws only on what validate already rejected

    const updated_at = new Date().toISOString();
    const { error } = await a.admin
      .from("fleet_inventories")
      .upsert({ org_id: orgId, document, updated_at, updated_by: a.p.userId }, { onConflict: "org_id" });
    if (error) {
      console.error("Inventory PUT failed:", error);
      return NextResponse.json({ error: "Failed to save the inventory" }, { status: 500 });
    }
    return NextResponse.json({ ok: true, updated_at, warnings, cost: summarize(document) });
  } catch (err) {
    console.error("Inventory PUT error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function DELETE(req: NextRequest, { params }: Params) {
  try {
    const { id: orgId } = await params;
    const a = await access(req, orgId);
    if ("error" in a) return a.error;
    if (!canWriteInventory(a.role)) {
      return NextResponse.json({ error: "Only owners and admins can change the inventory" }, { status: 403 });
    }
    const { error } = await a.admin.from("fleet_inventories").delete().eq("org_id", orgId);
    if (error) {
      console.error("Inventory DELETE failed:", error);
      return NextResponse.json({ error: "Failed to remove the inventory" }, { status: 500 });
    }
    return NextResponse.json({ ok: true });
  } catch (err) {
    console.error("Inventory DELETE error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
