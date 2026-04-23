import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";

function getSupabase() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error("Supabase not configured");
  return createClient(url, key);
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const email = typeof body.email === "string" ? body.email.trim() : "";
    const company =
      typeof body.company === "string" ? body.company.trim() : null;
    const message = typeof body.message === "string" ? body.message.trim() : "";
    const topic = typeof body.topic === "string" ? body.topic : "general";

    if (!name) {
      return NextResponse.json({ error: "Name is required" }, { status: 400 });
    }
    if (!email || !email.includes("@")) {
      return NextResponse.json(
        { error: "Valid email is required" },
        { status: 400 },
      );
    }
    if (!message) {
      return NextResponse.json(
        { error: "Message is required" },
        { status: 400 },
      );
    }

    const supabase = getSupabase();
    const { data, error } = await supabase
      .from("contact_requests")
      .insert({
        name,
        email: email.toLowerCase(),
        company,
        message,
        topic,
      })
      .select("id")
      .single();

    if (error) {
      console.error("[contact] Insert error:", error);
      return NextResponse.json(
        { error: "Failed to submit request" },
        { status: 500 },
      );
    }

    return NextResponse.json({ success: true, id: data.id });
  } catch (err) {
    console.error("[contact] Error:", err);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 },
    );
  }
}
