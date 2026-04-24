import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";
import { Resend } from "resend";

const CONTACT_EMAIL = "hello@threatcrush.com";
const FROM_EMAIL = `ThreatCrush <${CONTACT_EMAIL}>`;

function getSupabase() {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error("Supabase not configured");
  return createClient(url, key);
}

async function sendNotification(input: {
  name: string;
  email: string;
  company: string | null;
  message: string;
  topic: string;
}) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.warn("[contact] RESEND_API_KEY not set — skipping email");
    return;
  }
  const resend = new Resend(apiKey);
  const subject = `[ThreatCrush] New ${input.topic} inquiry from ${input.name}`;
  const lines = [
    `Name: ${input.name}`,
    `Email: ${input.email}`,
    input.company ? `Company: ${input.company}` : null,
    `Topic: ${input.topic}`,
    "",
    "Message:",
    input.message,
  ].filter(Boolean);
  const { error } = await resend.emails.send({
    from: FROM_EMAIL,
    to: CONTACT_EMAIL,
    replyTo: input.email,
    subject,
    text: lines.join("\n"),
  });
  if (error) console.error("[contact] Resend error:", error);
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

    await sendNotification({ name, email, company, message, topic });

    return NextResponse.json({ success: true, id: data.id });
  } catch (err) {
    console.error("[contact] Error:", err);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 },
    );
  }
}
