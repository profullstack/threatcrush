import { NextRequest, NextResponse } from "next/server";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { Resend } from "resend";

const FROM_EMAIL = "ThreatCrush <hello@threatcrush.com>";
const DEFAULT_SLUG = "ctem-guide";
const PDF_PATH = "/whitepaper/threatcrush-ctem-guide.pdf";

let supabase: SupabaseClient | undefined;
function getSupabase() {
  if (supabase) return supabase;
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error("Supabase not configured");
  // Memoized: a new client per request leaks auth/realtime timers → OOM.
  supabase = createClient(url, key, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  return supabase;
}

function appUrl() {
  return process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com";
}

async function sendDownloadEmail(input: {
  name: string;
  email: string;
}) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.warn("[whitepaper] RESEND_API_KEY not set — skipping email");
    return;
  }
  const resend = new Resend(apiKey);
  const downloadUrl = `${appUrl()}${PDF_PATH}`;
  const firstName = input.name.split(" ")[0] || input.name;

  const text = [
    `Hi ${firstName},`,
    "",
    "Thanks for downloading our CTEM operator's guide. The PDF is attached as a direct link below — no login required.",
    "",
    `Download: ${downloadUrl}`,
    "",
    "What's inside:",
    "  • The 5 stages of CTEM in operator language",
    "  • Why CVSS-weighted backlogs lie to you",
    "  • A 90-day implementation playbook",
    "  • Metrics that reward outcomes, not activity",
    "",
    "If you want to try the platform, the install is one line:",
    "  curl -fsSL https://threatcrush.com/install.sh | sh",
    "",
    "Reply to this email with questions, war stories, or feedback. We read everything.",
    "",
    "— The ThreatCrush team",
  ].join("\n");

  const html = `
<!doctype html>
<html><body style="font-family:Inter,system-ui,sans-serif;color:#0c1310;background:#fbfaf6;padding:24px;">
  <div style="max-width:560px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:32px;">
    <div style="font-family:'JetBrains Mono',monospace;color:#00cc6e;font-size:12px;letter-spacing:3px;margin-bottom:8px;">▣ THREATCRUSH</div>
    <h1 style="margin:0 0 16px;font-size:22px;">Your CTEM guide is ready</h1>
    <p>Hi ${firstName},</p>
    <p>Thanks for downloading the guide. Click below to grab the PDF — no login required.</p>
    <p style="text-align:center;margin:28px 0;">
      <a href="${downloadUrl}" style="display:inline-block;background:#00cc6e;color:#000;font-weight:700;text-decoration:none;padding:12px 22px;border-radius:8px;">Download the PDF →</a>
    </p>
    <p style="font-size:14px;color:#3b4540;"><strong>What's inside:</strong></p>
    <ul style="font-size:14px;color:#3b4540;line-height:1.6;">
      <li>The 5 stages of CTEM in operator language</li>
      <li>Why CVSS-weighted backlogs lie to you</li>
      <li>A 90-day implementation playbook</li>
      <li>Metrics that reward outcomes, not activity</li>
    </ul>
    <p style="font-size:14px;color:#3b4540;">If you want to try the platform, the install is one line:</p>
    <pre style="background:#0c1310;color:#00ff88;padding:12px 14px;border-radius:8px;font-size:13px;font-family:'JetBrains Mono',monospace;overflow:auto;">curl -fsSL https://threatcrush.com/install.sh | sh</pre>
    <p style="font-size:13px;color:#6b7570;margin-top:24px;">Reply to this email with questions, war stories, or feedback. We read everything.</p>
    <p style="font-size:13px;color:#6b7570;">— The ThreatCrush team</p>
  </div>
</body></html>`;

  const { error } = await resend.emails.send({
    from: FROM_EMAIL,
    to: input.email,
    subject: "Your CTEM guide from ThreatCrush",
    text,
    html,
  });
  if (error) console.error("[whitepaper] Resend error:", error);
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const name = typeof body.name === "string" ? body.name.trim() : "";
    const email = typeof body.email === "string" ? body.email.trim() : "";
    const company = typeof body.company === "string" ? body.company.trim() : null;
    const role = typeof body.role === "string" ? body.role.trim() : null;
    const teamSize = typeof body.team_size === "string" ? body.team_size.trim() : null;
    const slug = typeof body.slug === "string" && body.slug ? body.slug : DEFAULT_SLUG;
    const consentMarketing = body.consent_marketing !== false;

    if (!name) {
      return NextResponse.json({ error: "Name is required" }, { status: 400 });
    }
    if (!email || !email.includes("@")) {
      return NextResponse.json({ error: "Valid email is required" }, { status: 400 });
    }

    const utm = body.utm && typeof body.utm === "object" ? body.utm : {};
    const ip = request.headers.get("x-forwarded-for")?.split(",")[0].trim() || null;
    const ua = request.headers.get("user-agent") || null;

    const supabase = getSupabase();
    const { data, error } = await supabase
      .from("whitepaper_leads")
      .insert({
        name,
        email: email.toLowerCase(),
        company,
        role,
        team_size: teamSize,
        whitepaper_slug: slug,
        consent_marketing: consentMarketing,
        utm_source: utm.utm_source || null,
        utm_medium: utm.utm_medium || null,
        utm_campaign: utm.utm_campaign || null,
        utm_content: utm.utm_content || null,
        utm_term: utm.utm_term || null,
        source: typeof body.source === "string" ? body.source : "get-whitepaper",
        ip_address: ip,
        user_agent: ua,
      })
      .select("id")
      .single();

    if (error) {
      console.error("[whitepaper] Insert error:", error);
      return NextResponse.json({ error: "Failed to record request" }, { status: 500 });
    }

    // Fire-and-forget email; don't block the user's download on it.
    sendDownloadEmail({ name, email }).catch((err) =>
      console.error("[whitepaper] Email error:", err),
    );

    return NextResponse.json({
      success: true,
      id: data.id,
      download_url: PDF_PATH,
    });
  } catch (err) {
    console.error("[whitepaper] Error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

export async function GET() {
  return NextResponse.json({
    message: "ThreatCrush Whitepaper API",
    download: PDF_PATH,
  });
}
