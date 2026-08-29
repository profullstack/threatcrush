import { NextRequest, NextResponse } from "next/server";
import { Resend } from "resend";
import { getSupabaseAdmin } from "@/lib/supabase";
import { CHECKLIST, CHECKLIST_TOTAL } from "@/content/ctem-guide.generated";

/**
 * CTEM readiness checklist results.
 *
 * Two modes, both idempotent per session:
 *  - `{ session_id, answers }`            — records the score anonymously the
 *                                           moment the reader finishes ticking.
 *  - `{ session_id, answers, name, email }` — additionally creates a lead and
 *                                           emails them their gap list.
 *
 * The score is always recomputed here from the raw answers. A client-supplied
 * score would be the one number sales cares about and the easiest to forge.
 */

const FROM_EMAIL = "ThreatCrush <hello@threatcrush.com>";
const SLUG = "ctem-guide";

function appUrl() {
  return process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com";
}

const ITEM_IDS = new Set(
  CHECKLIST.stages.flatMap((s) => s.items.map((i) => i.id)),
);

/** Keep only ids we actually publish, so a junk payload cannot inflate a score. */
function sanitizeAnswers(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const seen = new Set<string>();
  for (const v of raw) {
    if (typeof v === "string" && ITEM_IDS.has(v)) seen.add(v);
  }
  return [...seen];
}

function bandFor(score: number) {
  return (
    CHECKLIST.bands.find((b) => score >= b.min && score <= b.max) ??
    CHECKLIST.bands[CHECKLIST.bands.length - 1]
  );
}

/** The unticked controls, grouped by stage — this is what the email is for. */
function gapsByStage(checked: Set<string>) {
  return CHECKLIST.stages
    .map((stage) => ({
      name: stage.name,
      n: stage.n,
      missing: stage.items.filter((i) => !checked.has(i.id)),
    }))
    .filter((s) => s.missing.length > 0);
}

async function sendResultsEmail(input: {
  name: string;
  email: string;
  score: number;
  bandLabel: string;
  bandSummary: string;
  checkedCount: number;
  gaps: ReturnType<typeof gapsByStage>;
}) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) {
    console.warn("[checklist] RESEND_API_KEY not set — skipping email");
    return;
  }
  const resend = new Resend(apiKey);
  const firstName = input.name.split(" ")[0] || input.name;
  const guideUrl = `${appUrl()}/read/ctem-guide`;
  const pdfUrl = `${appUrl()}/whitepaper/threatcrush-ctem-guide.pdf`;

  const gapLines = input.gaps
    .map(
      (s) =>
        `${s.n} ${s.name}\n` + s.missing.map((m) => `  · ${m.title}`).join("\n"),
    )
    .join("\n\n");

  const text = [
    `Hi ${firstName},`,
    "",
    `You scored ${input.score}% on the CTEM readiness checklist — ${input.bandLabel}.`,
    `(${input.checkedCount} of ${CHECKLIST_TOTAL} controls running today.)`,
    "",
    input.bandSummary,
    "",
    input.gaps.length ? "The controls you did not tick:" : "You ticked every control. Genuinely rare.",
    input.gaps.length ? "" : "",
    gapLines,
    "",
    `The full guide, including the 90-day playbook: ${guideUrl}`,
    `PDF version: ${pdfUrl}`,
    "",
    "If you want the discovery and validation stages running on your own",
    "infrastructure, the install is one line:",
    "  curl -fsSL https://threatcrush.com/install.sh | sh",
    "",
    "Reply with questions or disagreements. We read everything.",
    "",
    "— The ThreatCrush team",
  ]
    .filter((l) => l !== null)
    .join("\n");

  const gapHtml = input.gaps.length
    ? input.gaps
        .map(
          (s) => `
      <p style="margin:18px 0 4px;font-size:13px;font-weight:700;color:#0c1310;">
        <span style="font-family:'JetBrains Mono',monospace;color:#00cc33;">${s.n}</span> ${s.name}
      </p>
      <ul style="margin:0;padding-left:20px;font-size:14px;color:#3b4540;line-height:1.6;">
        ${s.missing.map((m) => `<li>${m.title}</li>`).join("")}
      </ul>`,
        )
        .join("")
    : `<p style="font-size:14px;color:#3b4540;">You ticked every control. That is genuinely rare — we would like to hear how you got there.</p>`;

  const html = `
<!doctype html>
<html><body style="font-family:Inter,system-ui,sans-serif;color:#0c1310;background:#fbfaf6;padding:24px;">
  <div style="max-width:600px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:32px;">
    <div style="font-family:'JetBrains Mono',monospace;color:#00cc33;font-size:12px;letter-spacing:3px;margin-bottom:8px;">▣ THREATCRUSH</div>
    <h1 style="margin:0 0 4px;font-size:22px;">Your CTEM readiness: ${input.score}%</h1>
    <p style="margin:0 0 20px;font-size:15px;font-weight:700;color:#00994d;">${input.bandLabel}</p>
    <p style="font-size:14px;color:#3b4540;line-height:1.6;">Hi ${firstName} — you have <strong>${input.checkedCount} of ${CHECKLIST_TOTAL}</strong> controls running today.</p>
    <p style="font-size:14px;color:#3b4540;line-height:1.6;">${input.bandSummary}</p>
    <div style="border-top:2px solid #00cc33;margin:24px 0 0;padding-top:4px;">
      <p style="margin:12px 0 0;font-size:15px;font-weight:800;">Where the gaps are</p>
    </div>
    ${gapHtml}
    <p style="text-align:center;margin:28px 0;">
      <a href="${guideUrl}" style="display:inline-block;background:#00cc33;color:#000;font-weight:700;text-decoration:none;padding:12px 22px;border-radius:8px;">Read the full guide →</a>
    </p>
    <p style="font-size:13px;color:#6b7570;">Prefer a PDF? <a href="${pdfUrl}" style="color:#00994d;">Download it here</a>.</p>
    <p style="font-size:14px;color:#3b4540;">To get discovery and validation running on your own infrastructure:</p>
    <pre style="background:#0c1310;color:#00ff41;padding:12px 14px;border-radius:8px;font-size:13px;font-family:'JetBrains Mono',monospace;overflow:auto;">curl -fsSL https://threatcrush.com/install.sh | sh</pre>
    <p style="font-size:13px;color:#6b7570;margin-top:24px;">Reply with questions or disagreements. We read everything.</p>
    <p style="font-size:13px;color:#6b7570;">— The ThreatCrush team</p>
  </div>
</body></html>`;

  const { error } = await resend.emails.send({
    from: FROM_EMAIL,
    to: input.email,
    subject: `Your CTEM readiness score: ${input.score}% (${input.bandLabel})`,
    text,
    html,
  });
  if (error) console.error("[checklist] Resend error:", error);
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    const sessionId =
      typeof body.session_id === "string" ? body.session_id.trim().slice(0, 64) : "";
    if (!sessionId) {
      return NextResponse.json({ error: "session_id is required" }, { status: 400 });
    }

    const answers = sanitizeAnswers(body.answers);
    const score = Math.round((answers.length / CHECKLIST_TOTAL) * 100);
    const band = bandFor(score);

    const supabase = getSupabaseAdmin();

    const { error: rpcError } = await supabase.rpc("record_reader_checklist", {
      p_session_id: sessionId,
      p_slug: SLUG,
      p_score: score,
      p_band: band.label,
      p_answers: answers,
    });
    if (rpcError) {
      console.error("[checklist] RPC error:", rpcError);
      return NextResponse.json({ error: "Failed to record results" }, { status: 500 });
    }

    const name = typeof body.name === "string" ? body.name.trim() : "";
    const email = typeof body.email === "string" ? body.email.trim() : "";

    // Anonymous scoring: record it and hand back the result. No lead row.
    if (!name && !email) {
      return NextResponse.json({ success: true, score, band: band.label });
    }

    if (!name) {
      return NextResponse.json({ error: "Name is required" }, { status: 400 });
    }
    if (!email || !email.includes("@")) {
      return NextResponse.json({ error: "Valid email is required" }, { status: 400 });
    }

    const utm = body.utm && typeof body.utm === "object" ? body.utm : {};
    const { error: leadError } = await supabase.from("whitepaper_leads").insert({
      name,
      email: email.toLowerCase(),
      company: typeof body.company === "string" ? body.company.trim() || null : null,
      role: typeof body.role === "string" ? body.role.trim() || null : null,
      team_size: typeof body.team_size === "string" ? body.team_size.trim() || null : null,
      whitepaper_slug: SLUG,
      consent_marketing: body.consent_marketing !== false,
      utm_source: utm.utm_source || null,
      utm_medium: utm.utm_medium || null,
      utm_campaign: utm.utm_campaign || null,
      utm_content: utm.utm_content || null,
      utm_term: utm.utm_term || null,
      source: "checklist",
      session_id: sessionId,
      read_percent:
        typeof body.read_percent === "number"
          ? Math.min(100, Math.max(0, Math.round(body.read_percent)))
          : null,
      checklist_score: score,
      checklist_band: band.label,
      checklist_answers: answers,
      ip_address: request.headers.get("x-forwarded-for")?.split(",")[0].trim() || null,
      user_agent: request.headers.get("user-agent") || null,
    });

    if (leadError) {
      console.error("[checklist] Lead insert error:", leadError);
      return NextResponse.json({ error: "Failed to record request" }, { status: 500 });
    }

    // Fire-and-forget: the reader already has their score on screen.
    sendResultsEmail({
      name,
      email,
      score,
      bandLabel: band.label,
      bandSummary: band.summary,
      checkedCount: answers.length,
      gaps: gapsByStage(new Set(answers)),
    }).catch((err) => console.error("[checklist] Email error:", err));

    return NextResponse.json({ success: true, score, band: band.label, emailed: true });
  } catch (err) {
    console.error("[checklist] Error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
