import "server-only";
import { Resend } from "resend";

/**
 * The $400 human-reviewed scan. A paid order lands in scan_orders and the
 * team is told at hello@threatcrush.com, with the buyer's email as reply-to,
 * so an engineer picks it up and writes back to schedule it.
 */

const TEAM = "hello@threatcrush.com";

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

export function scanBookedEmail(row: {
  id: string;
  email: string | null;
  target: string | null;
  notes: string | null;
  amount_usd: unknown;
}): { subject: string; text: string; html: string } {
  const lines = [
    `Order: ${row.id}`,
    `Paid: $${row.amount_usd}`,
    `Buyer: ${row.email ?? "(agent key, no email)"}`,
    `Target: ${row.target ?? "(not given; ask)"}`,
    `Notes: ${row.notes ?? ""}`,
    "",
    "Reply to the buyer within one business day to schedule the scan.",
  ];
  const text = lines.join("\n");
  return {
    subject: `[ThreatCrush] Scan booked: ${row.target ?? row.email ?? row.id}`.slice(0, 200),
    text,
    html: `<pre style="font-family:monospace">${esc(text)}</pre>`,
  };
}

export async function notifyScanBooked(row: {
  id: string;
  email: string | null;
  target: string | null;
  notes: string | null;
  amount_usd: unknown;
}): Promise<void> {
  const name = "RESEND_API_KEY";
  const apiKey = process.env[name];
  if (!apiKey) {
    console.warn("[scan-orders] RESEND_API_KEY not set; scan order", row.id, "booked without a notification");
    return;
  }
  const mail = scanBookedEmail(row);
  const { error } = await new Resend(apiKey).emails.send({
    from: "ThreatCrush <hello@threatcrush.com>",
    to: TEAM,
    ...(row.email ? { replyTo: row.email } : {}),
    subject: mail.subject,
    text: mail.text,
    html: mail.html,
  });
  if (error) console.error("[scan-orders] Resend error", error);
}
