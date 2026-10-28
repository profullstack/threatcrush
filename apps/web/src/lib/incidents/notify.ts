import "server-only";
import type { SupabaseClient } from "@supabase/supabase-js";
import { Resend } from "resend";
import { getSupabaseAdmin } from "@/lib/supabase";
import { appUrl } from "@/lib/teams";
import { sendIncidentSms } from "./sms";

/**
 * Page people about an incident: every member of the incident's team (no team:
 * the org's owners and admins) who has not muted that team, by email (Resend)
 * when their notification_email is on and by SMS when they have a verified
 * phone and notification_sms is on. Each attempt is a row in
 * incident_notifications. At most PAGES_PER_HOUR sent pages per person per
 * channel; the caller decides WHEN to page (new incident, or escalation to
 * critical), so one incident pages once, not once per finding. Never throws.
 */

export const PAGES_PER_HOUR = 5;
const HOUR_MS = 60 * 60 * 1000;
const EMAIL_FROM = "ThreatCrush Alerts <alerts@threatcrush.com>";
const SMS_MAX = 320;

type Channel = "sms" | "email";
type Status = "sent" | "failed" | "skipped" | "rate_limited";
export type ChannelTally = Record<Status, number>;
export interface NotifyResult { sms: ChannelTally; email: ChannelTally; recipients: number }

export interface PageableIncident {
  id: string;
  org_id: string;
  team_id: string | null;
  title: string;
  severity: string;
  host: string | null;
  summary: string;
  findings_count: number;
}

interface Profile {
  id: string;
  email: string | null;
  phone: string | null;
  phone_verified: boolean | null;
  notification_email: boolean | null;
  notification_sms: boolean | null;
}

export interface PageMessage { subject: string; text: string; sms: string; url: string; severity: string }

const emptyTally = (): ChannelTally => ({ sent: 0, failed: 0, skipped: 0, rate_limited: 0 });

function html(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export function buildPage(incident: PageableIncident, orgSlug: string | null, test = false): PageMessage {
  const url = orgSlug ? `${appUrl()}/org/${orgSlug}/incidents/${incident.id}` : `${appUrl()}/dashboard`;
  const sev = incident.severity.toUpperCase();
  const on = incident.host ? ` on ${incident.host}` : "";
  const n = incident.findings_count;
  const prefix = test ? "[ThreatCrush TEST]" : `[ThreatCrush ${sev}]`;
  const tail = `${n} finding${n === 1 ? "" : "s"}. ${url}`;
  let sms = `${prefix} ${incident.title}${on}. ${tail}`;
  if (sms.length > SMS_MAX) {
    const room = SMS_MAX - (`${prefix} ${on}. ${tail}`.length + 1);
    sms = `${prefix} ${incident.title.slice(0, Math.max(10, room))}…${on}. ${tail}`.slice(0, SMS_MAX);
  }
  return {
    subject: `${prefix} ${incident.title}${on}`.slice(0, 200),
    text: `${incident.title}${on}\nSeverity: ${sev}\n\n${incident.summary}\n\n${tail}`,
    sms,
    url,
    severity: incident.severity,
  };
}

async function sendEmail(to: string, msg: PageMessage): Promise<{ ok: boolean; detail: string }> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return { ok: false, detail: "RESEND_API_KEY not set" };
  try {
    const { error } = await new Resend(apiKey).emails.send({
      from: EMAIL_FROM,
      to: [to],
      subject: msg.subject,
      text: msg.text,
      html: `<h2>${html(msg.subject)}</h2><p style="white-space:pre-line">${html(msg.text)}</p><p><a href="${html(msg.url)}">Open the incident</a></p>`,
    });
    return error ? { ok: false, detail: `Resend: ${error.message}`.slice(0, 500) } : { ok: true, detail: "resend" };
  } catch (err) {
    return { ok: false, detail: `Resend: ${(err as Error).message}`.slice(0, 500) };
  }
}

async function sentLastHour(admin: SupabaseClient, userId: string, channel: Channel): Promise<number> {
  const { count } = await admin
    .from("incident_notifications")
    .select("id", { count: "exact", head: true })
    .eq("user_id", userId)
    .eq("channel", channel)
    .eq("status", "sent")
    .gte("created_at", new Date(Date.now() - HOUR_MS).toISOString());
  return count ?? 0;
}

/** Page one person on both channels per their settings. */
async function pagePerson(
  admin: SupabaseClient,
  profile: Profile,
  msg: PageMessage,
  incidentId: string | null,
  result: NotifyResult,
): Promise<void> {
  const rows: Array<{ incident_id: string | null; user_id: string; channel: Channel; status: Status; detail: string | null }> = [];
  const record = (channel: Channel, status: Status, detail: string | null) => {
    rows.push({ incident_id: incidentId, user_id: profile.id, channel, status, detail });
    result[channel][status]++;
  };

  // Email
  if (!profile.email) record("email", "skipped", "no email address");
  else if (profile.notification_email === false) record("email", "skipped", "email alerts are off");
  else if ((await sentLastHour(admin, profile.id, "email")) >= PAGES_PER_HOUR) record("email", "rate_limited", `${PAGES_PER_HOUR} pages an hour reached`);
  else {
    const out = await sendEmail(profile.email, msg);
    record("email", out.ok ? "sent" : "failed", out.detail);
  }

  // SMS
  if (!profile.phone) record("sms", "skipped", "no phone number");
  else if (!profile.phone_verified) record("sms", "skipped", "phone not verified");
  else if (profile.notification_sms === false) record("sms", "skipped", "SMS alerts are off");
  else if ((await sentLastHour(admin, profile.id, "sms")) >= PAGES_PER_HOUR) record("sms", "rate_limited", `${PAGES_PER_HOUR} pages an hour reached`);
  else {
    const out = await sendIncidentSms(profile.phone, msg.sms, process.env, msg.severity);
    record("sms", out.ok ? "sent" : "failed", out.ok ? (out.detail ?? out.provider) : out.error.slice(0, 500));
  }

  const { error } = await admin.from("incident_notifications").insert(rows);
  if (error) console.error("[incidents] could not record notifications:", error.message);
}

/** Who gets paged for an incident: user ids, after per-team mutes. */
export async function recipientsFor(admin: SupabaseClient, incident: { org_id: string; team_id: string | null }): Promise<string[]> {
  if (incident.team_id) {
    const { data } = await admin.from("team_members").select("user_id, notify_incidents").eq("team_id", incident.team_id);
    return ((data ?? []) as Array<{ user_id: string; notify_incidents?: boolean | null }>)
      .filter((m) => m.notify_incidents !== false)
      .map((m) => m.user_id);
  }
  const { data } = await admin
    .from("organization_members")
    .select("user_id, role")
    .eq("org_id", incident.org_id)
    .in("role", ["owner", "admin"]);
  return ((data ?? []) as Array<{ user_id: string }>).map((m) => m.user_id);
}

async function profiles(admin: SupabaseClient, ids: string[]): Promise<Profile[]> {
  if (ids.length === 0) return [];
  const { data } = await admin
    .from("user_profiles")
    .select("id, email, phone, phone_verified, notification_email, notification_sms")
    .in("id", ids);
  return (data ?? []) as Profile[];
}

/** How many of these people a page would reach on each channel (before the hourly cap). */
export async function reachable(admin: SupabaseClient, ids: string[]): Promise<{ sms: number; email: number }> {
  const people = await profiles(admin, [...new Set(ids)]);
  return {
    email: people.filter((x) => x.email && x.notification_email !== false).length,
    sms: people.filter((x) => x.phone && x.phone_verified && x.notification_sms !== false).length,
  };
}

async function orgSlug(admin: SupabaseClient, orgId: string): Promise<string | null> {
  const { data } = await admin.from("organizations").select("slug").eq("id", orgId).maybeSingle();
  return (data as { slug?: string } | null)?.slug ?? null;
}

export async function notifyIncident(incident: PageableIncident, admin: SupabaseClient = getSupabaseAdmin()): Promise<NotifyResult> {
  const result: NotifyResult = { sms: emptyTally(), email: emptyTally(), recipients: 0 };
  try {
    const ids = [...new Set(await recipientsFor(admin, incident))];
    const people = await profiles(admin, ids);
    result.recipients = people.length;
    const msg = buildPage(incident, await orgSlug(admin, incident.org_id));
    for (const person of people) await pagePerson(admin, person, msg, incident.id, result);
    await admin.from("incidents").update({ last_notified_at: new Date().toISOString() }).eq("id", incident.id);
  } catch (err) {
    console.error(`[incidents] notify failed for ${incident.id}:`, (err as Error).message);
  }
  return result;
}

/** A canned TEST page to ONE person (the admin test button / CLI check). */
export async function sendTestPage(admin: SupabaseClient, orgId: string, userId: string): Promise<NotifyResult> {
  const result: NotifyResult = { sms: emptyTally(), email: emptyTally(), recipients: 0 };
  const [person] = await profiles(admin, [userId]);
  if (!person) return result;
  result.recipients = 1;
  const msg = buildPage(
    { id: "test", org_id: orgId, team_id: null, title: "Test incident page", severity: "info", host: null, summary: "This is a test of ThreatCrush incident paging. Nothing is wrong.", findings_count: 0 },
    null,
    true,
  );
  msg.url = `${appUrl()}/account`;
  msg.sms = `[ThreatCrush TEST] Incident paging works. Nothing is wrong. Settings: ${msg.url}`;
  await pagePerson(admin, person, msg, null, result);
  return result;
}
