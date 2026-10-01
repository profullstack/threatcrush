import "server-only";
import { NextResponse } from "next/server";
import type { SupabaseClient } from "@supabase/supabase-js";
import { Resend } from "resend";
import { slugify } from "@/lib/supabase";
import type { TeamRole } from "@/lib/access";

/** Shared pieces for the teams, fleets, invites and agent-key routes. */

export const INVITE_FROM = "ThreatCrush <hello@threatcrush.com>";
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function appUrl(): string {
  return (process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com").replace(/\/$/, "");
}

export function isEmail(value: unknown): value is string {
  return typeof value === "string" && value.length <= 254 && EMAIL.test(value.trim());
}

export function cleanName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const name = value.trim().slice(0, 100);
  return name || null;
}

export const fail = (status: number, error: string) => NextResponse.json({ error }, { status });

export async function readJson(req: Request): Promise<Record<string, unknown> | null> {
  try {
    const body: unknown = await req.json();
    return body && typeof body === "object" && !Array.isArray(body) ? (body as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export interface TeamRow { id: string; org_id: string; name: string; slug: string; created_at: string }
export interface FleetRow { id: string; org_id: string; team_id: string; name: string; slug: string; created_at: string }

export async function loadTeam(admin: SupabaseClient, orgId: string, teamId: string): Promise<TeamRow | null> {
  const { data } = await admin
    .from("teams")
    .select("id, org_id, name, slug, created_at")
    .eq("id", teamId)
    .eq("org_id", orgId)
    .maybeSingle();
  return (data as TeamRow | null) ?? null;
}

export async function loadFleet(admin: SupabaseClient, orgId: string, fleetId: string): Promise<FleetRow | null> {
  const { data } = await admin
    .from("fleets")
    .select("id, org_id, team_id, name, slug, created_at")
    .eq("id", fleetId)
    .eq("org_id", orgId)
    .maybeSingle();
  return (data as FleetRow | null) ?? null;
}

/** A slug for `name` that is free in this org's `table` (teams or fleets). */
export async function uniqueSlug(admin: SupabaseClient, table: "teams" | "fleets", orgId: string, name: string): Promise<string> {
  const base = slugify(name).slice(0, 56) || table.slice(0, -1);
  const { data } = await admin.from(table).select("slug").eq("org_id", orgId).like("slug", `${base}%`);
  const taken = new Set((data ?? []).map((r) => r.slug as string));
  if (!taken.has(base)) return base;
  for (let i = 2; ; i++) if (!taken.has(`${base}-${i}`)) return `${base}-${i}`;
}

const ROLE_WORDS: Record<TeamRole, string> = {
  read: "read-only access",
  write: "write access",
  admin: "admin access",
};

/** Best effort: the invite is valid whether or not the email goes out. */
export async function sendInviteEmail(opts: {
  to: string;
  orgName: string;
  teamName: string;
  role: TeamRole;
  inviter: string | null;
  url: string;
}): Promise<boolean> {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) return false;
  const who = opts.inviter ?? "Someone";
  const subject = `${who} invited you to ${opts.teamName} on ThreatCrush`;
  const text =
    `${who} invited you to the ${opts.teamName} team in ${opts.orgName} on ThreatCrush, with ${ROLE_WORDS[opts.role]}.\n\n` +
    `Accept: ${opts.url}\n\nThe link works once and expires in 14 days.`;
  try {
    const { error } = await new Resend(apiKey).emails.send({ from: INVITE_FROM, to: [opts.to], subject, text });
    return !error;
  } catch {
    return false;
  }
}
