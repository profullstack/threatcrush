import type { Severity } from "@/lib/ingest-events";

export type { Severity };

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** A freshly inserted detection, as handed over by the ingest route. */
export interface AlertableDetection {
  id: string;
  organization_id: string;
  server_id: string;
  severity: Severity;
  title: string;
  description: string | null;
  source_ip: string | null;
  rule_id: string | null;
  detected_at: string;
}

export type DestinationType = "slack" | "discord" | "email" | "webhook" | "pagerduty" | "push";

export interface AlertDestinationRow {
  id: string;
  organization_id: string;
  name: string;
  type: DestinationType;
  config: Record<string, unknown> | null;
  enabled: boolean;
}

export interface AlertRuleRow {
  id: string;
  organization_id: string;
  name: string;
  min_severity: Severity;
  server_scope: unknown;
  destination_id: string;
  rate_limit_per_hour: number | null;
  enabled: boolean;
}

/** Channel-neutral alert content every sender renders from. */
export interface AlertMessage {
  title: string;
  body: string;
  severity: Severity;
  /** Absolute link into the dashboard. */
  url: string;
  timestamp: string;
  /** Collapses repeat notifications for the same thing on push channels. */
  tag: string;
  /** Present for real alerts, absent for test sends. */
  detection?: AlertableDetection & { server_name: string | null };
}

export type DeliveryOutcome = { ok: true; detail?: string } | { ok: false; error: string };
