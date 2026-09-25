// Validation for POST /api/ingest (daemon → cloud contract v2, which also
// covers v1 heartbeat/detection bodies). Mirrors the event types exported by
// @threatcrush/sdk; the web app does not depend on the SDK package.

export const INGEST_MAX_EVENTS = 500;
export const INGEST_MAX_BODY_BYTES = 1_000_000;
export const INGEST_MAX_TITLE_LENGTH = 300;
export const INGEST_MAX_RAW_METADATA_BYTES = 16 * 1024;

const SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type Severity = (typeof SEVERITIES)[number];

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type HeartbeatEvent = {
  type: "heartbeat";
  server_id: string;
  version: string | null;
  hostname: string | null;
};

export type DetectionEvent = {
  type: "detection";
  server_id: string;
  severity: Severity;
  title: string;
  rule_id: string | null;
  description: string | null;
  source_ip: string | null;
  username: string | null;
  raw_metadata: Record<string, unknown>;
  detected_at: string;
};

export type HardeningFindingEvent = {
  type: "hardening_finding";
  server_id: string;
  finding_key: string;
  status: "pass" | "warn" | "fail";
  severity: Severity;
  title: string;
  recommendation: string | null;
  observed_at: string;
};

export type RemediationEvent = {
  type: "remediation";
  server_id: string;
  action_type: "block" | "unblock";
  target_value: string;
  status: "executed" | "failed";
  /** Daemon-generated id that survives spool replays; null from older daemons. */
  event_id: string | null;
  rule_id: string | null;
  reason: string | null;
  error: string | null;
  dry_run: boolean;
  executed_at: string;
  expires_at: string | null;
};

export type IngestEvent = HeartbeatEvent | DetectionEvent | HardeningFindingEvent | RemediationEvent;

export type ParsedEvent = { ok: true; event: IngestEvent } | { ok: false; error: string };

class InvalidField extends Error {}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requiredString(obj: Record<string, unknown>, key: string, max: number): string {
  const value = obj[key];
  if (typeof value !== "string" || value.trim() === "") {
    throw new InvalidField(`${key} is required`);
  }
  if (value.length > max) throw new InvalidField(`${key} exceeds ${max} characters`);
  return value;
}

function optionalString(obj: Record<string, unknown>, key: string, max: number): string | null {
  const value = obj[key];
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string") throw new InvalidField(`${key} must be a string`);
  if (value.length > max) throw new InvalidField(`${key} exceeds ${max} characters`);
  return value;
}

function oneOf<T extends string>(obj: Record<string, unknown>, key: string, allowed: readonly T[]): T {
  const value = obj[key];
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) {
    throw new InvalidField(`${key} must be one of ${allowed.join(", ")}`);
  }
  return value as T;
}

/** Optional ISO timestamp, normalized to UTC ISO; `fallback` when absent. */
function timestamp(obj: Record<string, unknown>, key: string, fallback: string): string {
  const value = obj[key];
  if (value === undefined || value === null || value === "") return fallback;
  if (typeof value !== "string") throw new InvalidField(`${key} must be an ISO timestamp`);
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) throw new InvalidField(`${key} must be an ISO timestamp`);
  return new Date(ms).toISOString();
}

function serverId(obj: Record<string, unknown>): string {
  const value = obj.server_id;
  if (typeof value !== "string" || !UUID_RE.test(value)) {
    throw new InvalidField("server_id must be a server UUID");
  }
  return value.toLowerCase();
}

function optionalUuid(obj: Record<string, unknown>, key: string): string | null {
  const value = obj[key];
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || !UUID_RE.test(value)) throw new InvalidField(`${key} must be a UUID`);
  return value.toLowerCase();
}

function rawMetadata(obj: Record<string, unknown>): Record<string, unknown> {
  const value = obj.raw_metadata;
  if (value === undefined || value === null) return {};
  if (!isPlainObject(value)) throw new InvalidField("raw_metadata must be an object");
  if (Buffer.byteLength(JSON.stringify(value), "utf8") > INGEST_MAX_RAW_METADATA_BYTES) {
    throw new InvalidField(`raw_metadata exceeds ${INGEST_MAX_RAW_METADATA_BYTES} bytes`);
  }
  return value;
}

/** Validate and normalize one event. `now` is the receive time (ISO). */
export function parseIngestEvent(raw: unknown, now: string): ParsedEvent {
  if (!isPlainObject(raw)) return { ok: false, error: "event must be an object" };
  try {
    switch (raw.type) {
      case "heartbeat":
        return {
          ok: true,
          event: {
            type: "heartbeat",
            server_id: serverId(raw),
            version: optionalString(raw, "version", 64),
            hostname: optionalString(raw, "hostname", 253),
          },
        };
      case "detection":
        return {
          ok: true,
          event: {
            type: "detection",
            server_id: serverId(raw),
            severity: oneOf(raw, "severity", SEVERITIES),
            title: requiredString(raw, "title", INGEST_MAX_TITLE_LENGTH),
            rule_id: optionalString(raw, "rule_id", 200),
            description: optionalString(raw, "description", 10_000),
            source_ip: optionalString(raw, "source_ip", 64),
            username: optionalString(raw, "username", 256),
            raw_metadata: rawMetadata(raw),
            detected_at: timestamp(raw, "detected_at", now),
          },
        };
      case "hardening_finding":
        return {
          ok: true,
          event: {
            type: "hardening_finding",
            server_id: serverId(raw),
            finding_key: requiredString(raw, "finding_key", 200),
            status: oneOf(raw, "status", ["pass", "warn", "fail"] as const),
            severity: oneOf(raw, "severity", SEVERITIES),
            title: requiredString(raw, "title", INGEST_MAX_TITLE_LENGTH),
            recommendation: optionalString(raw, "recommendation", 10_000),
            observed_at: timestamp(raw, "observed_at", now),
          },
        };
      case "remediation": {
        if (raw.dry_run !== undefined && typeof raw.dry_run !== "boolean") {
          throw new InvalidField("dry_run must be a boolean");
        }
        const expires = raw.expires_at === undefined || raw.expires_at === null
          ? null
          : timestamp(raw, "expires_at", now);
        return {
          ok: true,
          event: {
            type: "remediation",
            server_id: serverId(raw),
            action_type: oneOf(raw, "action_type", ["block", "unblock"] as const),
            target_value: requiredString(raw, "target_value", 128),
            status: oneOf(raw, "status", ["executed", "failed"] as const),
            event_id: optionalUuid(raw, "event_id"),
            rule_id: optionalString(raw, "rule_id", 200),
            reason: optionalString(raw, "reason", 1_000),
            error: optionalString(raw, "error", 2_000),
            dry_run: raw.dry_run === true,
            executed_at: timestamp(raw, "executed_at", now),
            expires_at: expires,
          },
        };
      }
      default:
        return {
          ok: false,
          error: typeof raw.type === "string" ? `unknown event type: ${raw.type.slice(0, 50)}` : "type is required",
        };
    }
  } catch (err) {
    if (err instanceof InvalidField) return { ok: false, error: err.message };
    throw err;
  }
}

/**
 * Read a request body, giving up (null) as soon as it passes `maxBytes`, so an
 * oversized upload is never buffered whole.
 */
export async function readBodyCapped(req: Request, maxBytes: number): Promise<string | null> {
  const declared = Number(req.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) return null;
  if (!req.body) return "";

  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}
