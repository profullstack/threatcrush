// Anonymous CLI usage pings (apps/cli/src/core/usage-ping.ts): one per
// ai-scan run, counts only. Every field is checked against a narrow shape and
// anything else is dropped, so the table can only ever hold what the CLI
// documents sending.

const EVENTS = new Set(["ai-scan", "ai-scan-run"]);
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export const MAX_BODY = 4096;

const count = (v: unknown) =>
  typeof v === "number" && Number.isFinite(v) && v >= 0 ? Math.min(Math.floor(v), 1_000_000) : null;
const short = (v: unknown, re: RegExp) => (typeof v === "string" && re.test(v) ? v : null);

export function parsePing(body: unknown) {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const b = body as Record<string, unknown>;
  if (typeof b.event !== "string" || !EVENTS.has(b.event)) return null;
  const severity: Record<string, number> = {};
  if (b.severity && typeof b.severity === "object") {
    for (const k of SEVERITIES) {
      const n = count((b.severity as Record<string, unknown>)[k]);
      if (n) severity[k] = n;
    }
  }
  return {
    event: b.event,
    version: short(b.version, /^[0-9A-Za-z.+-]{1,32}$/),
    platform: short(b.platform, /^[a-z0-9]{1,16}$/),
    arch: short(b.arch, /^[a-z0-9_]{1,16}$/),
    node: short(b.node, /^v?[0-9.]{1,16}$/),
    ci: b.ci === true,
    install_id: short(b.install_id, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i),
    probes: count(b.probes),
    scans: count(b.scans),
    findings: count(b.findings) ?? 0,
    severity,
    duration_ms: count(b.duration_ms),
    failed: b.failed === true,
  };
}
