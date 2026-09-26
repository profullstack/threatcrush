import type { AlertableDetection, AlertMessage } from "./types";

/** Read per call so the deployment's NEXT_PUBLIC_APP_URL applies at runtime. */
function appUrl(): string {
  return (process.env.NEXT_PUBLIC_APP_URL || "https://threatcrush.com").replace(/\/$/, "");
}

export function buildDetectionMessage(
  detection: AlertableDetection,
  context: { orgSlug: string | null; serverName: string | null },
): AlertMessage {
  const base = appUrl();
  const lines = [
    detection.description,
    `Server: ${context.serverName ?? detection.server_id}`,
    detection.source_ip && `Source IP: ${detection.source_ip}`,
    detection.rule_id && `Rule: ${detection.rule_id}`,
  ].filter((line): line is string => Boolean(line));

  return {
    title: `[${detection.severity.toUpperCase()}] ${detection.title}`,
    body: lines.join("\n"),
    severity: detection.severity,
    // The detections list scrolls to and highlights ?detection=<id>.
    url: context.orgSlug
      ? `${base}/org/${encodeURIComponent(context.orgSlug)}/detections?detection=${encodeURIComponent(detection.id)}`
      : `${base}/dashboard`,
    timestamp: detection.detected_at,
    tag: `detection-${detection.id}`,
    detection: { ...detection, server_name: context.serverName },
  };
}

export function buildTestMessage(orgSlug: string | null): AlertMessage {
  const base = appUrl();
  return {
    title: "ThreatCrush Test Alert",
    body: "This is a test alert from ThreatCrush. If you received this, your alert destination is configured correctly.",
    severity: "info",
    url: orgSlug
      ? `${base}/org/${encodeURIComponent(orgSlug)}/settings/alerts`
      : `${base}/dashboard`,
    timestamp: new Date().toISOString(),
    tag: "threatcrush-test",
  };
}
