type DetectionLike = {
  rule_id?: string | null;
  username?: string | null;
  raw_metadata?: Record<string, unknown> | null;
};

function evidenceOf(detection: DetectionLike): Record<string, unknown> | null {
  const raw = detection.raw_metadata;
  const evidence = raw?.evidence;
  return typeof evidence === "object" && evidence !== null && !Array.isArray(evidence)
    ? evidence as Record<string, unknown>
    : null;
}

/** SSH usernames may be present only in the preserved sshd evidence on older detections. */
export function detectionUsername(detection: DetectionLike): string | null {
  if (typeof detection.username === "string" && detection.username.trim()) return detection.username.trim();

  const evidence = evidenceOf(detection);
  if (!evidence) return null;

  for (const key of ["ssh_user", "user", "username", "account"]) {
    const value = evidence[key];
    if (typeof value === "string" && value.trim()) return value.trim();
  }

  if (evidence.module !== "ssh-guard" || typeof evidence.message !== "string") return null;
  const match = /^(?:SSH login accepted for|Failed SSH login for|Invalid SSH user:)\s+([^\s]+)/i.exec(evidence.message);
  return match?.[1] ?? null;
}

export function isSshDetection(detection: DetectionLike): boolean {
  return Boolean(detection.rule_id?.startsWith("ssh-") || evidenceOf(detection)?.module === "ssh-guard");
}
