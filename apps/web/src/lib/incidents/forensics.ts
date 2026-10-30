/** Safe, bounded presentation of recorded facts; never identify a person from a daemon UID. */
export interface DetectionEvidence {
  id: string; server_id: string; rule_id: string | null; detected_at: string;
  source_ip: string | null; username: string | null; raw_metadata: Record<string, unknown> | null;
}
export function forensicEvidence(d: DetectionEvidence) {
  const raw = d.raw_metadata?.evidence;
  const ev = raw && typeof raw === "object" && !Array.isArray(raw) ? raw as Record<string, unknown> : {};
  const text = (v: unknown, max = 200) => typeof v === "string" || typeof v === "number" ? String(v).slice(0, max) : null;
  const message = text(ev.message, 500);
  const preauth = !!message && /\[preauth\]/i.test(message);
  return {
    detection_id: d.id, server_id: d.server_id, rule_id: d.rule_id, at: text(ev.at) ?? d.detected_at,
    source_ip: text(d.source_ip) ?? text(ev.source_ip), source_ip_basis: text(ev.source_ip_basis), target_account: text(d.username) ?? text(ev.ssh_user) ?? text(ev.user),
    logging_account: text(ev.system_account), logging_uid: text(ev.system_uid), process: text(ev.process), pid: text(ev.pid),
    unit: text(ev.unit), boot_id: text(ev.boot_id), journal_cursor: text(ev.journal_cursor, 300),
    auth_method: text(ev.auth_method), key_fingerprint: text(ev.fingerprint), command: text(ev.command), message,
    attribution: preauth
      ? "This record occurred before authentication. It does not establish a successful login, an executed command, or the identity of a person."
      : "Accounts and key fingerprints identify recorded credentials or processes; they do not by themselves identify a person.",
    next_steps: preauth ? [
      "Inspect sshd journal records around this timestamp, using the same boot and process ID when available, to recover the remote address and connection outcome.",
      "Check for an accepted login in that connection before treating this as unauthorized access. A rejected malformed packet alone does not prove compromise.",
      "If repeated probing is confirmed, review existing SSH rate limits and block policy. Do not block an address that has not been established by evidence.",
    ] : [
      "Correlate the timestamp, host, process/session and source address with the original logs.",
      "Verify the affected service and record the action taken and its outcome before closing the incident.",
    ],
  };
}
