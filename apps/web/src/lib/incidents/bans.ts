import { isIP } from "node:net";

/** A block/unblock row from remediation_actions, as the daemon or a user recorded it. */
export interface BanAction {
  action_type: string;
  target_value: string;
  status: string;
  created_at: string;
  executed_at: string | null;
  expires_at: string | null;
  metadata: Record<string, unknown> | null;
}

export type BanState = "active" | "expired" | "lifted" | "failed" | "dry_run" | "none";

/** What happened to one attacking address, so an incident can say "banned" instead of nothing. */
export interface IpBanSummary {
  ip: string;
  state: BanState;
  /** Executed (enforced) blocks in the incident window; the daemon re-blocks on each offence. */
  blocks: number;
  failed: number;
  dry_run: number;
  first_banned_at: string | null;
  last_banned_at: string | null;
  /** Latest expiry among enforced blocks; null with blocks > 0 means no expiry was recorded. */
  banned_until: string | null;
  /** Longest single block, in seconds (the top of the escalation ladder). */
  longest_seconds: number | null;
  lifted_at: string | null;
  lifted_reason: string | null;
  last_error: string | null;
}

const IP_CANDIDATE = /(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}/gi;

/** Addresses named in free text (incident summary, timeline), validated so ports and times are not mistaken for IPs. */
export function ipsInText(text: string | null | undefined): string[] {
  if (!text) return [];
  return [...new Set((text.match(IP_CANDIDATE) ?? []).filter((s) => isIP(s) !== 0))];
}

const at = (a: BanAction) => a.executed_at ?? a.created_at;
const ms = (s: string | null | undefined) => (s ? Date.parse(s) : NaN);
const meta = (a: BanAction, key: string) => {
  const v = a.metadata?.[key];
  return typeof v === "string" ? v : v === true ? true : null;
};

export function summarizeBans(ips: string[], actions: BanAction[], now = Date.now()): IpBanSummary[] {
  return ips.map((ip) => {
    const mine = actions.filter((a) => a.target_value === ip).sort((a, b) => ms(at(a)) - ms(at(b)));
    const blocks = mine.filter((a) => a.action_type === "block");
    const dry = blocks.filter((a) => meta(a, "dry_run") === true);
    const enforced = blocks.filter((a) => a.status === "executed" && meta(a, "dry_run") !== true);
    const failed = blocks.filter((a) => a.status === "failed");
    const unblocks = mine.filter((a) => a.action_type === "unblock" && a.status === "executed");

    let until: number | null = null;
    let open = false;
    let longest: number | null = null;
    for (const b of enforced) {
      const exp = ms(b.expires_at);
      if (Number.isNaN(exp)) open = true;
      else {
        until = until === null ? exp : Math.max(until, exp);
        const len = Math.round((exp - ms(at(b))) / 1000);
        if (len > 0) longest = longest === null ? len : Math.max(longest, len);
      }
    }
    const lastBlock = enforced.at(-1);
    const lastUnblock = unblocks.at(-1);
    // An unblock after the newest block ends it; "ban expired" is the daemon's own ladder expiry.
    const liftedAfter = lastBlock && lastUnblock && ms(at(lastUnblock)) >= ms(at(lastBlock)) ? lastUnblock : null;
    const liftedReason = liftedAfter ? (meta(liftedAfter, "reason") as string | null) : null;
    const manual = !!liftedAfter && !/expired/i.test(liftedReason ?? "");

    let state: BanState = "none";
    if (enforced.length) {
      if (manual) state = "lifted";
      else if (!liftedAfter && (open || (until !== null && until > now))) state = "active";
      else state = "expired";
    } else if (failed.length) state = "failed";
    else if (dry.length) state = "dry_run";

    return {
      ip,
      state,
      blocks: enforced.length,
      failed: failed.length,
      dry_run: dry.length,
      first_banned_at: enforced[0] ? at(enforced[0]) : null,
      last_banned_at: lastBlock ? at(lastBlock) : null,
      banned_until: open ? null : until === null ? null : new Date(until).toISOString(),
      longest_seconds: longest,
      lifted_at: liftedAfter ? at(liftedAfter) : null,
      lifted_reason: liftedReason,
      last_error: (failed.at(-1) && (meta(failed.at(-1)!, "error") as string | null)) || null,
    };
  });
}
