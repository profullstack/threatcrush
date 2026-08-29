/**
 * Client-side engagement tracking for the on-site guide reader.
 *
 * Deliberately tiny and dependency-free: this runs on a marketing page whose
 * whole point is that it renders instantly. Nothing here may throw — private
 * browsing modes make `sessionStorage` access itself raise.
 */

const SESSION_KEY = "tc_reader_session";

export type UtmFields = Partial<
  Record<"utm_source" | "utm_medium" | "utm_campaign" | "utm_content" | "utm_term", string>
>;

function randomId(): string {
  try {
    return crypto.randomUUID();
  } catch {
    return `s_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
  }
}

/**
 * A per-tab id so repeat scroll beacons collapse onto one row. Scoped to the
 * session, not the device: we are measuring one reading of one document, and a
 * persistent id would quietly become cross-visit tracking nobody asked for.
 */
export function getSessionId(): string {
  if (typeof window === "undefined") return "";
  try {
    const existing = window.sessionStorage.getItem(SESSION_KEY);
    if (existing) return existing;
    const id = randomId();
    window.sessionStorage.setItem(SESSION_KEY, id);
    return id;
  } catch {
    // Storage blocked. Fall back to a per-load id; we lose row collapsing but
    // the page still works, which matters more.
    return randomId();
  }
}

export function getUtm(): UtmFields {
  if (typeof window === "undefined") return {};
  const out: UtmFields = {};
  try {
    const params = new URLSearchParams(window.location.search);
    (["utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term"] as const).forEach(
      (k) => {
        const v = params.get(k);
        if (v) out[k] = v.slice(0, 120);
      },
    );
  } catch {
    /* malformed query string — not worth a broken page */
  }
  return out;
}

export type ProgressPayload = {
  session_id: string;
  slug: string;
  read_percent: number;
  seconds_engaged: number;
  furthest_section: string | null;
  completed: boolean;
  referrer?: string;
  utm?: UtmFields;
};

/**
 * Beacon a progress update. Uses `sendBeacon` so it survives the page being
 * closed mid-flight; falls back to a keepalive fetch where it is unavailable.
 */
export function sendProgress(payload: ProgressPayload): void {
  if (typeof window === "undefined") return;
  const body = JSON.stringify(payload);
  try {
    if (navigator.sendBeacon) {
      const blob = new Blob([body], { type: "application/json" });
      if (navigator.sendBeacon("/api/reader-events", blob)) return;
    }
    void fetch("/api/reader-events", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body,
      keepalive: true,
    }).catch(() => {});
  } catch {
    /* analytics must never break reading */
  }
}
