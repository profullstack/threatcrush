/**
 * "Mark this key as expected CI" on the viewer's side: SHA256 fingerprints in
 * localStorage, applied with @threatcrush/event-detail's applyExpectedKeys so
 * listed logins show as a quiet info row. The desktop app keeps the same list
 * under the same key. Never throws: no storage just means no allowlist.
 */
const STORAGE_KEY = "threatcrush.expectedCiKeys";

export function loadExpectedKeys(): Set<string> {
  try {
    const raw = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "[]");
    return new Set(Array.isArray(raw) ? raw.filter((k): k is string => typeof k === "string" && k.startsWith("SHA256:")) : []);
  } catch {
    return new Set();
  }
}

export function saveExpectedKeys(keys: ReadonlySet<string>): void {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify([...keys].slice(0, 500))); } catch { /* private window */ }
}
