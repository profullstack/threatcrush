/**
 * "Mark this key as expected CI": SHA256 fingerprints kept in this app's
 * localStorage (same key as the web dashboard), applied with
 * @threatcrush/event-detail's applyExpectedKeys so a listed key's logins show
 * as a quiet info row. The agent itself only quiets them when the fingerprint
 * is in `[ssh_context] expected_keys`; the detail view shows that snippet.
 */
const STORAGE_KEY = 'threatcrush.expectedCiKeys'

export function loadExpectedKeys(): Set<string> {
  try {
    const raw = JSON.parse(globalThis.localStorage?.getItem(STORAGE_KEY) ?? '[]') as unknown
    return new Set(Array.isArray(raw) ? raw.filter((k): k is string => typeof k === 'string' && k.startsWith('SHA256:')) : [])
  } catch {
    return new Set()
  }
}

export function saveExpectedKeys(keys: ReadonlySet<string>): void {
  try {
    globalThis.localStorage?.setItem(STORAGE_KEY, JSON.stringify([...keys].slice(0, 500)))
  } catch {
    /* no storage */
  }
}
