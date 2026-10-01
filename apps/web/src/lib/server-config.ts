/**
 * `threatcrush save` uploads a machine's daemon config. Alert channels carry
 * SMTP passwords, webhook URLs and API keys; none of that belongs in the
 * dashboard database. The CLI redacts before sending and the server redacts
 * again, so an older or modified client cannot store a secret either.
 */

export const MAX_CONFIG_BYTES = 64 * 1024;

const SECRET_KEY = /pass(word)?|secret|token|api_?key|private|webhook|dsn|url|routing_key|auth/i;
export const REDACTED = "[redacted]";
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export function redactConfig(value: unknown, depth = 0): unknown {
  if (depth > 10) return REDACTED;
  if (Array.isArray(value)) return value.map((v) => redactConfig(v, depth + 1));
  if (value && typeof value === "object") {
    // Built from pairs rather than by assigning computed keys, and keys that
    // could reach a prototype are dropped: the keys come from the uploaded config.
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key]) => !UNSAFE_KEYS.has(key))
        .map(([key, v]) => [
          key,
          SECRET_KEY.test(key) && v !== null && typeof v !== "object" && typeof v !== "boolean"
            ? REDACTED
            : redactConfig(v, depth + 1),
        ]),
    );
  }
  return value;
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
