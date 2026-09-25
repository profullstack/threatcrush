import "server-only";
import { validatePublicHttpsUrl } from "@/lib/ssrf-guard";

/** The config key holding the delivery URL, for destination types that POST to one. */
export const DESTINATION_URL_FIELDS: Readonly<Record<string, string>> = {
  webhook: "url",
  slack: "webhook_url",
  discord: "webhook_url",
};

/**
 * Why `config` cannot be saved for a destination of `type`, or null when it
 * can. Types that deliver to a URL must carry an https URL on a public host:
 * the server POSTs to it, so anything else is a request into our own network.
 */
export async function destinationConfigError(type: string, config: unknown): Promise<string | null> {
  const field = DESTINATION_URL_FIELDS[type];
  if (!field) return null;

  const url =
    config && typeof config === "object" ? (config as Record<string, unknown>)[field] : undefined;
  if (typeof url !== "string" || !url.trim()) {
    return `config.${field} is required for ${type} destinations`;
  }

  try {
    await validatePublicHttpsUrl(url);
    return null;
  } catch (err) {
    return `config.${field}: ${(err as Error).message}`;
  }
}
