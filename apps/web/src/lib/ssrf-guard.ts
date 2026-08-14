import "server-only";
import { isIP } from "net";
import dns from "dns/promises";

/**
 * Shared SSRF guard for every endpoint that fetches a user-supplied URL.
 *
 * This logic used to live only in /api/scan; /api/modules/fetch-meta had none
 * at all, so `{"url":"http://127.0.0.1:3000/api/health"}` reached internal
 * services (TC-08), and its four logo probes amplified that into five requests
 * per call (TC-40).
 *
 * Residual risk: a host whose DNS record flips between the check and the
 * connection (DNS rebinding, TC-21) can still slip through, because Node's
 * fetch resolves the name again itself. Closing that needs a dispatcher that
 * connects to a pinned address.
 */

export function isBlockedAddress(address: string): boolean {
  const version = isIP(address);
  const mappedHex = address.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  const ipv4Address =
    version === 4
      ? address
      : mappedHex
        ? [
            parseInt(mappedHex[1], 16) >> 8,
            parseInt(mappedHex[1], 16) & 255,
            parseInt(mappedHex[2], 16) >> 8,
            parseInt(mappedHex[2], 16) & 255,
          ].join(".")
        : address.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i)?.[1];

  if (ipv4Address) {
    const parts = ipv4Address.split(".").map((part) => Number(part));
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
      return true;
    }

    const [first, second] = parts;
    return (
      first === 0 ||
      first === 10 ||
      first === 127 ||
      (first === 169 && second === 254) || // link-local, incl. cloud metadata
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      first >= 224
    );
  }

  const normalized = address.toLowerCase();
  return (
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("fe80:") ||
    /^f[cd][0-9a-f]{0,2}:/i.test(normalized) ||
    normalized.startsWith("ff")
  );
}

export async function isPrivateIP(hostname: string): Promise<boolean> {
  try {
    const lookupHost = hostname.startsWith("[") && hostname.endsWith("]")
      ? hostname.slice(1, -1)
      : hostname;
    const addresses = isIP(lookupHost)
      ? [{ address: lookupHost }]
      : await dns.lookup(lookupHost, { all: true });
    return addresses.some(({ address }) => isBlockedAddress(address));
  } catch {
    // If DNS resolution fails, fail closed (treat as non-resolvable / potentially malicious)
    return true;
  }
}

export async function validateExternalHttpUrl(url: URL): Promise<void> {
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("URL must be http or https");
  }
  if (await isPrivateIP(url.hostname)) {
    throw new Error("Requests to internal addresses are not allowed");
  }
}

/** True when the URL is safe to fetch; never throws. */
export async function isSafeExternalUrl(url: string): Promise<boolean> {
  try {
    await validateExternalHttpUrl(new URL(url));
    return true;
  } catch {
    return false;
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECTS = 3;

/**
 * fetch() that validates the target — and every redirect hop — against the
 * guard above. Redirects must be followed manually: `redirect: "follow"` would
 * let a public host bounce us straight to 169.254.169.254.
 */
export async function safeFetch(
  rawUrl: string,
  init: RequestInit = {},
  maxRedirects = MAX_REDIRECTS,
): Promise<Response> {
  let current = new URL(rawUrl);

  for (let hop = 0; hop <= maxRedirects; hop++) {
    await validateExternalHttpUrl(current);

    const res = await fetch(current.href, { ...init, redirect: "manual" });

    if (!REDIRECT_STATUSES.has(res.status)) return res;

    const location = res.headers.get("location");
    if (!location) return res;
    current = new URL(location, current);
  }

  throw new Error("Too many redirects");
}
