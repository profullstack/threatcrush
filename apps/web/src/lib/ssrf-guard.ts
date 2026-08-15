import "server-only";
import { isIP } from "net";
import dns from "dns/promises";
import http from "node:http";
import https from "node:https";

/**
 * Shared SSRF guard for every endpoint that fetches a user-supplied URL.
 *
 * This logic used to live only in /api/scan; /api/modules/fetch-meta had none
 * at all, so `{"url":"http://127.0.0.1:3000/api/health"}` reached internal
 * services (TC-08), and its four logo probes amplified that into five requests
 * per call (TC-40).
 *
 * TC-21 (DNS rebinding) is closed by safeFetch: the name is resolved once, the
 * resulting address is checked, and the socket is then pinned to that exact
 * address. Validating with `fetch()` alone is not enough, because fetch does
 * its own second resolution — a record that flips in between would be honoured.
 */

/** `new URL("http://[::1]/").hostname` keeps the brackets; sockets want them off. */
function unbracket(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
}

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
    const lookupHost = unbracket(hostname);
    const addresses = isIP(lookupHost)
      ? [{ address: lookupHost }]
      : await dns.lookup(lookupHost, { all: true });
    return addresses.some(({ address }) => isBlockedAddress(address));
  } catch {
    // If DNS resolution fails, fail closed (treat as non-resolvable / potentially malicious)
    return true;
  }
}

/**
 * Validate a URL and return the single address the request must be pinned to.
 *
 * Rejects if *any* returned address is blocked, not just the one we pick: a
 * hostname answering with both a public and a private address is exactly the
 * shape a rebinding attack takes, so there is no safe address to choose.
 */
export async function resolveSafeAddress(url: URL): Promise<string> {
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("URL must be http or https");
  }

  const host = unbracket(url.hostname);
  let addresses: string[];

  if (isIP(host)) {
    addresses = [host];
  } else {
    try {
      addresses = (await dns.lookup(host, { all: true })).map((entry) => entry.address);
    } catch {
      throw new Error("Requests to internal addresses are not allowed");
    }
  }

  if (addresses.length === 0 || addresses.some(isBlockedAddress)) {
    throw new Error("Requests to internal addresses are not allowed");
  }

  return addresses[0];
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
const REQUEST_TIMEOUT_MS = 10_000;
/** Nothing this guard fetches (HTML <head>, favicons) is legitimately larger. */
const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;
/** Statuses the Response constructor forbids a body on. */
const NULL_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);

function toHeaderRecord(headers: HeadersInit | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) return out;
  if (headers instanceof Headers) {
    headers.forEach((value, key) => {
      out[key] = value;
    });
  } else if (Array.isArray(headers)) {
    for (const [key, value] of headers) out[key] = value;
  } else {
    Object.assign(out, headers);
  }
  return out;
}

/**
 * A dns.lookup replacement that ignores the hostname and always answers with
 * the address we already validated. This is what actually closes TC-21.
 */
function pinnedLookup(address: string) {
  const family = isIP(address);
  return (
    _hostname: string,
    options: { all?: boolean } | ((...args: never[]) => void),
    callback?: (...args: never[]) => void,
  ) => {
    const done = (typeof options === "function" ? options : callback) as (
      err: NodeJS.ErrnoException | null,
      addressOrList: unknown,
      family?: number,
    ) => void;
    const wantsAll = typeof options === "object" && options !== null && options.all === true;
    if (wantsAll) done(null, [{ address, family }]);
    else done(null, address, family);
  };
}

function requestPinned(url: URL, init: RequestInit, address: string): Promise<Response> {
  const isHttps = url.protocol === "https:";
  const transport = isHttps ? https : http;
  const hostname = unbracket(url.hostname);
  const headers = toHeaderRecord(init.headers);
  if (!Object.keys(headers).some((key) => key.toLowerCase() === "host")) {
    headers.host = url.host;
  }

  return new Promise<Response>((resolve, reject) => {
    const signal = init.signal;
    if (signal?.aborted) {
      reject(new Error("Request aborted"));
      return;
    }

    const req = transport.request(
      {
        protocol: url.protocol,
        hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method: (init.method || "GET").toUpperCase(),
        headers,
        // Certificates are still checked against the real name, not the IP.
        servername: isHttps && !isIP(hostname) ? hostname : undefined,
        lookup: pinnedLookup(address) as never,
        timeout: REQUEST_TIMEOUT_MS,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let total = 0;

        res.on("data", (chunk: Buffer) => {
          total += chunk.length;
          if (total > MAX_RESPONSE_BYTES) {
            res.destroy();
            reject(new Error("Response too large"));
            return;
          }
          chunks.push(chunk);
        });

        res.on("error", reject);
        res.on("end", () => {
          const status = res.statusCode ?? 502;
          const outHeaders = new Headers();
          for (const [key, value] of Object.entries(res.headers)) {
            if (Array.isArray(value)) value.forEach((one) => outHeaders.append(key, one));
            else if (value != null) outHeaders.append(key, String(value));
          }
          const body = NULL_BODY_STATUSES.has(status) ? null : Buffer.concat(chunks);
          resolve(new Response(body as BodyInit | null, { status, headers: outHeaders }));
        });
      },
    );

    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy(new Error("Request timed out"));
    });

    // Callers pass their own deadline (AbortSignal.timeout, an AbortController).
    // REQUEST_TIMEOUT_MS is a ceiling, not a replacement for it — without this
    // a caller asking for 5s would silently get 10s.
    if (signal) {
      const onAbort = () => req.destroy(new Error("Request aborted"));
      signal.addEventListener("abort", onAbort, { once: true });
      req.on("close", () => signal.removeEventListener("abort", onAbort));
    }

    const body = init.body;
    if (body != null) {
      if (typeof body === "string" || Buffer.isBuffer(body) || body instanceof Uint8Array) {
        req.write(body);
      } else {
        req.destroy();
        reject(new Error("Unsupported request body for a pinned request"));
        return;
      }
    }
    req.end();
  });
}

/**
 * fetch() that validates the target — and every redirect hop — against the
 * guard above, then connects to the address it validated.
 *
 * Redirects are followed manually: `redirect: "follow"` would let a public host
 * bounce us straight to 169.254.169.254 without a second check.
 *
 * `init.redirect: "manual"` returns the 3xx response untouched, for callers that
 * want to inspect or refuse the hop themselves.
 */
export async function safeFetch(
  rawUrl: string,
  init: RequestInit = {},
  maxRedirects = MAX_REDIRECTS,
): Promise<Response> {
  let current = new URL(rawUrl);
  const manual = init.redirect === "manual";

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const address = await resolveSafeAddress(current);
    const res = await requestPinned(current, init, address);

    if (manual || !REDIRECT_STATUSES.has(res.status)) return res;

    const location = res.headers.get("location");
    if (!location) return res;
    current = new URL(location, current);
  }

  throw new Error("Too many redirects");
}
