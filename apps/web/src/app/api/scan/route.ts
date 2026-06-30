import { NextRequest, NextResponse } from "next/server";
import { isIP } from "net";
import dns from "dns/promises";

const SECURITY_HEADERS = [
  {
    name: "Strict-Transport-Security",
    recommendation: "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS",
  },
  {
    name: "Content-Security-Policy",
    recommendation: "Add a Content-Security-Policy header to prevent XSS and injection attacks",
  },
  {
    name: "X-Frame-Options",
    recommendation: "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent clickjacking",
  },
  {
    name: "X-Content-Type-Options",
    recommendation: "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing",
  },
  {
    name: "Referrer-Policy",
    recommendation: "Add 'Referrer-Policy: strict-origin-when-cross-origin' to control referrer information",
  },
  {
    name: "Permissions-Policy",
    recommendation: "Add a Permissions-Policy header to control browser feature access",
  },
];

function computeGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

function isBlockedAddress(address: string): boolean {
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
      (first === 169 && second === 254) ||
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

async function isPrivateIP(hostname: string): Promise<boolean> {
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

async function validateExternalHttpUrl(url: URL): Promise<void> {
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("URL must be http or https");
  }
  if (await isPrivateIP(url.hostname)) {
    throw new Error("Scanning internal addresses is not allowed");
  }
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * POST /api/scan
 * Free security header scanner — no auth required.
 */
export async function POST(request: NextRequest) {
  let body: { url?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const { url } = body;
  if (!url) {
    return NextResponse.json({ error: "url is required" }, { status: 400 });
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    return NextResponse.json({ error: "Invalid URL" }, { status: 400 });
  }

  try {
    await validateExternalHttpUrl(parsedUrl);
  } catch (err) {
    return NextResponse.json({ error: (err as Error).message }, { status: 400 });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const res = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; ThreatCrush-Scanner/1.0; +https://threatcrush.com)",
      },
      signal: controller.signal,
      redirect: "manual",
    });
    clearTimeout(timeout);

    if (REDIRECT_STATUSES.has(res.status)) {
      const location = res.headers.get("location");
      if (location) {
        const redirectUrl = new URL(location, parsedUrl);
        try {
          await validateExternalHttpUrl(redirectUrl);
        } catch (err) {
          return NextResponse.json({ error: (err as Error).message }, { status: 400 });
        }
      }
      return NextResponse.json({ error: "Redirect responses are not followed by the scanner" }, { status: 400 });
    }

    const ssl = parsedUrl.protocol === "https:";

    // Check security headers
    const headers = SECURITY_HEADERS.map((h) => {
      const value = res.headers.get(h.name);
      return {
        name: h.name,
        present: !!value,
        ...(value ? { value } : {}),
        recommendation: value ? undefined : h.recommendation,
      };
    });

    // Server info (information disclosure)
    const serverHeader = res.headers.get("Server") || undefined;
    const poweredBy = res.headers.get("X-Powered-By") || undefined;

    // Check security.txt and robots.txt
    const [securityTxt, robotsTxt] = await Promise.all([
      checkExists(`${parsedUrl.origin}/.well-known/security.txt`),
      checkExists(`${parsedUrl.origin}/robots.txt`),
    ]);

    // Calculate score
    const headersPresent = headers.filter((h) => h.present).length;
    const totalChecks = SECURITY_HEADERS.length + 4; // headers + ssl + security.txt + robots.txt + no server disclosure

    let points = 0;
    // Each security header: ~10 points (60 total)
    points += headersPresent * 10;
    // SSL: 20 points
    if (ssl) points += 20;
    // security.txt: 5 points
    if (securityTxt) points += 5;
    // robots.txt: 5 points
    if (robotsTxt) points += 5;
    // No server header disclosure: 5 points
    if (!serverHeader) points += 5;
    // No X-Powered-By disclosure: 5 points
    if (!poweredBy) points += 5;

    const maxPoints = SECURITY_HEADERS.length * 10 + 20 + 5 + 5 + 5 + 5;
    const score = Math.round((points / maxPoints) * 100);
    const grade = computeGrade(score);

    return NextResponse.json({
      url,
      score,
      grade,
      ssl,
      headers,
      checks: {
        security_txt: securityTxt,
        robots_txt: robotsTxt,
      },
      server_info: {
        ...(serverHeader ? { server: serverHeader } : {}),
        ...(poweredBy ? { powered_by: poweredBy } : {}),
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Failed to scan URL";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}

async function checkExists(url: string): Promise<boolean> {
  try {
    await validateExternalHttpUrl(new URL(url));
    const res = await fetch(url, {
      method: "HEAD",
      signal: AbortSignal.timeout(5000),
      redirect: "manual",
    });
    return res.ok;
  } catch {
    return false;
  }
}
