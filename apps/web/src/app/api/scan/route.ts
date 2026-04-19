import { NextRequest, NextResponse } from "next/server";

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

  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    return NextResponse.json({ error: "URL must be http or https" }, { status: 400 });
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
      redirect: "follow",
    });
    clearTimeout(timeout);

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
    const res = await fetch(url, {
      method: "HEAD",
      signal: AbortSignal.timeout(5000),
      redirect: "follow",
    });
    return res.ok;
  } catch {
    return false;
  }
}
