import { NextRequest, NextResponse } from "next/server";
import { languageOf, scanText, type ScanLanguage } from "@threatcrush/scan";

/**
 * The same rules the CLI runs, over submitted text.
 *
 * This route exists because `@threatcrush/scan` exists. Before the engine was
 * extracted from `apps/cli`, the only way to run these rules was to install the
 * CLI; the web app could not have offered this without a second copy of the
 * rule set, which for a rule set whose value is careful false-positive tuning
 * is worse than not offering it at all.
 *
 * Imports the default entry point, not `@threatcrush/scan/node` — nothing here
 * touches a filesystem, so there is no tree walker and no SARIF writer in this
 * bundle.
 */

/**
 * Cap on submitted content.
 *
 * Every rule is a regular expression run per line, and the rule set includes
 * `redos-nested-quantifier` precisely because catastrophic backtracking is
 * real. An unbounded body on an unauthenticated endpoint is the shape of a
 * cheap denial of service, so the input is bounded before any rule sees it.
 */
const MAX_BYTES = 256 * 1024;
const MAX_LINES = 20_000;

const LANGUAGES: readonly ScanLanguage[] = [
  "javascript",
  "typescript",
  "python",
  "ruby",
  "go",
  "java",
  "php",
  "shell",
  "config",
  "other",
];

/**
 * POST /api/scan/code
 * Free code scanner — no auth required, matching /api/scan.
 */
export async function POST(request: NextRequest) {
  let body: { content?: string; filename?: string; language?: string };
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const { content, filename, language } = body;

  if (typeof content !== "string" || content.length === 0) {
    return NextResponse.json({ error: "content is required" }, { status: 400 });
  }

  // Byte length, not string length: the limit is about how much work this
  // costs to serve, and a multi-byte character is not one byte.
  if (Buffer.byteLength(content, "utf8") > MAX_BYTES) {
    return NextResponse.json(
      { error: `content exceeds ${MAX_BYTES} bytes` },
      { status: 413 },
    );
  }

  const lineCount = content.split("\n").length;
  if (lineCount > MAX_LINES) {
    return NextResponse.json(
      { error: `content exceeds ${MAX_LINES} lines` },
      { status: 413 },
    );
  }

  if (language !== undefined && !LANGUAGES.includes(language as ScanLanguage)) {
    return NextResponse.json(
      { error: `unknown language: ${language} (expected ${LANGUAGES.join(", ")})` },
      { status: 400 },
    );
  }

  // The filename is used for language detection and echoed back on each
  // finding. It is never opened — this route has no filesystem access — so a
  // traversal sequence in it reaches nothing. It is still bounded and stripped
  // of directories, because a caller should not be able to put arbitrary text
  // into a response that another user may see.
  const safeName = (filename ?? "snippet.txt").split("/").pop()?.slice(0, 128) || "snippet.txt";
  const resolved = (language as ScanLanguage | undefined) ?? languageOf(safeName);

  const findings = scanText(safeName, content, resolved);

  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) summary[finding.severity] += 1;

  return NextResponse.json({
    filename: safeName,
    language: resolved,
    lines_scanned: lineCount,
    // Excerpts are redacted by the engine before they reach here, so echoing a
    // finding never returns the credential that produced it.
    findings,
    summary,
  });
}
