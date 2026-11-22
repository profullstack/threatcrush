import { createHash, timingSafeEqual } from "node:crypto";
import type { NextRequest } from "next/server";
import { LIMITS, type ScanFile } from "@/lib/labeler";
import { SHA256_URI } from "@/lib/labeler-sign";

/** Read a request body as JSON, refusing more than `max` bytes while streaming (Content-Length can lie). */
export async function readJsonCapped(req: NextRequest, max: number): Promise<{ ok: true; body: unknown } | { ok: false; status: number; error: string }> {
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (declared > max) return { ok: false, status: 413, error: `body over ${max} bytes` };
  if (!req.body) return { ok: false, status: 400, error: "Body must be JSON" };
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel().catch(() => {});
      return { ok: false, status: 413, error: `body over ${max} bytes` };
    }
    chunks.push(value);
  }
  try {
    return { ok: true, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) };
  } catch {
    return { ok: false, status: 400, error: "Body must be JSON" };
  }
}

/**
 * Scanning costs CPU and outbound lookups, so it needs a token. Tokens are kept
 * only as SHA-256 hex in LABELER_SCAN_TOKENS (comma separated) and compared in
 * constant time.
 */
export function scanAuthorized(req: NextRequest, env: NodeJS.ProcessEnv = process.env): boolean {
  const name = "LABELER_SCAN_TOKENS";
  const allowed = (env[name] ?? "")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => /^[0-9a-f]{64}$/.test(s));
  if (allowed.length === 0) return false;
  const token = (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "").trim();
  if (token.length < 24 || token.length > 256) return false;
  const got = createHash("sha256").update(token).digest();
  let ok = false;
  for (const a of allowed) ok = timingSafeEqual(got, Buffer.from(a, "hex")) || ok;
  return ok;
}

// Path: relative, printable, no traversal or control characters. Used only for display and extension checks.
const PATH_RE = /^[^\x00-\x1f\x7f\\]+$/;
const B64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/** Validate {files:[{path, content_b64}]}. Returns the decoded files or an error string. */
export function parseScanFiles(body: unknown): { files: ScanFile[] } | { error: string; status: number } {
  const raw = (body as { files?: unknown } | null)?.files;
  if (!Array.isArray(raw) || raw.length === 0) return { error: "files must be a non-empty array of {path, content_b64}", status: 400 };
  if (raw.length > LIMITS.maxFiles) return { error: `at most ${LIMITS.maxFiles} files per scan`, status: 413 };
  const files: ScanFile[] = [];
  let total = 0;
  for (const [i, f] of raw.entries()) {
    const path = (f as { path?: unknown })?.path;
    const b64 = (f as { content_b64?: unknown })?.content_b64;
    if (typeof path !== "string" || path.length === 0 || path.length > LIMITS.maxPathLength || !PATH_RE.test(path) || path.split("/").includes("..")) {
      return { error: `files[${i}].path is invalid`, status: 400 };
    }
    if (typeof b64 !== "string" || !B64_RE.test(b64) || b64.length % 4 !== 0) return { error: `files[${i}].content_b64 is not base64`, status: 400 };
    const bytes = Buffer.from(b64, "base64");
    if (bytes.length > LIMITS.maxFileBytes) return { error: `files[${i}] is over ${LIMITS.maxFileBytes} bytes`, status: 413 };
    total += bytes.length;
    if (total > LIMITS.maxTotalBytes) return { error: `files total over ${LIMITS.maxTotalBytes} bytes`, status: 413 };
    files.push({ path, bytes: new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength) });
  }
  return { files };
}

/** Validate {uris:[...]} for /query: only sha256: subjects, deduplicated. */
export function parseQueryUris(body: unknown): { uris: string[] } | { error: string; status: number } {
  const raw = (body as { uris?: unknown } | null)?.uris;
  if (!Array.isArray(raw) || raw.length === 0) return { error: "uris must be a non-empty array of sha256:<hex>", status: 400 };
  if (raw.length > LIMITS.maxQueryUris) return { error: `at most ${LIMITS.maxQueryUris} uris per query`, status: 413 };
  if (!raw.every((u) => typeof u === "string")) return { error: "every uri must be sha256:<64 hex>", status: 400 };
  const uris = [...new Set((raw as string[]).map((u) => u.trim().toLowerCase()))];
  if (!uris.every((u) => SHA256_URI.test(u))) return { error: "every uri must be sha256:<64 hex>", status: 400 };
  return { uris };
}

export const NO_STORE = { "Cache-Control": "no-store" } as const;
