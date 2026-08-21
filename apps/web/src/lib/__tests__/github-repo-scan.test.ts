import { describe, expect, it, vi } from "vitest";
import {
  MAX_FILE_BYTES,
  isScannable,
  isSkippedPath,
  prioritise,
  scanRepository,
} from "../github-repo-scan";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const entry = (path: string, size = 100, sha = `sha-${path}`) => ({ path, sha, size });

describe("isSkippedPath", () => {
  it("skips lockfiles, which are other people's code", () => {
    expect(isSkippedPath("pnpm-lock.yaml")).toBe(true);
    expect(isSkippedPath("apps/web/package-lock.json")).toBe(true);
    expect(isSkippedPath("go.sum")).toBe(true);
  });

  it("skips vendored and build directories at any depth", () => {
    expect(isSkippedPath("node_modules/left-pad/index.js")).toBe(true);
    expect(isSkippedPath("apps/web/.next/static/chunk.js")).toBe(true);
    expect(isSkippedPath("vendor/lib.go")).toBe(true);
  });

  it("skips generated artifacts", () => {
    expect(isSkippedPath("dist/app.min.js")).toBe(true);
    expect(isSkippedPath("public/app.js.map")).toBe(true);
  });

  it("keeps ordinary source", () => {
    expect(isSkippedPath("src/index.ts")).toBe(false);
    expect(isSkippedPath("package.json")).toBe(false);
  });
});

describe("isScannable", () => {
  it("accepts known source extensions", () => {
    expect(isScannable(entry("src/index.ts"))).toBe(true);
    expect(isScannable(entry("main.py"))).toBe(true);
  });

  it("accepts manifests by name", () => {
    expect(isScannable(entry("package.json"))).toBe(true);
    expect(isScannable(entry("requirements.txt"))).toBe(true);
  });

  it("rejects unknown extensions and extensionless files", () => {
    expect(isScannable(entry("logo.png"))).toBe(false);
    expect(isScannable(entry("LICENSE"))).toBe(false);
  });

  it("rejects files over the per-file byte ceiling", () => {
    expect(isScannable(entry("huge.ts", MAX_FILE_BYTES + 1))).toBe(false);
    expect(isScannable(entry("fine.ts", MAX_FILE_BYTES))).toBe(true);
  });

  it("rejects empty files, which cost a request and can match nothing", () => {
    expect(isScannable(entry("empty.ts", 0))).toBe(false);
  });
});

describe("prioritise", () => {
  it("puts manifests first, then shallowest paths", () => {
    const ordered = prioritise([
      entry("a/b/c/deep.ts"),
      entry("root.ts"),
      entry("package.json"),
      entry("a/mid.ts"),
    ]).map((e) => e.path);

    expect(ordered).toEqual(["package.json", "root.ts", "a/mid.ts", "a/b/c/deep.ts"]);
  });
});

describe("scanRepository", () => {
  function fetcherFor(files: Record<string, string>, opts: { truncated?: boolean } = {}) {
    return vi.fn(async (url: string) => {
      if (url.includes("/git/trees/")) {
        return jsonResponse({
          truncated: Boolean(opts.truncated),
          tree: Object.keys(files).map((path) => ({
            path,
            type: "blob",
            sha: `sha:${path}`,
            size: Buffer.byteLength(files[path]),
          })),
        });
      }
      const sha = decodeURIComponent(url.split("/git/blobs/")[1] ?? "");
      const path = sha.replace(/^sha:/, "");
      const content = files[path];
      if (content === undefined) return jsonResponse({ message: "Not Found" }, 404);
      return jsonResponse({
        content: Buffer.from(content, "utf8").toString("base64"),
        encoding: "base64",
      });
    });
  }

  it("finds a hardcoded secret in a scanned file", async () => {
    // Assembled at runtime rather than written as a literal. The scanner under
    // test still receives the whole string, but the file itself contains no
    // key-shaped token — GitHub's push protection blocks a push over a fixture
    // that merely looks like a live Stripe key, and this repo's gitleaks job
    // reads every ref, so such a fixture is unpushable on any branch.
    const fakeKey = ["sk", "live", "abcdefghijklmnopqrstuvwx"].join("_");
    const fetchImpl = fetcherFor({
      "src/config.ts": `const key = "${fakeKey}";\n`,
    });

    const result = await scanRepository("tok", "org/repo", "main", fetchImpl);

    expect(result.filesScanned).toBe(1);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].file).toBe("src/config.ts");
    expect(result.peak).toBeTruthy();
  });

  it("reports a clean repository as clean, not as an error", async () => {
    const fetchImpl = fetcherFor({ "src/ok.ts": "export const add = (a: number, b: number) => a + b;\n" });

    const result = await scanRepository("tok", "org/repo", "main", fetchImpl);

    expect(result.findings).toEqual([]);
    expect(result.peak).toBeNull();
    expect(result.truncated).toBe(false);
    expect(result.truncationReason).toBeNull();
  });

  it("never requests a skipped file", async () => {
    const fetchImpl = fetcherFor({
      "node_modules/evil/index.js": 'eval(userInput);\n',
      "src/ok.ts": "export const x = 1;\n",
    });

    await scanRepository("tok", "org/repo", "main", fetchImpl);

    const blobUrls = fetchImpl.mock.calls.map(([url]) => url).filter((u) => u.includes("/git/blobs/"));
    expect(blobUrls.some((u) => u.includes("node_modules"))).toBe(false);
  });

  it("propagates GitHub's tree truncation so a partial scan is never reported clean", async () => {
    const fetchImpl = fetcherFor({ "src/ok.ts": "export const x = 1;\n" }, { truncated: true });

    const result = await scanRepository("tok", "org/repo", "main", fetchImpl);

    expect(result.truncated).toBe(true);
    expect(result.truncationReason).toContain("truncated");
  });

  it("survives a blob that 404s mid-scan", async () => {
    const fetchImpl = vi.fn(async (url: string) => {
      if (url.includes("/git/trees/")) {
        return jsonResponse({
          tree: [
            { path: "a.ts", type: "blob", sha: "sha:a", size: 20 },
            { path: "b.ts", type: "blob", sha: "sha:b", size: 20 },
          ],
        });
      }
      if (url.includes("sha:a")) return jsonResponse({ message: "Not Found" }, 404);
      return jsonResponse({
        content: Buffer.from("export const x = 1;\n", "utf8").toString("base64"),
        encoding: "base64",
      });
    });

    const result = await scanRepository("tok", "org/repo", "main", fetchImpl);

    expect(result.filesConsidered).toBe(2);
    expect(result.filesScanned).toBe(1);
  });

  it("throws when the tree itself cannot be read", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ message: "Not Found" }, 404));
    await expect(scanRepository("tok", "org/gone", "main", fetchImpl)).rejects.toThrow();
  });
});
