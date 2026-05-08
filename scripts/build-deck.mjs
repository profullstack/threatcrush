#!/usr/bin/env node
/**
 * Build the ThreatCrush investor deck PDF.
 *
 *   node scripts/build-deck.mjs
 *
 * Boots the web app (Next dev mode by default — falls back to next start if
 * the build is up-to-date), opens /deck?print=1 in headless chromium, and
 * writes the PDF to apps/web/public/threatcrush-deck.pdf.
 *
 * Override the URL with TC_DECK_URL (e.g. https://threatcrush.com/deck?print=1)
 * to render against an already-running server instead.
 */
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { setTimeout as wait } from "node:timers/promises";

const exec = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const webDir = join(repoRoot, "apps", "web");
const outDir = join(webDir, "public");
const outPdf = join(outDir, "threatcrush-deck.pdf");

const port = process.env.TC_DECK_PORT || "3434";
const overrideUrl = process.env.TC_DECK_URL;
const url = overrideUrl || `http://localhost:${port}/deck?print=1`;

function findChromium() {
  for (const bin of ["chromium", "chromium-browser", "google-chrome", "chrome"]) {
    for (const prefix of ["/usr/bin", "/snap/bin", "/opt/homebrew/bin", "/usr/local/bin"]) {
      const p = `${prefix}/${bin}`;
      if (existsSync(p)) return p;
    }
  }
  return null;
}

async function waitForServer(targetUrl, timeoutMs = 60_000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const res = await fetch(targetUrl, { method: "GET" });
      if (res.ok) return;
    } catch {
      /* not ready */
    }
    await wait(500);
  }
  throw new Error(`Server at ${targetUrl} did not become ready within ${timeoutMs}ms`);
}

async function main() {
  const chromium = findChromium();
  if (!chromium) {
    console.error("✗ chromium not found. Install with: sudo apt install chromium-browser");
    process.exit(1);
  }

  await mkdir(outDir, { recursive: true });

  let serverProc = null;

  if (!overrideUrl) {
    console.log(`• starting next dev on :${port} from ${webDir}`);
    serverProc = spawn("pnpm", ["exec", "next", "dev", "-p", port], {
      cwd: webDir,
      stdio: ["ignore", "inherit", "inherit"],
      env: { ...process.env, NODE_ENV: "development" },
    });

    serverProc.on("exit", (code) => {
      if (code !== null && code !== 0) {
        console.error(`• next dev exited with code ${code}`);
      }
    });

    console.log(`• waiting for ${url}…`);
    try {
      await waitForServer(url);
    } catch (err) {
      serverProc.kill("SIGTERM");
      throw err;
    }
  } else {
    console.log(`• using TC_DECK_URL=${url}`);
  }

  try {
    console.log(`• rendering deck PDF via ${chromium}…`);
    await exec(
      chromium,
      [
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        "--no-pdf-header-footer",
        "--hide-scrollbars",
        "--virtual-time-budget=10000",
        `--print-to-pdf=${outPdf}`,
        url,
      ],
      { timeout: 180_000 }
    );
    console.log(`✓ wrote ${outPdf}`);
  } finally {
    if (serverProc && !serverProc.killed) {
      serverProc.kill("SIGTERM");
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
