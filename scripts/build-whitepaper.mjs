#!/usr/bin/env node
/**
 * Build the CTEM whitepaper.
 *
 *   node scripts/build-whitepaper.mjs
 *
 * Reads docs/whitepaper-ctem.md, converts to a print-styled HTML document
 * (with the SVG cover as page 1), writes it to apps/web/public/whitepaper/
 * threatcrush-ctem-guide.html, and — if chromium is installed — produces
 * threatcrush-ctem-guide.pdf alongside it.
 */
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync, readdirSync } from "node:fs";
import { homedir } from "node:os";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const exec = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const srcMd = join(repoRoot, "docs", "whitepaper-ctem.md");
const srcChecklist = join(repoRoot, "docs", "ctem-checklist.json");
const outWebModule = join(
  repoRoot,
  "apps",
  "web",
  "src",
  "content",
  "ctem-guide.generated.ts",
);
const outDir = join(repoRoot, "apps", "web", "public", "whitepaper");
const outHtml = join(outDir, "threatcrush-ctem-guide.html");
const outPdf = join(outDir, "threatcrush-ctem-guide.pdf");
const coverSvg = join(outDir, "cover.svg");

/* ── Minimal markdown → HTML ─────────────────────────────────────────── */
function escapeHtml(s) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function inline(s) {
  return s
    .replace(/`([^`]+)`/g, (_, c) => `<code>${escapeHtml(c)}</code>`)
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>")
    .replace(/_([^_\n]+)_/g, "<em>$1</em>")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
}

function renderTable(lines) {
  const rows = lines.map((l) =>
    l
      .replace(/^\||\|$/g, "")
      .split("|")
      .map((c) => c.trim()),
  );
  const [head, _sep, ...body] = rows;
  const thead = `<thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join("")}</tr></thead>`;
  const tbody = `<tbody>${body
    .map(
      (r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`,
    )
    .join("")}</tbody>`;
  return `<table>${thead}${tbody}</table>`;
}

function mdToHtml(md) {
  const lines = md.split("\n");
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];

    // Horizontal rule
    if (/^---+\s*$/.test(line)) {
      out.push("<hr/>");
      i++;
      continue;
    }

    // Heading
    const h = line.match(/^(#{1,6})\s+(.*)$/);
    if (h) {
      const level = h[1].length;
      out.push(`<h${level}>${inline(h[2])}</h${level}>`);
      i++;
      continue;
    }

    // Table
    if (line.startsWith("|") && i + 1 < lines.length && /^\|[\s\-:|]+\|$/.test(lines[i + 1])) {
      const tableLines = [];
      while (i < lines.length && lines[i].startsWith("|")) {
        tableLines.push(lines[i]);
        i++;
      }
      out.push(renderTable(tableLines));
      continue;
    }

    // Unordered list
    if (/^[-*]\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^[-*]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^[-*]\s+/, ""));
        i++;
        // Allow continuation lines (indented)
        while (i < lines.length && /^\s{2,}\S/.test(lines[i])) {
          items[items.length - 1] += " " + lines[i].trim();
          i++;
        }
      }
      out.push(`<ul>${items.map((t) => `<li>${inline(t)}</li>`).join("")}</ul>`);
      continue;
    }

    // Ordered list
    if (/^\d+\.\s+/.test(line)) {
      const items = [];
      while (i < lines.length && /^\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\d+\.\s+/, ""));
        i++;
        while (i < lines.length && /^\s{2,}\S/.test(lines[i])) {
          items[items.length - 1] += " " + lines[i].trim();
          i++;
        }
      }
      out.push(`<ol>${items.map((t) => `<li>${inline(t)}</li>`).join("")}</ol>`);
      continue;
    }

    // Blank line
    if (line.trim() === "") {
      i++;
      continue;
    }

    // Paragraph
    const para = [line];
    i++;
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !/^(#{1,6}|---|\||[-*]\s|\d+\.\s)/.test(lines[i])
    ) {
      para.push(lines[i]);
      i++;
    }
    out.push(`<p>${inline(para.join(" "))}</p>`);
  }
  return out.join("\n");
}

/* ── Sections (for the on-site reader TOC) ──────────────────────────── */
function slugify(s) {
  return s
    .toLowerCase()
    .replace(/^\d+\.\s*/, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * Split the stripped markdown on H2 boundaries so the web reader can build a
 * table of contents and track which section is on screen. Anything before the
 * first H2 becomes the lead-in section.
 */
function splitSections(md) {
  const lines = md.split("\n");
  const sections = [];
  let current = { id: "top", title: "Overview", lines: [] };
  for (const line of lines) {
    const h2 = line.match(/^##\s+(?!#)(.*)$/);
    if (h2) {
      if (current.lines.some((l) => l.trim())) sections.push(current);
      const title = h2[1].trim();
      current = { id: slugify(title), title, lines: [] };
      continue;
    }
    current.lines.push(line);
  }
  if (current.lines.some((l) => l.trim())) sections.push(current);

  return sections.map((s) => ({
    id: s.id,
    title: s.title,
    html: mdToHtml(s.lines.join("\n").replace(/^\s*---+\s*$/gm, "").trim()),
  }));
}

/* ── Checklist appendix ─────────────────────────────────────────────── */
function checklistToHtml(cl) {
  const total = cl.stages.reduce((n, s) => n + s.items.length, 0);
  const stages = cl.stages
    .map(
      (st) => `
  <div class="cl-stage">
    <div class="cl-stage-head">
      <span class="cl-n">${escapeHtml(st.n)}</span>
      <span class="cl-name">${escapeHtml(st.name)}</span>
      <span class="cl-q">${escapeHtml(st.question)}</span>
    </div>
    ${st.items
      .map(
        (it) => `<div class="cl-item"><div class="cl-box"></div><div class="cl-body">
      <div class="cl-title">${inline(escapeHtml(it.title))}</div>
      <p class="cl-detail">${inline(escapeHtml(it.detail))}</p>
    </div></div>`,
      )
      .join("\n    ")}
  </div>`,
    )
    .join("\n");

  const bands = cl.bands
    .map(
      (b) =>
        `<p class="cl-band"><b>${b.min}–${b.max}% &nbsp;${escapeHtml(b.label)}</b> — ${escapeHtml(b.summary)}</p>`,
    )
    .join("\n    ");

  return `
<h2 id="checklist">Appendix A. ${escapeHtml(cl.title)}</h2>
<p><em>${escapeHtml(cl.subtitle)}</em></p>
<p>${escapeHtml(cl.intro)}</p>
${stages}
  <div class="cl-score">
    <p style="margin:0 0 6px;font-weight:700;">Scoring — ${total} controls in total</p>
    <p style="margin:0 0 8px;font-size:9.5pt;">Count your ticks, divide by ${total}, multiply by 100.</p>
    ${bands}
  </div>
  <p class="disclaimer">${escapeHtml(cl.disclaimer)}</p>
`;
}

/* ── Generated module consumed by the Next.js reader ────────────────── */
function webModule({ sections, checklist, words }) {
  const banner = `// GENERATED FILE — do not edit by hand.
// Source: docs/whitepaper-ctem.md + docs/ctem-checklist.json
// Regenerate with: pnpm build:whitepaper
`;
  return `${banner}
export type GuideSection = { id: string; title: string; html: string };

export type ChecklistItem = { id: string; title: string; detail: string };
export type ChecklistStage = {
  id: string;
  n: string;
  name: string;
  question: string;
  items: ChecklistItem[];
};
export type ChecklistBand = { min: number; max: number; label: string; summary: string };
export type Checklist = {
  slug: string;
  title: string;
  subtitle: string;
  intro: string;
  disclaimer: string;
  bands: ChecklistBand[];
  stages: ChecklistStage[];
};

export const GUIDE_WORD_COUNT = ${words};
export const GUIDE_READ_MINUTES = ${Math.max(1, Math.round(words / 220))};

export const GUIDE_SECTIONS: GuideSection[] = ${JSON.stringify(sections, null, 2)};

export const CHECKLIST: Checklist = ${JSON.stringify(checklist, null, 2)};

export const CHECKLIST_TOTAL = ${checklist.stages.reduce((n, s) => n + s.items.length, 0)};
`;
}

/* ── HTML template ──────────────────────────────────────────────────── */
function pageTemplate({ title, body, coverDataUri }) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${escapeHtml(title)}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet"/>
<style>
  :root {
    --tc-green: #00ff88;
    --tc-green-dim: #00cc6e;
    --ink: #0c1310;
    --ink-soft: #2c3530;
    --paper: #fbfaf6;
    --rule: #d8dcd5;
  }
  * { box-sizing: border-box; }
  html, body {
    margin: 0;
    padding: 0;
    background: var(--paper);
    color: var(--ink);
    font-family: "Inter", system-ui, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
  }
  .page {
    max-width: 7.5in;
    margin: 0 auto;
    padding: 0.85in 0.85in 1in 0.85in;
  }
  .cover {
    page-break-after: always;
    margin: 0;
    padding: 0;
    max-width: none;
  }
  .cover img {
    display: block;
    width: 100%;
    height: auto;
  }
  h1, h2, h3, h4 {
    font-family: "Inter", system-ui, sans-serif;
    color: var(--ink);
    line-height: 1.25;
    letter-spacing: -0.01em;
  }
  h1 {
    font-size: 28pt;
    font-weight: 900;
    margin-top: 0;
    margin-bottom: 0.5em;
  }
  h2 {
    font-size: 18pt;
    font-weight: 800;
    margin-top: 1.6em;
    margin-bottom: 0.4em;
    padding-top: 0.4em;
    border-top: 2px solid var(--tc-green);
    page-break-after: avoid;
  }
  h3 {
    font-size: 13pt;
    font-weight: 700;
    margin-top: 1.4em;
    margin-bottom: 0.3em;
    page-break-after: avoid;
  }
  h4 {
    font-size: 11pt;
    font-weight: 700;
    margin-top: 1.1em;
    margin-bottom: 0.2em;
  }
  p {
    margin: 0.6em 0;
    text-align: justify;
    hyphens: auto;
  }
  strong { font-weight: 700; color: #000; }
  em { font-style: italic; color: var(--ink-soft); }
  a { color: var(--tc-green-dim); text-decoration: underline; }
  hr {
    border: none;
    border-top: 1px solid var(--rule);
    margin: 1.4em 0;
  }
  ul, ol {
    margin: 0.6em 0 0.6em 1.2em;
    padding: 0;
  }
  li { margin: 0.25em 0; }
  ul li::marker { color: var(--tc-green-dim); }
  code {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    background: #eef0ec;
    padding: 1px 5px;
    border-radius: 3px;
    font-size: 0.92em;
    color: #1a2520;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 1em 0;
    font-size: 0.95em;
    page-break-inside: avoid;
  }
  th, td {
    text-align: left;
    padding: 8px 10px;
    border-bottom: 1px solid var(--rule);
    vertical-align: top;
  }
  th {
    background: #f0f2ee;
    font-weight: 700;
    border-bottom: 2px solid var(--tc-green);
  }
  /* TL;DR style first paragraph */
  .page > p:first-of-type strong:first-child {
    color: var(--tc-green-dim);
  }
  /* Checklist appendix */
  .cl-stage {
    page-break-inside: avoid;
    margin: 1.1em 0;
  }
  .cl-stage-head {
    display: flex;
    align-items: baseline;
    gap: 8px;
    border-bottom: 2px solid var(--tc-green);
    padding-bottom: 3px;
    margin-bottom: 0.5em;
  }
  .cl-n {
    font-family: "JetBrains Mono", ui-monospace, monospace;
    font-size: 10pt;
    color: var(--tc-green-dim);
    font-weight: 700;
  }
  .cl-name { font-size: 14pt; font-weight: 800; }
  .cl-q { font-size: 9.5pt; font-style: italic; color: var(--ink-soft); margin-left: auto; }
  .cl-item {
    display: flex;
    gap: 8px;
    margin: 0.45em 0;
    page-break-inside: avoid;
  }
  .cl-box {
    flex: 0 0 auto;
    width: 11px;
    height: 11px;
    border: 1.5px solid var(--ink-soft);
    border-radius: 2px;
    margin-top: 3px;
  }
  .cl-body { flex: 1 1 auto; }
  .cl-title { font-weight: 700; font-size: 10.5pt; }
  .cl-detail { font-size: 9.5pt; color: var(--ink-soft); text-align: left; margin: 1px 0 0; }
  .cl-score {
    border: 1.5px solid var(--tc-green);
    border-radius: 6px;
    padding: 10px 14px;
    margin: 1.2em 0;
    page-break-inside: avoid;
  }
  .cl-band { font-size: 9.5pt; margin: 0.3em 0; }
  .cl-band b { color: var(--tc-green-dim); }
  .disclaimer { font-size: 7pt; font-style: italic; color: #6b7570; margin-top: 1.2em; }
  /* Print rules */
  @page {
    size: Letter;
    margin: 0.6in;
  }
  @page :first {
    margin: 0;
  }
  @media print {
    .page { padding: 0; }
    h2 { page-break-after: avoid; }
  }
</style>
</head>
<body>
  <div class="cover"><img src="${coverDataUri}" alt="ThreatCrush — From Vulnerability Management to Continuous Threat Exposure Management"/></div>
  <div class="page">
${body}
  </div>
</body>
</html>
`;
}

/* ── Locate a headless Chrome ───────────────────────────────────────── */
/**
 * Checks, in order: $CHROME_PATH, the usual system install paths, then any
 * browser Puppeteer has already downloaded (newest version first). Dev boxes
 * and CI images frequently have only the last of those.
 */
function findChromium() {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) {
    return process.env.CHROME_PATH;
  }

  const names = ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"];
  const dirs = ["/usr/bin", "/usr/local/bin", "/snap/bin", "/opt/google/chrome"];
  for (const dir of dirs) {
    for (const name of names) {
      const p = join(dir, name);
      if (existsSync(p)) return p;
    }
  }

  const cache = join(homedir(), ".cache", "puppeteer", "chrome");
  if (existsSync(cache)) {
    const versions = readdirSync(cache)
      .filter((d) => d.startsWith("linux-") || d.startsWith("mac") || d.startsWith("win"))
      .sort(compareChromeDirs)
      .reverse();
    for (const v of versions) {
      for (const rel of [
        ["chrome-linux64", "chrome"],
        ["chrome-mac-x64", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing"],
        ["chrome-mac-arm64", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing"],
      ]) {
        const p = join(cache, v, ...rel);
        if (existsSync(p)) return p;
      }
    }
  }

  return null;
}

/** Sort `linux-152.0.7977.42` style dir names numerically, not lexically. */
function compareChromeDirs(a, b) {
  const parts = (s) => (s.split("-")[1] || "").split(".").map(Number);
  const [pa, pb] = [parts(a), parts(b)];
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

/* ── Main ────────────────────────────────────────────────────────────── */
async function main() {
  await mkdir(outDir, { recursive: true });
  const md = await readFile(srcMd, "utf8");

  // Drop the first H1 (it's redundant — the cover already shows the title)
  const stripped = md.replace(/^#\s+.*\n/, "");

  const checklist = JSON.parse(await readFile(srcChecklist, "utf8"));

  // The checklist is an appendix in the PDF and an interactive scorer on the
  // site; both render from the same JSON so they can never drift.
  const body = mdToHtml(stripped) + checklistToHtml(checklist);
  const svgRaw = await readFile(coverSvg, "utf8");
  const coverDataUri = `data:image/svg+xml;base64,${Buffer.from(svgRaw).toString("base64")}`;

  const html = pageTemplate({
    title: "ThreatCrush — The CTEM Operator's Guide",
    body,
    coverDataUri,
  });
  await writeFile(outHtml, html);
  console.log(`✓ Wrote ${outHtml}`);

  const sections = splitSections(stripped);
  const words = stripped.split(/\s+/).filter(Boolean).length;
  await mkdir(dirname(outWebModule), { recursive: true });
  await writeFile(outWebModule, webModule({ sections, checklist, words }));
  console.log(`✓ Wrote ${outWebModule} (${sections.length} sections, ${words} words)`);

  const chromium = findChromium();

  if (!chromium) {
    console.log("• chromium not found — skipping PDF render. Open the HTML in a browser and Print to PDF.");
    console.log("  Set CHROME_PATH=/path/to/chrome to render it here.");
    return;
  }

  console.log(`• Rendering PDF via ${chromium}…`);
  try {
    await exec(chromium, [
      "--headless=new",
      "--no-sandbox",
      "--disable-gpu",
      "--no-pdf-header-footer",
      `--print-to-pdf=${outPdf}`,
      `file://${outHtml}`,
    ], { timeout: 120_000 });
    console.log(`✓ Wrote ${outPdf}`);
  } catch (err) {
    console.warn("• PDF render failed:", err.message);
    console.warn("  HTML still written; print to PDF from a browser.");
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
