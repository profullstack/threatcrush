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
import { existsSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const exec = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, "..");
const srcMd = join(repoRoot, "docs", "whitepaper-ctem.md");
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

/* ── Main ────────────────────────────────────────────────────────────── */
async function main() {
  await mkdir(outDir, { recursive: true });
  const md = await readFile(srcMd, "utf8");

  // Drop the first H1 (it's redundant — the cover already shows the title)
  const stripped = md.replace(/^#\s+.*\n/, "");

  const body = mdToHtml(stripped);
  const svgRaw = await readFile(coverSvg, "utf8");
  const coverDataUri = `data:image/svg+xml;base64,${Buffer.from(svgRaw).toString("base64")}`;

  const html = pageTemplate({
    title: "ThreatCrush — The CTEM Operator's Guide",
    body,
    coverDataUri,
  });
  await writeFile(outHtml, html);
  console.log(`✓ Wrote ${outHtml}`);

  // Try to render PDF via chromium headless
  const chromium = ["chromium", "chromium-browser", "google-chrome", "chrome"].find((bin) => {
    try {
      // We use exec sync below; here just shortcut with which-style check via env PATH
      return existsSync(`/usr/bin/${bin}`) || existsSync(`/snap/bin/${bin}`);
    } catch {
      return false;
    }
  });

  if (!chromium) {
    console.log("• chromium not found — skipping PDF render. Open the HTML in a browser and Print to PDF.");
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
