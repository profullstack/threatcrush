/**
 * Minimal dependency-free PDF 1.4 writer for plain-text evidence reports.
 *
 * Text only: one Helvetica font, fixed line height, wrapped lines and
 * non-ASCII replaced with `?`. It exists so the CIS evidence report can ship
 * as a PDF without pulling a PDF library into the CLI bundle.
 */

const LINE_CHARS = 96;
const LINES_PER_PAGE = 48;

function pdfEscape(value: string): string {
  return value.replace(/[\\()]/g, '\\$&');
}

function asciiLine(line: string): string {
  return line
    .replace(/[—–]/g, '-')
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[^\x20-\x7e]/g, '?');
}

/** Wrap at word boundaries where possible, hard-cut otherwise. */
function wrap(line: string): string[] {
  if (line.length <= LINE_CHARS) return [line];
  const out: string[] = [];
  let rest = line;
  while (rest.length > LINE_CHARS) {
    let cut = rest.lastIndexOf(' ', LINE_CHARS);
    if (cut < LINE_CHARS / 2) cut = LINE_CHARS;
    out.push(rest.slice(0, cut).trimEnd());
    rest = `  ${rest.slice(cut).trimStart()}`;
  }
  out.push(rest);
  return out;
}

export function renderTextPdf(text: string): Uint8Array {
  const lines = text.split('\n').flatMap((line) => wrap(asciiLine(line)));
  const pages: string[][] = [];
  for (let i = 0; i < lines.length; i += LINES_PER_PAGE) pages.push(lines.slice(i, i + LINES_PER_PAGE));
  if (pages.length === 0) pages.push([]);

  const objects: string[] = ['<< /Type /Catalog /Pages 2 0 R >>', '', '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>'];
  const pageRefs: string[] = [];
  pages.forEach((page, index) => {
    const pageId = 4 + index * 2;
    const streamId = pageId + 1;
    pageRefs.push(`${pageId} 0 R`);
    const body = ['BT', '/F1 9 Tf', '50 760 Td', '14 TL', ...page.flatMap((line) => [`(${pdfEscape(line)}) Tj`, 'T*']), 'ET'].join('\n');
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${streamId} 0 R >>`);
    objects.push(`<< /Length ${body.length} >>\nstream\n${body}\nendstream`);
  });
  objects[1] = `<< /Type /Pages /Kids [${pageRefs.join(' ')}] /Count ${pages.length} >>`;

  // Every byte is ASCII, so string length equals byte length.
  let pdf = '%PDF-1.4\n';
  const offsets: number[] = [];
  objects.forEach((object, index) => {
    offsets.push(pdf.length);
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xref = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets) pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return new TextEncoder().encode(pdf);
}
