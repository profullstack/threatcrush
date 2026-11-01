import { hostname } from 'node:os';
import { readFileSync, writeFileSync } from 'node:fs';
import type { HardeningResult } from './harden.js';

export interface CisEvidenceReport {
  schema_version: 1;
  generated_at: string;
  benchmark_catalog_checked_at: '2026-11-01';
  host: { hostname: string; os_id: string | null; os_version: string | null; pretty_name: string | null };
  benchmark: { name: string; version: string; source: string } | null;
  assessment: 'partial';
  mapped_controls: 0;
  total_checks: number;
  hardening_score: number;
  checks: Array<HardeningResult & { cis_control_ids: string[]; mapping_status: 'unverified' }>;
  limitations: string[];
}

const CIS_UBUNTU_URL = 'https://www.cisecurity.org/benchmark/ubuntu_linux';
const CIS_DEBIAN_URL = 'https://www.cisecurity.org/benchmark/debian_linux';
// Release numbers and titles are taken from the official CIS product pages.
// Keep the check-to-control crosswalk separate; IDs must be verified against
// each edition before being added to a report.
const EDITIONS: Record<string, Record<string, { version: string; name: string; source: string }>> = {
  ubuntu: {
    '26.04': { version: '1.0.0', name: 'CIS Ubuntu Linux 26.04 LTS', source: CIS_UBUNTU_URL },
    '24.04': { version: '2.0.0', name: 'CIS Ubuntu Linux 24.04 LTS', source: CIS_UBUNTU_URL },
    '22.04': { version: '3.0.0', name: 'CIS Ubuntu Linux 22.04 LTS', source: CIS_UBUNTU_URL },
    '20.04': { version: '3.0.0', name: 'CIS Ubuntu Linux 20.04 LTS', source: CIS_UBUNTU_URL },
  },
  debian: {
    '13': { version: '1.1.0', name: 'CIS Debian Linux 13', source: CIS_DEBIAN_URL },
    '12': { version: '2.0.0', name: 'CIS Debian Linux 12', source: CIS_DEBIAN_URL },
    '11': { version: '2.0.0', name: 'CIS Debian Linux 11', source: CIS_DEBIAN_URL },
  },
};

function osRelease(): Record<string, string> {
  let raw = '';
  try { raw = readFileSync('/etc/os-release', 'utf8'); } catch { return {}; }
  const fields: Record<string, string> = {};
  for (const line of raw.split('\n')) {
    const match = /^([A-Z0-9_]+)=(.*)$/.exec(line);
    if (!match) continue;
    const value = match[2].trim().replace(/^(["'])(.*)\1$/, '$2');
    fields[match[1]] = value;
  }
  return fields;
}

export function buildCisEvidenceReport(findings: HardeningResult[], score: number, now = new Date()): CisEvidenceReport {
  const os = osRelease();
  const id = os.ID?.toLowerCase() ?? null;
  const version = os.VERSION_ID ?? null;
  const edition = id && version ? EDITIONS[id]?.[version] : undefined;
  return {
    schema_version: 1,
    generated_at: now.toISOString(),
    benchmark_catalog_checked_at: '2026-11-01',
    host: { hostname: hostname(), os_id: id, os_version: version, pretty_name: os.PRETTY_NAME ?? null },
    benchmark: edition ? { name: edition.name, version: edition.version, source: edition.source } : null,
    assessment: 'partial',
    mapped_controls: 0,
    total_checks: findings.length,
    hardening_score: score,
    checks: findings.map((finding) => ({ ...finding, cis_control_ids: [], mapping_status: 'unverified' })),
    limitations: [
      'This report contains ThreatCrush hardening checks only; it does not assess a CIS Benchmark profile.',
      'No check-to-control crosswalk has been verified against the selected CIS Benchmark edition, so no CIS control IDs are claimed.',
      'A PASS is a result for the named ThreatCrush check, not a CIS control pass or a certification claim.',
    ],
  };
}

export function renderCisMarkdown(report: CisEvidenceReport): string {
  const benchmark = report.benchmark
    ? `${report.benchmark.name} v${report.benchmark.version} (${report.benchmark.source})`
    : 'No CIS Benchmark edition is known for this OS release';
  const rows = report.checks.map((check) => {
    const facts = check.details ? ` Observed data: ${JSON.stringify(check.details)}` : '';
    const evidence = `${check.explanation}${facts}`.replace(/[|\r\n]+/g, ' ').trim();
    const recommendation = check.recommendation?.replace(/[|\r\n]+/g, ' ').trim() ?? '—';
    return `| ${check.key} | ${check.status.toUpperCase()} | Unverified | ${evidence} | ${recommendation} |`;
  });
  return [
    '# CIS benchmark evidence report',
    '',
    '> Partial ThreatCrush evidence only. This is not a CIS Benchmark assessment or certification report.',
    '',
    `- Generated: ${report.generated_at}`,
    `- CIS edition catalog checked: ${report.benchmark_catalog_checked_at}`,
    `- Host: ${report.host.hostname}`,
    `- OS: ${report.host.pretty_name ?? 'unknown'} (${report.host.os_id ?? 'unknown'} ${report.host.os_version ?? 'unknown'})`,
    `- Benchmark edition: ${benchmark}`,
    `- ThreatCrush hardening score: ${report.hardening_score}/100`,
    `- Mapped CIS controls: ${report.mapped_controls}`,
    '',
    '| Check | Result | CIS mapping | Evidence | Recommendation |',
    '|---|---|---|---|---|',
    ...rows,
    '',
    '## Limitations',
    '',
    ...report.limitations.map((limitation) => `- ${limitation}`),
    '',
  ].join('\n');
}

function pdfEscape(value: string): string {
  return value.replace(/[^\x20-\x7e]/g, '?').replace(/[\\()]/g, '\\$&');
}

/** Minimal dependency-free PDF writer for plain-text evidence reports. */
export function renderCisPdf(markdown: string): Buffer {
  const lines = markdown.split('\n').flatMap((line) => {
    const safe = line.replace(/[^\x20-\x7e]/g, '?');
    if (safe.length <= 96) return [safe];
    const parts: string[] = [];
    for (let i = 0; i < safe.length; i += 96) parts.push(safe.slice(i, i + 96));
    return parts;
  });
  const pages: string[][] = [];
  for (let i = 0; i < lines.length; i += 48) pages.push(lines.slice(i, i + 48));
  if (pages.length === 0) pages.push([]);

  const objects: string[] = [];
  const pageRefs: string[] = [];
  objects.push('<< /Type /Catalog /Pages 2 0 R >>');
  objects.push('');
  objects.push('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>');
  pages.forEach((page, index) => {
    const pageId = 4 + index * 2;
    const streamId = pageId + 1;
    pageRefs.push(`${pageId} 0 R`);
    const text = ['BT', '/F1 9 Tf', '50 760 Td', '14 TL', ...page.flatMap((line) => [`(${pdfEscape(line)}) Tj`, 'T*']), 'ET'].join('\n');
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${streamId} 0 R >>`);
    objects.push(`<< /Length ${Buffer.byteLength(text, 'ascii')} >>\nstream\n${text}\nendstream`);
  });
  objects[1] = `<< /Type /Pages /Kids [${pageRefs.join(' ')}] /Count ${pages.length} >>`;

  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets.push(Buffer.byteLength(pdf, 'ascii'));
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xref = Buffer.byteLength(pdf, 'ascii');
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const offset of offsets.slice(1)) pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(pdf, 'ascii');
}

export function writeCisReport(path: string, format: 'md' | 'pdf' | 'json', report: CisEvidenceReport): void {
  const markdown = renderCisMarkdown(report);
  const content = format === 'json'
    ? `${JSON.stringify(report, null, 2)}\n`
    : format === 'pdf'
      ? renderCisPdf(markdown)
      : markdown;
  writeFileSync(path, content);
}
