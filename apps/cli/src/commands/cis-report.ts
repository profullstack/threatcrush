import { hostname } from 'node:os';
import { readFileSync, writeFileSync } from 'node:fs';
import {
  CIS_CATALOG_CHECKED_AT,
  CIS_DISCLAIMER,
  cisEditionCaveat,
  cisMappingCell,
  cisMappingFields,
  cisProfileFor,
  currentCisEdition,
  renderTextPdf,
  resolveCisMapping,
  type CisControlRef,
  type CisMappingStatus,
} from '@threatcrush/scan/cis';
import type { HardeningResult } from './harden.js';

export interface CisEvidenceReport {
  schema_version: 2;
  generated_at: string;
  disclaimer: string;
  benchmark_catalog_checked_at: string;
  host: { hostname: string; os_id: string | null; os_version: string | null; pretty_name: string | null };
  /** The current CIS edition for this OS according to the CIS catalog. */
  benchmark: { name: string; version: string; source: string } | null;
  /** The pinned ComplianceAsCode profile the control ids come from. */
  mapping_profile: {
    name: string; version: string; cac_tag: string; cac_file: string; cac_file_sha: string; source: string;
  } | null;
  assessment: 'partial';
  mapped_controls: number;
  mapped_checks: number;
  unmapped_checks: number;
  total_checks: number;
  hardening_score: number;
  checks: Array<HardeningResult & {
    cis_control_ids: string[];
    mapping_status: CisMappingStatus;
    mapping_coverage?: 'full' | 'partial';
    mapping_controls?: CisControlRef[];
    mapping_source?: string;
    mapping_benchmark?: string;
    mapping_reason?: string;
    mapping_detail: string;
  }>;
  limitations: string[];
}

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

/**
 * Attach CIS mapping fields from the pinned crosswalk to every finding. The
 * host OS goes into `details` for every finding, mapped or not, so the
 * dashboard can re-derive the mapping from the same catalog instead of
 * trusting ids sent by the agent.
 */
export function tagCisMappings(findings: HardeningResult[], os = osRelease()): HardeningResult[] {
  const osId = os.ID?.toLowerCase() ?? null;
  const osVersion = os.VERSION_ID ?? null;
  return findings.map((finding) => {
    const resolved = resolveCisMapping(finding.key, 'harden', osId, osVersion);
    const fields = cisMappingFields(resolved);
    return {
      ...finding,
      cis_control_ids: fields.cis_control_ids,
      cis_mapping_status: fields.cis_mapping_status,
      ...(fields.cis_mapping_coverage ? { cis_mapping_coverage: fields.cis_mapping_coverage } : {}),
      ...(fields.cis_controls ? { cis_controls: fields.cis_controls } : {}),
      ...(fields.cis_mapping_status === 'verified' && fields.cis_mapping_source ? { cis_mapping_source: fields.cis_mapping_source } : {}),
      ...(fields.cis_mapping_status === 'verified' && fields.cis_mapping_benchmark ? { cis_mapping_benchmark: fields.cis_mapping_benchmark } : {}),
      ...(fields.cis_unmapped_reason ? { cis_unmapped_reason: fields.cis_unmapped_reason } : {}),
      details: {
        ...(finding.details ?? {}),
        ...fields,
        cis_host_os_id: osId,
        cis_host_os_version: osVersion,
      },
    };
  });
}

export function buildCisEvidenceReport(findings: HardeningResult[], score: number, now = new Date(), os = osRelease()): CisEvidenceReport {
  const id = os.ID?.toLowerCase() ?? null;
  const version = os.VERSION_ID ?? null;
  const edition = currentCisEdition(id, version);
  const profile = cisProfileFor(id, version);
  const checks = tagCisMappings(findings, os).map((finding) => {
    const resolved = resolveCisMapping(finding.key, 'harden', id, version);
    return {
      ...finding,
      cis_control_ids: finding.cis_control_ids ?? [],
      mapping_status: finding.cis_mapping_status ?? 'unverified' as const,
      ...(finding.cis_mapping_coverage ? { mapping_coverage: finding.cis_mapping_coverage } : {}),
      ...(finding.cis_controls ? { mapping_controls: finding.cis_controls } : {}),
      ...(finding.cis_mapping_source ? { mapping_source: finding.cis_mapping_source } : {}),
      ...(finding.cis_mapping_benchmark ? { mapping_benchmark: finding.cis_mapping_benchmark } : {}),
      ...(finding.cis_unmapped_reason ? { mapping_reason: finding.cis_unmapped_reason } : {}),
      mapping_detail: cisMappingCell(resolved),
    };
  });
  const mappedControls = new Set(checks.flatMap((check) => check.mapping_status === 'verified' ? check.cis_control_ids : []));
  const mappedChecks = checks.filter((check) => check.mapping_status === 'verified').length;
  return {
    schema_version: 2,
    generated_at: now.toISOString(),
    disclaimer: CIS_DISCLAIMER,
    benchmark_catalog_checked_at: CIS_CATALOG_CHECKED_AT,
    host: { hostname: hostname(), os_id: id, os_version: version, pretty_name: os.PRETTY_NAME ?? null },
    benchmark: edition ? { ...edition } : null,
    mapping_profile: profile ? {
      name: profile.benchmarkName,
      version: profile.benchmarkVersion,
      cac_tag: profile.cacTag,
      cac_file: profile.cacFile,
      cac_file_sha: profile.cacFileSha,
      source: profile.source,
    } : null,
    assessment: 'partial',
    mapped_controls: mappedControls.size,
    mapped_checks: mappedChecks,
    unmapped_checks: checks.length - mappedChecks,
    total_checks: findings.length,
    hardening_score: score,
    checks,
    limitations: [
      'This report contains ThreatCrush hardening checks only; it does not assess a CIS Benchmark profile.',
      cisEditionCaveat(profile, edition),
      'A mapping with partial coverage means the check reads the same setting with a narrower scope or looser threshold: its FAIL is a real finding against the control, its PASS does not satisfy the control.',
      'Checks marked Unmapped have no matching control or ComplianceAsCode rule in the pinned profile; no id is invented for them.',
      'A PASS is a result for the named ThreatCrush check, not a CIS control pass or a certification claim.',
    ],
  };
}

function cell(value: string): string {
  return value.replace(/[|\r\n]+/g, ' ').trim();
}

export function renderCisMarkdown(report: CisEvidenceReport): string {
  const benchmark = report.benchmark
    ? `${report.benchmark.name} v${report.benchmark.version} (${report.benchmark.source})`
    : 'No CIS Benchmark edition is known for this OS release';
  const profile = report.mapping_profile
    ? `${report.mapping_profile.name} v${report.mapping_profile.version} via ComplianceAsCode ${report.mapping_profile.cac_tag} ${report.mapping_profile.cac_file} (${report.mapping_profile.source})`
    : 'None (no pinned ComplianceAsCode profile for this OS release)';
  const rows = report.checks.map((check) => {
    const { details } = check;
    // The mapping is shown in its own column; keep evidence to observed facts.
    const observed = details
      ? Object.fromEntries(Object.entries(details).filter(([key]) => !key.startsWith('cis_')))
      : {};
    const facts = Object.keys(observed).length ? ` Observed data: ${JSON.stringify(observed)}` : '';
    const evidence = cell(`${check.explanation}${facts}`);
    const recommendation = check.recommendation ? cell(check.recommendation) : '-';
    return `| ${check.key} | ${check.status.toUpperCase()} | ${cell(check.mapping_detail)} | ${evidence} | ${recommendation} |`;
  });
  return [
    '# CIS benchmark evidence report',
    '',
    `> ${report.disclaimer}`,
    '',
    `- Generated: ${report.generated_at}`,
    `- CIS edition catalog checked: ${report.benchmark_catalog_checked_at}`,
    `- Host: ${report.host.hostname}`,
    `- OS: ${report.host.pretty_name ?? 'unknown'} (${report.host.os_id ?? 'unknown'} ${report.host.os_version ?? 'unknown'})`,
    `- Current benchmark edition: ${benchmark}`,
    `- Mapping profile: ${profile}`,
    `- ThreatCrush hardening score: ${report.hardening_score}/100`,
    `- Checks mapped to CIS controls: ${report.mapped_checks} of ${report.total_checks} (${report.mapped_controls} distinct controls); not mapped (unmapped, or no pinned profile for this OS): ${report.unmapped_checks}`,
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

/** Plain-text PDF of the Markdown report (dependency-free writer). */
export function renderCisPdf(markdown: string): Buffer {
  return Buffer.from(renderTextPdf(markdown));
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
