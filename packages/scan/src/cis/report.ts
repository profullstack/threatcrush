/**
 * Shared wording and per-check mapping fields for the CIS evidence report,
 * used by both `threatcrush harden --report cis` and the dashboard export so
 * the two never disagree about what a mapping means.
 */
import { cisProvenance, type CisControlMapping, type CisMappingStatus, type CisProfile, type CisResolvedMapping } from './crosswalk';
import type { CisEdition } from './editions';

export const CIS_DISCLAIMER = 'Evidence for an auditor, not certification. This is a partial ThreatCrush evidence report, not a CIS Benchmark assessment, and a PASS is a result for the named ThreatCrush check, not a CIS control pass.';

export interface CisControlRef {
  id: string;
  title: string;
  levels: string[];
  cac_rules: string[];
  coverage: 'full' | 'partial';
  note?: string;
}

/** The mapping fields a report row (and an uploaded finding's details) carries. */
export interface CisMappingFields {
  cis_control_ids: string[];
  cis_mapping_status: CisMappingStatus;
  cis_mapping_coverage?: 'full' | 'partial';
  cis_controls?: CisControlRef[];
  cis_mapping_benchmark?: string;
  cis_mapping_source?: string;
  cis_profile_os_id?: string;
  cis_profile_os_version?: string;
  cis_profile_name?: string;
  cis_profile_version?: string;
  cis_cac_tag?: string;
  cis_cac_file?: string;
  cis_cac_file_sha?: string;
  cis_unmapped_reason?: string;
}

function controlRef(m: CisControlMapping): CisControlRef {
  return { id: m.controlId, title: m.title, levels: [...m.levels], cac_rules: [...m.cacRules], coverage: m.coverage, ...(m.note ? { note: m.note } : {}) };
}

export function cisMappingFields(resolved: CisResolvedMapping): CisMappingFields {
  const p = resolved.profile;
  const profileFields = p ? {
    cis_profile_os_id: p.osId,
    cis_profile_os_version: p.osVersion,
    cis_profile_name: p.benchmarkName,
    cis_profile_version: p.benchmarkVersion,
    cis_cac_tag: p.cacTag,
    cis_cac_file: p.cacFile,
    cis_cac_file_sha: p.cacFileSha,
    cis_mapping_source: p.source,
    cis_mapping_benchmark: `${p.benchmarkName} v${p.benchmarkVersion}`,
  } : {};
  if (resolved.status !== 'verified') {
    return { cis_control_ids: [], cis_mapping_status: resolved.status, ...profileFields, ...(resolved.reason ? { cis_unmapped_reason: resolved.reason } : {}) };
  }
  const coverage = resolved.controls.every((c) => c.coverage === 'full') ? 'full' as const : 'partial' as const;
  return {
    cis_control_ids: resolved.controls.map((c) => c.controlId),
    cis_mapping_status: 'verified',
    cis_mapping_coverage: coverage,
    cis_controls: resolved.controls.map(controlRef),
    ...profileFields,
  };
}

/** One Markdown-safe cell describing a check's mapping, with provenance. */
export function cisMappingCell(resolved: CisResolvedMapping): string {
  const p = resolved.profile;
  if (resolved.status === 'unverified') return `Unverified: ${resolved.reason ?? 'no pinned profile'}`;
  if (resolved.status === 'unmapped' || !p) return `Unmapped: ${resolved.reason ?? 'no matching control'}`;
  return resolved.controls.map((m) => {
    const note = m.note ? ` Note: ${m.note}` : '';
    return `${m.controlId} "${m.title}" [${m.levels.join(', ')}; ${m.coverage} coverage] (${cisProvenance(p, m)}).${note}`;
  }).join(' ');
}

/** States which edition the ids come from versus the current CIS catalog. */
export function cisEditionCaveat(profile: CisProfile | null, current: CisEdition | null): string {
  if (!profile) {
    return 'No pinned ComplianceAsCode CIS profile exists for this OS release, so no CIS control ids are stated.';
  }
  const from = `Control ids come from ComplianceAsCode ${profile.cacTag} ${profile.cacFile} (git blob ${profile.cacFileSha}), which implements ${profile.benchmarkName} v${profile.benchmarkVersion}.`;
  if (current && current.version !== profile.benchmarkVersion) {
    return `${from} The CIS catalog lists v${current.version} as current; no mapping to v${current.version} is claimed and ids may differ there.`;
  }
  return from;
}
