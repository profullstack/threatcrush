import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { CIS_CROSSWALK } from '@threatcrush/scan/cis';
import { buildCisEvidenceReport, renderCisMarkdown, renderCisPdf, tagCisMappings } from '../cis-report.js';
import type { HardeningResult } from '../harden.js';

const REPO = join(__dirname, '..', '..', '..', '..', '..');

/** Every check key `threatcrush harden` can emit, read from its source. */
function hardenKeys(): string[] {
  const src = readFileSync(join(REPO, 'apps/cli/src/commands/harden.ts'), 'utf8');
  const keys = [...src.matchAll(/\bkey: '([a-z0-9-]+)'/g), ...src.matchAll(/checkKey = '([a-z0-9-]+)'/g)].map((m) => m[1]);
  return [...new Set(keys)];
}

/** Every PRD 0005 config check id, read from the code-scanner source. */
function configCheckIds(): string[] {
  const src = ['checks.ts', 'index.ts']
    .map((file) => readFileSync(join(REPO, 'modules/code-scanner/src/config', file), 'utf8'))
    .join('\n');
  return [...new Set([...src.matchAll(/checkId: '([a-z0-9-]+)'/g)].map((m) => m[1]))];
}

const UBUNTU_2404 = { ID: 'ubuntu', VERSION_ID: '24.04', PRETTY_NAME: 'Ubuntu 24.04.1 LTS' };

function finding(key: string, status: HardeningResult['status'] = 'pass'): HardeningResult {
  return { key, status, severity: 'high', title: key, explanation: `${key} observed`, details: { observed: true } };
}

describe('CIS crosswalk coverage', () => {
  it('finds the checks it is supposed to cover', () => {
    expect(hardenKeys()).toHaveLength(9);
    expect(configCheckIds().length).toBeGreaterThanOrEqual(10);
  });

  it('lists every harden check as mapped with provenance or explicitly unmapped', () => {
    for (const key of hardenKeys()) {
      const entry = CIS_CROSSWALK.find((row) => row.scope === 'harden' && row.check === key);
      expect(entry, `harden check ${key} missing from the CIS crosswalk`).toBeDefined();
      expect(entry!.mappings.length > 0 || Boolean(entry!.unmapped)).toBe(true);
    }
  });

  it('lists every PRD 0005 config check as mapped with provenance or explicitly unmapped', () => {
    for (const id of configCheckIds()) {
      const entry = CIS_CROSSWALK.find((row) => row.scope === 'config' && row.check === id);
      expect(entry, `config check ${id} missing from the CIS crosswalk`).toBeDefined();
      expect(entry!.mappings.length > 0 || Boolean(entry!.unmapped)).toBe(true);
    }
  });

  it('has no crosswalk rows for checks that no longer exist', () => {
    const harden = new Set(hardenKeys());
    const config = new Set(configCheckIds());
    for (const row of CIS_CROSSWALK) {
      expect((row.scope === 'harden' ? harden : config).has(row.check), `stale crosswalk row ${row.scope}:${row.check}`).toBe(true);
    }
  });
});

describe('tagCisMappings', () => {
  it('tags each finding from the pinned catalog and records the host OS on every finding', () => {
    const [root, password] = tagCisMappings([finding('ssh-root-login'), finding('ssh-password-auth')], UBUNTU_2404);
    expect(root).toMatchObject({ cis_control_ids: ['5.1.20'], cis_mapping_status: 'verified', cis_mapping_coverage: 'full' });
    expect(root.details).toMatchObject({
      cis_profile_name: 'CIS Ubuntu Linux 24.04 LTS', cis_profile_version: '1.0.0',
      cis_cac_tag: 'v0.1.82', cis_cac_file: 'controls/cis_ubuntu2404.yml', cis_host_os_id: 'ubuntu', cis_host_os_version: '24.04',
    });
    expect(root.cis_controls?.[0]).toMatchObject({ id: '5.1.20', cac_rules: ['sshd_disable_root_login'], levels: ['l1_server', 'l1_workstation'] });
    expect(password).toMatchObject({ cis_control_ids: [], cis_mapping_status: 'unmapped' });
    expect(password.details).toMatchObject({ cis_host_os_id: 'ubuntu', cis_host_os_version: '24.04' });
  });

  it('marks everything unverified on an OS with no pinned profile', () => {
    const tagged = tagCisMappings(hardenKeys().map((key) => finding(key)), { ID: 'fedora', VERSION_ID: '41' });
    expect(tagged.every((f) => f.cis_mapping_status === 'unverified' && f.cis_control_ids?.length === 0)).toBe(true);
  });
});

describe('CIS evidence report', () => {
  const findings = hardenKeys().map((key) => finding(key, key === 'firewall-active' ? 'fail' : 'pass'));
  const report = buildCisEvidenceReport(findings, 72, new Date('2026-11-22T00:00:00Z'), UBUNTU_2404);

  it('counts mapped and unmapped checks for the host profile', () => {
    expect(report.schema_version).toBe(2);
    expect(report.mapping_profile).toMatchObject({ name: 'CIS Ubuntu Linux 24.04 LTS', version: '1.0.0', cac_tag: 'v0.1.82' });
    expect(report.benchmark?.version).toBe('2.0.0');
    expect(report.mapped_checks).toBe(5);
    expect(report.unmapped_checks).toBe(4);
    expect(report.mapped_controls).toBe(6);
    expect(report.limitations.join(' ')).toMatch(/v2\.0\.0 as current; no mapping to v2\.0\.0 is claimed/);
  });

  it('keeps the auditor disclaimer in every format', () => {
    const markdown = renderCisMarkdown(report);
    const pdf = renderCisPdf(markdown).toString('latin1');
    const json = JSON.stringify(report);
    for (const out of [markdown, pdf, json]) expect(out).toContain('Evidence for an auditor, not certification.');
    expect(markdown).toContain('| ssh-root-login | PASS | 5.1.20 "Ensure sshd PermitRootLogin is disabled (Automated)"');
    expect(markdown).toContain('Unmapped: No pinned profile has a PasswordAuthentication control');
    expect(markdown).not.toContain('"cis_');
    expect(pdf.startsWith('%PDF-1.4')).toBe(true);
    expect(pdf.trimEnd().endsWith('%%EOF')).toBe(true);
    expect(pdf).toContain('5.1.20');
    expect(pdf).toContain('7.1.11');
  });
});
