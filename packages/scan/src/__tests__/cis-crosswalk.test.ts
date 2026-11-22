import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import {
  CAC_TAG,
  CIS_CROSSWALK,
  CIS_PROFILES,
  cisEditionCaveat,
  cisMappingFields,
  cisProfileFor,
  currentCisEdition,
  renderTextPdf,
  resolveCisMapping,
} from '../cis';

describe('CIS crosswalk provenance', () => {
  it('pins every profile to one CaC tag with an auditable file and blob sha', () => {
    for (const p of Object.values(CIS_PROFILES)) {
      expect(p.cacTag).toBe(CAC_TAG);
      expect(p.cacFile).toMatch(/^controls\/cis_(ubuntu|debian)\d+\.yml$/);
      expect(p.cacFileSha).toMatch(/^[0-9a-f]{40}$/);
      expect(p.source).toBe(`https://github.com/ComplianceAsCode/content/blob/${CAC_TAG}/${p.cacFile}`);
      expect(p.benchmarkVersion).toMatch(/^\d+\.\d+\.\d+$/);
    }
  });

  it('gives every mapping row full provenance and every unmapped check a reason', () => {
    const seen = new Set<string>();
    for (const entry of CIS_CROSSWALK) {
      const key = `${entry.scope}:${entry.check}`;
      expect(seen.has(key), `duplicate ${key}`).toBe(false);
      seen.add(key);
      if (entry.mappings.length === 0) {
        expect(entry.unmapped?.trim().length ?? 0, `${key} has neither mappings nor an unmapped reason`).toBeGreaterThan(20);
        continue;
      }
      expect(entry.unmapped).toBeUndefined();
      for (const m of entry.mappings) {
        expect(CIS_PROFILES[m.profile], `${key} unknown profile ${m.profile}`).toBeDefined();
        expect(m.controlId).toMatch(/^\d+(\.\d+)+$/);
        expect(m.title).toMatch(/^Ensure .+\((Automated|Manual)\)$/);
        expect(m.levels.length).toBeGreaterThan(0);
        expect(m.cacRules.length).toBeGreaterThan(0);
        for (const rule of m.cacRules) expect(rule).toMatch(/^[a-z0-9_-]+$/);
        if (m.coverage === 'partial') expect(m.note, `${key} ${m.profile} partial without a note`).toBeTruthy();
      }
      const perProfile = new Set(entry.mappings.map((m) => `${m.profile}:${m.controlId}`));
      expect(perProfile.size).toBe(entry.mappings.length);
    }
  });
});

describe('resolveCisMapping', () => {
  it('maps root login on every pinned profile with full coverage', () => {
    const expected: Record<string, string> = { 'ubuntu 24.04': '5.1.20', 'ubuntu 22.04': '5.1.20', 'debian 12': '5.1.20', 'debian 13': '5.1.21' };
    for (const [os, id] of Object.entries(expected)) {
      const [osId, osVersion] = os.split(' ');
      const resolved = resolveCisMapping('ssh-root-login', 'harden', osId, osVersion);
      expect(resolved.status).toBe('verified');
      expect(resolved.controls.map((c) => c.controlId)).toEqual([id]);
      expect(cisMappingFields(resolved).cis_mapping_coverage).toBe('full');
    }
  });

  it('reports unmapped and unverified distinctly and never invents ids', () => {
    const unmapped = cisMappingFields(resolveCisMapping('ssh-password-auth', 'harden', 'ubuntu', '24.04'));
    expect(unmapped).toMatchObject({ cis_mapping_status: 'unmapped', cis_control_ids: [] });
    expect(unmapped.cis_unmapped_reason).toMatch(/PasswordAuthentication/);
    const noProfile = cisMappingFields(resolveCisMapping('ssh-root-login', 'harden', 'ubuntu', '26.04'));
    expect(noProfile).toMatchObject({ cis_mapping_status: 'unverified', cis_control_ids: [] });
    expect(resolveCisMapping('firewall-active', 'harden', 'debian', '13').controls.map((c) => c.controlId)).toEqual(['4.1.2']);
    expect(resolveCisMapping('not-a-check', 'harden', 'debian', '12').status).toBe('unmapped');
  });

  it('states the edition gap between the pinned profile and the current catalog', () => {
    const caveat = cisEditionCaveat(cisProfileFor('ubuntu', '24.04'), currentCisEdition('ubuntu', '24.04'));
    expect(caveat).toContain('v1.0.0');
    expect(caveat).toContain('v2.0.0');
    expect(caveat).toContain(CAC_TAG);
  });
});

describe('renderTextPdf', () => {
  const text = ['# CIS benchmark evidence report', '', 'Evidence for an auditor, not certification.', `5.1.20 "Ensure sshd PermitRootLogin is disabled (Automated)" — (parens) \\ back`, 'x'.repeat(300), ...Array.from({ length: 120 }, (_, i) => `line ${i}`)].join('\n');
  const pdf = new TextDecoder().decode(renderTextPdf(text));

  it('writes a structurally valid PDF with a correct xref table', () => {
    expect(pdf.startsWith('%PDF-1.4\n')).toBe(true);
    expect(pdf.endsWith('%%EOF\n')).toBe(true);
    const startxref = Number(/startxref\n(\d+)\n%%EOF\n$/.exec(pdf)?.[1]);
    expect(pdf.slice(startxref, startxref + 4)).toBe('xref');
    const count = Number(/xref\n0 (\d+)\n/.exec(pdf)?.[1]);
    const offsets = [...pdf.slice(startxref).matchAll(/^(\d{10}) 00000 n $/gm)].map((m) => Number(m[1]));
    expect(offsets.length).toBe(count - 1);
    offsets.forEach((offset, i) => expect(pdf.slice(offset).startsWith(`${i + 1} 0 obj\n`)).toBe(true));
    for (const match of pdf.matchAll(/<< \/Length (\d+) >>\nstream\n/g)) {
      const start = (match.index ?? 0) + match[0].length;
      expect(pdf.slice(start + Number(match[1]), start + Number(match[1]) + 10)).toBe('\nendstream');
    }
    expect(/\/Count (\d+)/.exec(pdf)?.[1]).toBe('3');
  });

  it('carries the control ids and disclaimer as escaped ASCII text', () => {
    expect(pdf).toContain('(5.1.20 "Ensure sshd PermitRootLogin is disabled \\(Automated\\)" - \\(parens\\) \\\\ back) Tj');
    expect(pdf).toContain('(Evidence for an auditor, not certification.) Tj');
    expect(/[^\x0a\x20-\x7e]/.test(pdf)).toBe(false);
  });
});

/**
 * Re-checks every mapping against the pinned ComplianceAsCode files. Network
 * access is needed, so it runs only with CIS_VERIFY_ONLINE=1.
 */
describe.skipIf(!process.env.CIS_VERIFY_ONLINE)('CIS crosswalk against ComplianceAsCode (online)', () => {
  interface CacControl { id: string; title?: string; levels?: string[]; rules?: string[]; controls?: CacControl[] }
  const flatten = (controls: CacControl[] = []): CacControl[] => controls.flatMap((c) => [c, ...flatten(c.controls)]);

  for (const p of Object.values(CIS_PROFILES)) {
    it(`matches ${p.cacFile} at ${p.cacTag}`, async () => {
      const raw = await fetch(`https://raw.githubusercontent.com/ComplianceAsCode/content/${p.cacTag}/${p.cacFile}`).then((r) => r.text());
      const doc = parse(raw) as { version: string | number; controls: CacControl[] };
      expect(String(doc.version)).toBe(p.benchmarkVersion);
      const byId = new Map(flatten(doc.controls).map((c) => [String(c.id), c]));
      for (const entry of CIS_CROSSWALK) {
        for (const m of entry.mappings.filter((row) => row.profile === p.key)) {
          const control = byId.get(m.controlId);
          expect(control, `${entry.check}: ${m.controlId} missing`).toBeDefined();
          expect(control?.title).toBe(m.title);
          expect([...(control?.levels ?? [])].sort()).toEqual([...m.levels].sort());
          for (const rule of m.cacRules) expect(control?.rules ?? [], `${entry.check}: ${rule}`).toContain(rule);
        }
      }
    }, 30_000);
  }
});
