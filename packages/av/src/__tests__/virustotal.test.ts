import { describe, expect, it } from 'vitest';
import { queryVirusTotal, mergeReputation } from '../reputation';

const HASH = 'a'.repeat(64);

function fakeFetch(status: number, body: unknown): typeof fetch {
  return (async () => ({ status, json: async () => body })) as unknown as typeof fetch;
}

describe('queryVirusTotal', () => {
  it('returns null without a key or an invalid hash', async () => {
    expect(await queryVirusTotal(HASH, '', fakeFetch(200, {}))).toBeNull();
    expect(await queryVirusTotal('nope', 'KEY', fakeFetch(200, {}))).toBeNull();
  });

  it('returns null for an unknown hash (404)', async () => {
    expect(await queryVirusTotal(HASH, 'KEY', fakeFetch(404, {}))).toBeNull();
  });

  it('flags malicious when engines detect it, with the threat label', async () => {
    const rep = await queryVirusTotal(HASH, 'KEY', fakeFetch(200, {
      data: { attributes: {
        last_analysis_stats: { malicious: 42, suspicious: 3 },
        popular_threat_classification: { suggested_threat_label: 'trojan.generic/x' },
        meaningful_name: 'evil.exe',
      } },
    }));
    expect(rep?.knownMalicious).toContain('VirusTotal');
    expect(rep?.malwareName).toBe('trojan.generic/x');
    expect(rep?.fileName).toBe('evil.exe');
    expect(rep?.trust).toBe(0);
  });

  it('known-but-clean contributes a filename and no trust claim', async () => {
    const rep = await queryVirusTotal(HASH, 'KEY', fakeFetch(200, {
      data: { attributes: { last_analysis_stats: { malicious: 0 }, meaningful_name: 'setup.exe' } },
    }));
    expect(rep?.knownMalicious).toBeNull();
    expect(rep?.trust).toBeNull();
    expect(rep?.fileName).toBe('setup.exe');
  });

  it('a VT malicious verdict wins in mergeReputation', () => {
    const vt = { sha256: HASH, knownMalicious: 'VirusTotal (42 engines)', malwareName: 'trojan', trust: 0, fileName: 'evil.exe' };
    const circlClean = { sha256: HASH, knownMalicious: null, malwareName: null, trust: 95, fileName: 'a' };
    expect(mergeReputation(HASH, [circlClean, vt])?.knownMalicious).toContain('VirusTotal');
  });
});
