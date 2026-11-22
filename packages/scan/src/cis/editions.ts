/**
 * Current CIS Benchmark editions per OS release, from the official CIS
 * product pages (checked on CIS_CATALOG_CHECKED_AT). These can be newer than
 * the edition a pinned ComplianceAsCode profile implements; reports name both
 * and never claim a crosswalk applies to an edition it was not taken from.
 */
export const CIS_CATALOG_CHECKED_AT = '2026-11-01';

const CIS_UBUNTU_URL = 'https://www.cisecurity.org/benchmark/ubuntu_linux';
const CIS_DEBIAN_URL = 'https://www.cisecurity.org/benchmark/debian_linux';

export interface CisEdition { name: string; version: string; source: string }

export const CIS_CURRENT_EDITIONS: Record<string, Record<string, CisEdition>> = {
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

export function currentCisEdition(osId: string | null | undefined, osVersion: string | null | undefined): CisEdition | null {
  if (!osId || !osVersion) return null;
  return CIS_CURRENT_EDITIONS[osId.toLowerCase()]?.[osVersion] ?? null;
}
