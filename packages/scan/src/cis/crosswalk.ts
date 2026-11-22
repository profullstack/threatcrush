/**
 * CIS Benchmark crosswalk for ThreatCrush host checks.
 *
 * Every control id, title and level below is copied from a ComplianceAsCode
 * (CaC) control file at a pinned release tag. Nothing here is guessed: a check
 * is mapped only when a CaC rule listed under the control tests the same
 * setting the ThreatCrush check reads. A check with no such rule carries an
 * explicit `unmapped` reason instead of an id.
 *
 * `coverage` says how far a ThreatCrush PASS goes:
 *   - `full`: the check reads the same setting and requires the same value as
 *     the CaC rule, so a PASS is evidence for that rule.
 *   - `partial`: the check reads the same setting but with a narrower scope or
 *     a looser threshold (stated in `note`). A PASS is NOT evidence the control
 *     passes; a FAIL is still a real finding against it.
 *
 * Re-verify with `CIS_VERIFY_ONLINE=1 pnpm --filter @threatcrush/scan exec vitest run cis-crosswalk`, which
 * fetches each pinned CaC file and checks every id, title, level and rule.
 *
 * This is evidence for an auditor, not a CIS assessment or certification.
 */

export const CAC_TAG = 'v0.1.82';
export const CAC_REPO = 'https://github.com/ComplianceAsCode/content';

export type CisProfileKey = 'ubuntu-24.04' | 'ubuntu-22.04' | 'debian-12' | 'debian-13';

export interface CisProfile {
  key: CisProfileKey;
  osId: 'ubuntu' | 'debian';
  osVersion: string;
  benchmarkName: string;
  /** The benchmark edition the pinned CaC control file implements. */
  benchmarkVersion: string;
  cacTag: typeof CAC_TAG;
  cacFile: string;
  /** Git blob SHA of `cacFile` at `cacTag`, so the exact source is auditable. */
  cacFileSha: string;
  source: string;
}

function profile(key: CisProfileKey, osId: 'ubuntu' | 'debian', osVersion: string, benchmarkName: string, benchmarkVersion: string, file: string, sha: string): CisProfile {
  const cacFile = `controls/${file}`;
  return { key, osId, osVersion, benchmarkName, benchmarkVersion, cacTag: CAC_TAG, cacFile, cacFileSha: sha, source: `${CAC_REPO}/blob/${CAC_TAG}/${cacFile}` };
}

export const CIS_PROFILES: Record<CisProfileKey, CisProfile> = {
  'ubuntu-24.04': profile('ubuntu-24.04', 'ubuntu', '24.04', 'CIS Ubuntu Linux 24.04 LTS', '1.0.0', 'cis_ubuntu2404.yml', 'd4e1dfde39c30eb90c57ccaef872a43042a4b097'),
  'ubuntu-22.04': profile('ubuntu-22.04', 'ubuntu', '22.04', 'CIS Ubuntu Linux 22.04 LTS', '2.0.0', 'cis_ubuntu2204.yml', '997016fd1e977cd500766b395a3fc7bea4dbcef8'),
  'debian-12': profile('debian-12', 'debian', '12', 'CIS Debian Linux 12', '1.1.0', 'cis_debian12.yml', '6ffb09b7dda324cb4813c3eb75ed9df9d58565bd'),
  'debian-13': profile('debian-13', 'debian', '13', 'CIS Debian Linux 13', '1.0.0', 'cis_debian13.yml', '2b522c716e1ea971c93b45a22a385abc9c7293e2'),
};

export type CisLevel = 'l1_server' | 'l2_server' | 'l1_workstation' | 'l2_workstation';

export interface CisControlMapping {
  profile: CisProfileKey;
  controlId: string;
  /** Control title exactly as written in the CaC file. */
  title: string;
  levels: CisLevel[];
  /** The CaC rule ids under this control that test what the check reads. */
  cacRules: string[];
  coverage: 'full' | 'partial';
  note?: string;
}

export interface CisCheckCrosswalk {
  check: string;
  /** `harden` = `threatcrush harden`; `config` = PRD 0005 code-scanner config checks. */
  scope: 'harden' | 'config';
  mappings: CisControlMapping[];
  /** Required when `mappings` is empty: why no pinned control matches. */
  unmapped?: string;
}

const L1: CisLevel[] = ['l1_server', 'l1_workstation'];

function each(rows: Array<[CisProfileKey, string, string]>, rest: Omit<CisControlMapping, 'profile' | 'controlId' | 'title' | 'levels'> & { levels?: CisLevel[] }): CisControlMapping[] {
  return rows.map(([p, controlId, title]) => ({ profile: p, controlId, title, levels: rest.levels ?? L1, cacRules: rest.cacRules, coverage: rest.coverage, ...(rest.note ? { note: rest.note } : {}) }));
}

const ROOT_LOGIN = 'Ensure sshd PermitRootLogin is disabled (Automated)';
const MAX_AUTH = 'Ensure sshd MaxAuthTries is configured (Automated)';
const WORLD_WRITABLE = 'Ensure world writable files and directories are secured (Automated)';
const TFTP = 'Ensure tftp server services are not in use (Automated)';

const WORLD_WRITABLE_ROWS: Array<[CisProfileKey, string, string]> = [
  ['ubuntu-24.04', '7.1.11', WORLD_WRITABLE],
  ['ubuntu-22.04', '7.1.11', WORLD_WRITABLE],
  ['debian-12', '7.1.11', WORLD_WRITABLE],
  ['debian-13', '7.1.11', WORLD_WRITABLE],
];

const NOT_AN_OS_CONTROL = 'Application, container or web-server setting. None of the pinned CIS Ubuntu/Debian OS benchmark profiles has a control or CaC rule for it.';

export const CIS_CROSSWALK: CisCheckCrosswalk[] = [
  {
    check: 'ssh-root-login',
    scope: 'harden',
    mappings: each([
      ['ubuntu-24.04', '5.1.20', ROOT_LOGIN],
      ['ubuntu-22.04', '5.1.20', ROOT_LOGIN],
      ['debian-12', '5.1.20', ROOT_LOGIN],
      ['debian-13', '5.1.21', ROOT_LOGIN],
    ], {
      cacRules: ['sshd_disable_root_login'],
      coverage: 'full',
      note: 'Reads the effective `sshd -T` value and passes only on exactly `PermitRootLogin no`.',
    }),
  },
  {
    check: 'ssh-password-auth',
    scope: 'harden',
    mappings: [],
    unmapped: 'No pinned profile has a PasswordAuthentication control. The nearest, "Ensure sshd PermitEmptyPasswords is disabled" (sshd_disable_empty_passwords), tests a different setting.',
  },
  {
    check: 'ssh-weak-config',
    scope: 'harden',
    mappings: each([
      ['ubuntu-24.04', '5.1.16', MAX_AUTH],
      ['ubuntu-22.04', '5.1.16', MAX_AUTH],
      ['debian-12', '5.1.16', MAX_AUTH],
      ['debian-13', '5.1.17', MAX_AUTH],
    ], {
      cacRules: ['sshd_set_max_auth_tries'],
      coverage: 'partial',
      note: 'Only the MaxAuthTries part maps. ThreatCrush flags MaxAuthTries > 6 in /etc/ssh/sshd_config; the control requires 4 or less (CaC sshd_max_auth_tries_value=4), so a PASS does not satisfy it. The X11Forwarding and Protocol parts have no matching rule (DisableForwarding is a different directive).',
    }),
  },
  {
    check: 'auto-updates',
    scope: 'harden',
    mappings: [],
    unmapped: '"Ensure updates, patches, and additional security software are installed" (1.2.2.1) is a Manual control with no CaC rule, and it concerns installed updates, not an automatic-update mechanism.',
  },
  {
    check: 'firewall-active',
    scope: 'harden',
    mappings: [
      ...each([
        ['ubuntu-24.04', '4.2.3', 'Ensure ufw service is enabled (Automated)'],
        ['ubuntu-22.04', '4.1.3', 'Ensure ufw service is enabled (Automated)'],
        ['debian-12', '4.2.3', 'Ensure ufw service is enabled (Automated)'],
        ['debian-13', '4.1.2', 'Ensure ufw service is configured (Automated)'],
      ], {
        cacRules: ['check_ufw_active'],
        coverage: 'partial',
        note: 'ThreatCrush passes when ufw is active, any nftables table exists, or iptables has rules. It does not check that the ufw service is enabled at boot (service_ufw_enabled).',
      }),
      ...each([
        ['ubuntu-24.04', '4.3.4', 'Ensure a nftables table exists (Automated)'],
        ['ubuntu-22.04', '4.2.4', 'Ensure a nftables table exists (Automated)'],
        ['debian-12', '4.3.4', 'Ensure a nftables table exists (Automated)'],
      ], {
        cacRules: ['set_nftables_table'],
        coverage: 'partial',
        note: 'ThreatCrush accepts any nftables table; the CaC rule expects an inet filter table. Not applicable when the host uses ufw.',
      }),
    ],
  },
  {
    check: 'exposed-ports',
    scope: 'harden',
    mappings: [],
    unmapped: 'No pinned control tests which address a service binds to. "Ensure ... firewall rules exist for all open ports" tests firewall rules, a different setting.',
  },
  {
    check: 'fail2ban-present',
    scope: 'harden',
    mappings: [],
    unmapped: 'No pinned profile has a fail2ban or login-throttling daemon control.',
  },
  {
    check: 'world-writable-dirs',
    scope: 'harden',
    mappings: each(WORLD_WRITABLE_ROWS, {
      cacRules: ['file_permissions_unauthorized_world_writable'],
      coverage: 'partial',
      note: 'ThreatCrush looks at directories only, two levels deep under /etc, /usr, /var/log and /boot; the control covers world-writable files on every local filesystem.',
    }),
  },
  {
    check: 'risky-services',
    scope: 'harden',
    mappings: each([
      ['ubuntu-24.04', '2.1.16', TFTP],
      ['ubuntu-22.04', '2.1.16', TFTP],
      ['debian-12', '2.1.16', TFTP],
      ['debian-13', '2.1.17', TFTP],
    ], {
      cacRules: ['service_tftp_disabled'],
      coverage: 'partial',
      note: 'Only the tftp part maps, and only to the service rule: ThreatCrush checks whether tftp.socket/tftp.service is active, not whether the package is removed (package_tftp-server_removed). The telnet, rsh, rlogin and rexec parts test running services, while the pinned controls for those test client or server package removal.',
    }),
  },

  // PRD 0005 code-scanner config checks (modules/code-scanner/src/config).
  {
    check: 'world-writable',
    scope: 'config',
    mappings: each(WORLD_WRITABLE_ROWS, {
      cacRules: ['file_permissions_unauthorized_world_writable'],
      coverage: 'partial',
      note: 'Only paths the config audit walks (web roots and deploy paths) are checked; the control covers every local filesystem.',
    }),
  },
  {
    check: 'credentials-world-readable',
    scope: 'config',
    mappings: [],
    unmapped: 'The pinned key-file controls ("Ensure permissions on SSH private host key files are configured") cover /etc/ssh host keys only; this check looks at .env, id_* and *.pem/*.key files in application paths.',
  },
  { check: 'sensitive-file-in-webroot', scope: 'config', mappings: [], unmapped: NOT_AN_OS_CONTROL },
  { check: 'debug-enabled', scope: 'config', mappings: [], unmapped: NOT_AN_OS_CONTROL },
  { check: 'container-privileged', scope: 'config', mappings: [], unmapped: NOT_AN_OS_CONTROL },
  { check: 'docker-socket-mounted', scope: 'config', mappings: [], unmapped: NOT_AN_OS_CONTROL },
  { check: 'container-host-network', scope: 'config', mappings: [], unmapped: NOT_AN_OS_CONTROL },
  { check: 'container-sys-admin', scope: 'config', mappings: [], unmapped: NOT_AN_OS_CONTROL },
  { check: 'directory-listing', scope: 'config', mappings: [], unmapped: NOT_AN_OS_CONTROL },
  { check: 'cors-wildcard-with-credentials', scope: 'config', mappings: [], unmapped: NOT_AN_OS_CONTROL },
];

/** The pinned CaC profile for an /etc/os-release ID + VERSION_ID, if any. */
export function cisProfileFor(osId: string | null | undefined, osVersion: string | null | undefined): CisProfile | null {
  if (!osId || !osVersion) return null;
  const id = osId.toLowerCase();
  return Object.values(CIS_PROFILES).find((p) => p.osId === id && p.osVersion === osVersion) ?? null;
}

export type CisMappingStatus = 'verified' | 'unmapped' | 'unverified';

export interface CisResolvedMapping {
  /** verified: ids from the pinned source; unmapped: no matching control in this profile; unverified: no pinned profile for this OS. */
  status: CisMappingStatus;
  profile: CisProfile | null;
  controls: CisControlMapping[];
  reason?: string;
}

/** Resolve a check key against the host's OS. Never returns ids that are not in the catalog. */
export function resolveCisMapping(check: string, scope: 'harden' | 'config', osId: string | null | undefined, osVersion: string | null | undefined): CisResolvedMapping {
  const p = cisProfileFor(osId, osVersion);
  const entry = CIS_CROSSWALK.find((row) => row.check === check && row.scope === scope);
  if (!p) {
    return { status: 'unverified', profile: null, controls: [], reason: `No pinned ComplianceAsCode CIS profile for ${osId ?? 'unknown OS'} ${osVersion ?? ''}`.trim() + '.' };
  }
  if (!entry) return { status: 'unmapped', profile: p, controls: [], reason: 'Check is not in the CIS crosswalk.' };
  const controls = entry.mappings.filter((m) => m.profile === p.key);
  if (controls.length === 0) {
    return { status: 'unmapped', profile: p, controls: [], reason: entry.unmapped ?? `No matching control in ${p.benchmarkName} v${p.benchmarkVersion}.` };
  }
  return { status: 'verified', profile: p, controls };
}

/** Short provenance string for one mapping row. */
export function cisProvenance(p: CisProfile, m: CisControlMapping): string {
  return `${p.benchmarkName} v${p.benchmarkVersion} ${m.controlId} via CaC ${p.cacTag} ${p.cacFile} rule ${m.cacRules.join(', ')}`;
}
