/**
 * Misconfiguration checks — the `config` subsystem of `code-scanner`.
 *
 * Implements PRD 0005. Two ideas shape this file:
 *
 *  1. **Rank by reachability, not by benchmark severity.** An exposed `.env` in
 *     a served directory is a tonight problem; the same file outside any web
 *     root is a tidiness issue. A tool that scores both identically forces the
 *     operator to do the triage the tool should have done.
 *
 *  2. **Every finding carries a fix, and the fix includes the follow-through.**
 *     Moving an exposed `.env` is not remediation — the credentials in it must
 *     be rotated, because it should be assumed read. Operators routinely do the
 *     first half and stop, so the text says both.
 *
 * The standing risk, named in the PRD, is drift toward a 200-item compliance
 * checklist that nobody reads. Every check here should be traceable to a way
 * servers actually get breached.
 */

export type Reachability = 'exposed' | 'local' | 'hardening';
export type ConfigSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface ConfigFinding {
  checkId: string;
  title: string;
  /** Where the problem is: a path, or a setting. */
  subject: string;
  reachability: Reachability;
  severity: ConfigSeverity;
  /** What an attacker gets. */
  consequence: string;
  /** What to do, including anything that must follow. */
  remediation: string;
}

/** Files that must never sit inside a directory a webserver serves. */
export const SENSITIVE_IN_WEBROOT: readonly { pattern: RegExp; what: string }[] = [
  { pattern: /^\.env(\..+)?$/i, what: 'environment file' },
  { pattern: /^\.git$/i, what: 'git directory' },
  { pattern: /^\.htpasswd$/i, what: 'htpasswd file' },
  { pattern: /^id_(?:rsa|dsa|ecdsa|ed25519)$/i, what: 'private key' },
  { pattern: /\.(?:sql|dump)$/i, what: 'database dump' },
  { pattern: /\.(?:bak|old|orig|save|swp)$/i, what: 'backup file' },
  { pattern: /^docker-compose\.ya?ml$/i, what: 'compose file' },
  { pattern: /^\.npmrc$/i, what: 'npm credentials file' },
  { pattern: /^\.aws$/i, what: 'AWS credentials directory' },
];

/**
 * Is this filename dangerous to serve?
 *
 * Returns what it is, so the finding can say "environment file" rather than
 * quoting a rule id at the operator.
 */
export function sensitiveInWebroot(name: string): string | null {
  for (const entry of SENSITIVE_IN_WEBROOT) {
    if (entry.pattern.test(name)) return entry.what;
  }
  return null;
}

/**
 * Web roots declared by an nginx or Apache configuration.
 *
 * A targeted directive scrape rather than a config parser: the full grammars
 * are large, and PRD 0005 explicitly scopes a parser out. When this finds
 * nothing the caller must report `unknown` rather than assuming nothing is
 * served — an unknown root that reads as "nothing exposed" is the failure this
 * subsystem is supposed to prevent.
 */
export function parseWebRoots(configText: string): string[] {
  const roots = new Set<string>();

  // nginx: `root /var/www/html;` — skip commented lines.
  for (const line of configText.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('#')) continue;

    const nginx = /^root\s+([^;]+);/.exec(trimmed);
    if (nginx?.[1]) roots.add(nginx[1].trim().replace(/^["']|["']$/g, ''));

    const apache = /^DocumentRoot\s+(.+)$/i.exec(trimmed);
    if (apache?.[1]) roots.add(apache[1].trim().replace(/^["']|["']$/g, ''));
  }

  return [...roots];
}

/** Conventional locations, used only when config parsing yields nothing. */
export const CONVENTIONAL_WEB_ROOTS = [
  '/var/www/html',
  '/var/www',
  '/usr/share/nginx/html',
  '/srv/www',
  '/srv/http',
];

export interface ModeCheck {
  path: string;
  /** Unix mode bits, e.g. 0o777. */
  mode: number;
  isDirectory: boolean;
}

/**
 * Permission problems that matter.
 *
 * Restricted to cases with a real consequence: anyone on the box can rewrite
 * the code that runs, or read the credentials it runs with. General
 * "permissions are broader than ideal" reporting is how this subsystem becomes
 * a checklist.
 */
export function checkMode(entry: ModeCheck): ConfigFinding | null {
  const worldWritable = (entry.mode & 0o002) !== 0;
  const worldReadable = (entry.mode & 0o004) !== 0;
  const name = entry.path.split('/').pop() ?? entry.path;

  if (worldWritable) {
    return {
      checkId: 'world-writable',
      title: `world-writable ${entry.isDirectory ? 'directory' : 'file'}`,
      subject: entry.path,
      reachability: 'local',
      severity: entry.isDirectory ? 'high' : 'medium',
      consequence: entry.isDirectory
        ? 'Any local user can add or replace files here, including code that will be executed.'
        : 'Any local user can rewrite this file.',
      remediation: `chmod o-w ${entry.path}`,
    };
  }

  if (worldReadable && /^\.env|^id_(?:rsa|dsa|ecdsa|ed25519)$|\.pem$|\.key$/i.test(name)) {
    return {
      checkId: 'credentials-world-readable',
      title: 'credential file readable by every local user',
      subject: entry.path,
      reachability: 'local',
      severity: 'high',
      consequence: 'Any account on this host can read these credentials.',
      remediation: `chmod 600 ${entry.path} — then rotate the credentials, since anyone with shell access could already have read them.`,
    };
  }

  return null;
}

/** Production-marker detection for debug settings. */
const DEBUG_PATTERNS: readonly { pattern: RegExp; setting: string }[] = [
  { pattern: /^\s*APP_DEBUG\s*=\s*(?:true|1)\s*$/im, setting: 'APP_DEBUG' },
  { pattern: /^\s*DEBUG\s*=\s*(?:true|1|True)\s*$/im, setting: 'DEBUG' },
  { pattern: /^\s*DEBUG\s*=\s*True\s*$/m, setting: 'Django DEBUG' },
  { pattern: /consider_all_requests_local\s*=\s*true/i, setting: 'Rails consider_all_requests_local' },
  { pattern: /^\s*NODE_ENV\s*=\s*(?:development|dev)\s*$/im, setting: 'NODE_ENV' },
];

export function checkDebugSettings(path: string, text: string): ConfigFinding[] {
  const findings: ConfigFinding[] = [];

  for (const { pattern, setting } of DEBUG_PATTERNS) {
    if (!pattern.test(text)) continue;
    findings.push({
      checkId: 'debug-enabled',
      title: `${setting} enabled`,
      subject: path,
      reachability: 'exposed',
      severity: 'high',
      consequence:
        'Error pages disclose stack traces, file paths, environment variables and sometimes credentials to anyone who can trigger an error.',
      remediation: `Set ${setting} to its production value and restart the service.`,
    });
  }

  return findings;
}

/**
 * Container settings that hand over the host.
 *
 * Reading compose files from disk only. Querying the Docker daemon is a
 * privilege boundary of its own and is deliberately not done here.
 */
export function checkComposeFile(path: string, text: string): ConfigFinding[] {
  const findings: ConfigFinding[] = [];
  const lines = text.split('\n').filter((line) => !line.trim().startsWith('#'));
  const body = lines.join('\n');

  if (/privileged\s*:\s*true/i.test(body)) {
    findings.push({
      checkId: 'container-privileged',
      title: 'container runs privileged',
      subject: path,
      reachability: 'local',
      severity: 'critical',
      consequence:
        'A privileged container can access host devices and escape to the host trivially; the container boundary is decorative.',
      remediation:
        'Remove `privileged: true` and grant only the specific capabilities the workload needs.',
    });
  }

  if (/\/var\/run\/docker\.sock/.test(body)) {
    findings.push({
      checkId: 'docker-socket-mounted',
      title: 'Docker socket mounted into a container',
      subject: path,
      reachability: 'local',
      severity: 'critical',
      consequence:
        'Access to the socket is equivalent to root on the host — a process in the container can start a new privileged container mounting the host filesystem.',
      remediation:
        'Remove the socket mount. If the container genuinely needs to orchestrate, use a scoped proxy rather than the raw socket.',
    });
  }

  if (/network_mode\s*:\s*["']?host/i.test(body)) {
    findings.push({
      checkId: 'container-host-network',
      title: 'container shares the host network namespace',
      subject: path,
      reachability: 'local',
      severity: 'high',
      consequence:
        'The container can reach every service bound to loopback on the host, including databases that believe they are unreachable.',
      remediation: 'Use a bridge network and publish only the ports the service needs.',
    });
  }

  if (/cap_add\s*:[\s\S]{0,80}SYS_ADMIN/i.test(body)) {
    findings.push({
      checkId: 'container-sys-admin',
      title: 'container granted CAP_SYS_ADMIN',
      subject: path,
      reachability: 'local',
      severity: 'high',
      consequence: 'CAP_SYS_ADMIN is broad enough to be a well-known route to container escape.',
      remediation: 'Drop SYS_ADMIN and add only the narrower capability actually required.',
    });
  }

  return findings;
}

/** Webserver directives that expose more than intended. */
export function checkWebserverConfig(path: string, text: string): ConfigFinding[] {
  const findings: ConfigFinding[] = [];
  const body = text
    .split('\n')
    .filter((line) => !line.trim().startsWith('#'))
    .join('\n');

  if (/autoindex\s+on|Options\s+[^\n]*\+Indexes/i.test(body)) {
    findings.push({
      checkId: 'directory-listing',
      title: 'directory listing enabled',
      subject: path,
      reachability: 'exposed',
      severity: 'medium',
      consequence:
        'Visitors can enumerate every file in the directory, including ones that were never meant to be discoverable.',
      remediation: 'Set `autoindex off` (nginx) or `Options -Indexes` (Apache).',
    });
  }

  // Individually defensible, together a vulnerability: a wildcard origin with
  // credentials allows any site to make authenticated requests as the user.
  const wildcardOrigin = /Access-Control-Allow-Origin[^\n]*\*/i.test(body);
  const allowCredentials = /Access-Control-Allow-Credentials[^\n]*true/i.test(body);
  if (wildcardOrigin && allowCredentials) {
    findings.push({
      checkId: 'cors-wildcard-with-credentials',
      title: 'CORS allows any origin with credentials',
      subject: path,
      reachability: 'exposed',
      severity: 'high',
      consequence:
        'Any website can make authenticated requests to this application using a visitor’s session.',
      remediation:
        'Replace the wildcard with an explicit origin allowlist, or stop sending credentials cross-origin.',
    });
  }

  return findings;
}

export const REACHABILITY_RANK: Record<Reachability, number> = {
  hardening: 0,
  local: 1,
  exposed: 2,
};

export const CONFIG_SEVERITY_RANK: Record<ConfigSeverity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/** Exposure first, then severity — reachability is what sets the deadline. */
export function rankFindings(findings: readonly ConfigFinding[]): ConfigFinding[] {
  return [...findings].sort(
    (a, b) =>
      REACHABILITY_RANK[b.reachability] - REACHABILITY_RANK[a.reachability] ||
      CONFIG_SEVERITY_RANK[b.severity] - CONFIG_SEVERITY_RANK[a.severity],
  );
}
