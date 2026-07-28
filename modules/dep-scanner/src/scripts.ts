/**
 * Install-script inventory and heuristics (PRD 0002 R11, R12).
 *
 * This is the detector that does not need a CVE to exist. `ua-parser-js`,
 * `event-stream` and `node-ipc` were all clean by advisory standards at the
 * moment they were installed, because the advisory is written *after* someone
 * notices. What they had in common is the execution vector: a lifecycle script
 * running with the installing user's privileges, with network access.
 *
 * Two design rules, both learned from how scanners lose their audience:
 *
 *  - **Inventory first, judgement second.** Most operators have never seen the
 *    list of install scripts that run on their own server. The list alone has
 *    value even when nothing scores.
 *  - **Score, and explain in behavioural terms.** A rule fires with a reason a
 *    human can check ("pipes a download into a shell"), never a verdict about
 *    the maintainer. These heuristics will hit legitimate packages —
 *    `node-gyp` builds, prebuilt-binary downloaders and CLI installers all look
 *    structurally similar to malware — so the wording must survive being wrong.
 *
 * Pure functions over strings: no filesystem, no network, so the rules are
 * testable against the real historical payloads.
 */

export type ScriptStage = 'preinstall' | 'install' | 'postinstall' | 'prepare';

export const INSTALL_STAGES: readonly ScriptStage[] = [
  'preinstall',
  'install',
  'postinstall',
  'prepare',
];

export interface InstallScript {
  packageName: string;
  version: string;
  stage: ScriptStage;
  command: string;
}

export interface ScriptSignal {
  rule: string;
  /** Contribution to the score. Nothing here is conclusive alone. */
  weight: number;
  message: string;
}

export interface ScriptVerdict {
  script: InstallScript;
  signals: ScriptSignal[];
  score: number;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Behavioural rules, ordered roughly by how damning they are.
 *
 * Weights are deliberately coarse. Precision here is false comfort: the point
 * is to rank a handful of scripts for a human to read, not to compute a
 * probability of malice.
 */
const RULES: readonly {
  rule: string;
  weight: number;
  message: string;
  test: RegExp;
}[] = [
  {
    // Weighted to reach `critical` on its own (with the remote-fetch it
    // implies). There is no benign reason for an install script to execute
    // whatever a remote host happens to be serving at install time.
    rule: 'curl-pipe-shell',
    weight: 7,
    message: 'pipes a network download directly into a shell',
    test: /(?:curl|wget)[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|k|d)?sh\b/i,
  },
  {
    rule: 'encoded-payload',
    weight: 5,
    message: 'decodes an encoded blob at install time (base64/hex)',
    test: /(?:base64\s+(?:-d|--decode)|from\s*\(\s*['"]base64|Buffer\.from\([^)]*['"]base64['"]|atob\s*\()/i,
  },
  {
    rule: 'credential-path',
    weight: 5,
    message: 'reads a credential or key path during install',
    test: /(?:\.npmrc|\.aws\/|\.ssh\/|id_rsa|\.docker\/config|\.kube\/config|\.git-credentials|\.env\b)/i,
  },
  {
    // Matched in both directions. The environment can be read before the
    // network call that ships it (`const e = process.env; fetch(...)`) or
    // inside it (`fetch(url, {body: process.env})`), and an exfiltration rule
    // that only understands one ordering is trivially evaded by the other.
    rule: 'env-exfiltration',
    weight: 4,
    message: 'reads the process environment and sends it somewhere',
    test: new RegExp(
      [
        '(?:process\\.env|printenv|\\benv\\b)[\\s\\S]{0,120}(?:curl|wget|fetch\\s*\\(|https?\\.request|net\\.connect)',
        '(?:curl|wget|fetch\\s*\\(|https?\\.request|net\\.connect)[\\s\\S]{0,120}(?:process\\.env|printenv)',
      ].join('|'),
      'i',
    ),
  },
  {
    rule: 'remote-fetch',
    weight: 3,
    message: 'fetches a remote resource at install time',
    test: /(?:\bcurl\b|\bwget\b|https?:\/\/|fetch\s*\(|https?\.get\s*\()/i,
  },
  {
    rule: 'inline-interpreter',
    weight: 3,
    message: 'executes an inline one-liner through an interpreter',
    test: /\b(?:node|python3?|perl|ruby)\s+-(?:e|c|epc)\b/i,
  },
  {
    rule: 'shell-spawn',
    weight: 3,
    message: 'spawns a shell from inside the install script',
    test: /(?:child_process|execSync|spawnSync|exec\s*\(|\bsystem\s*\()/i,
  },
  {
    rule: 'writes-outside-package',
    weight: 3,
    message: 'writes outside its own package directory',
    test: /(?:>\s*\/(?:etc|usr|bin|opt|root|var)\/|cp\s+[^\s]+\s+\/(?:etc|usr|bin|opt)\/|\/etc\/cron|systemctl\s+enable)/i,
  },
  {
    rule: 'obfuscation',
    weight: 4,
    message: 'contains obfuscated or dynamically-built code',
    test: /(?:eval\s*\(|new\s+Function\s*\(|\\x[0-9a-f]{2}\\x[0-9a-f]{2}|String\.fromCharCode\s*\()/i,
  },
  {
    rule: 'hidden-output',
    weight: 2,
    message: 'suppresses its own output',
    test: />\s*\/dev\/null\s*2>&1|2>&1\s*>\s*\/dev\/null|\s--silent\b.*\s(?:curl|wget)/i,
  },
  {
    rule: 'geolocation-probe',
    weight: 4,
    message: 'probes host location or identity at install time',
    test: /(?:ipinfo\.io|ip-api\.com|geoip|freegeoip|ifconfig\.me|checkip\.|whatismyip)/i,
  },
];

/**
 * Well-known native-build tooling.
 *
 * These legitimately compile and download at install time and would otherwise
 * dominate every report. They are *discounted, never excluded* — a compromised
 * `node-gyp` invocation is exactly what an attacker would want to hide behind,
 * so the signals stay attached and only the score is reduced.
 */
const BUILD_TOOLS = /^(?:node-gyp(?:-build)?|prebuild-install|node-pre-gyp|neon|cargo-cp-artifact)\b/;

export function scoreScript(script: InstallScript): ScriptVerdict {
  const command = script.command;
  const signals: ScriptSignal[] = [];

  for (const rule of RULES) {
    if (rule.test.test(command)) {
      signals.push({ rule: rule.rule, weight: rule.weight, message: rule.message });
    }
  }

  let score = signals.reduce((sum, signal) => sum + signal.weight, 0);

  if (BUILD_TOOLS.test(command.trim()) && score > 0) {
    score = Math.max(0, score - 4);
    signals.push({
      rule: 'known-build-tool',
      weight: -4,
      message: 'recognized native-build tooling — score reduced, not cleared',
    });
  }

  return { script, signals, score, severity: severityFor(score) };
}

function severityFor(score: number): ScriptVerdict['severity'] {
  if (score >= 10) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score >= 1) return 'low';
  return 'info';
}

/** Extract lifecycle scripts from a parsed `package.json`. */
export function extractScripts(
  pkg: { name?: string; version?: string; scripts?: Record<string, string> },
  fallbackName = '<unknown>',
): InstallScript[] {
  const scripts = pkg.scripts;
  if (!scripts) return [];

  const found: InstallScript[] = [];
  for (const stage of INSTALL_STAGES) {
    const command = scripts[stage];
    if (typeof command === 'string' && command.trim().length > 0) {
      found.push({
        packageName: pkg.name ?? fallbackName,
        version: pkg.version ?? '0.0.0',
        stage,
        command: command.trim(),
      });
    }
  }
  return found;
}

/** Everything that scored, worst first. */
export function rankScripts(scripts: readonly InstallScript[]): ScriptVerdict[] {
  return scripts
    .map(scoreScript)
    .filter((verdict) => verdict.score > 0)
    .sort((a, b) => b.score - a.score);
}
