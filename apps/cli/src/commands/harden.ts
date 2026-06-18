import { existsSync, readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import chalk from 'chalk';
import ora from 'ora';
import { banner, logger } from '../core/logger.js';

interface HardeningResult {
  key: string;
  status: 'pass' | 'warn' | 'fail';
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  explanation: string;
  recommendation?: string;
}

function tryExec(cmd: string): string | null {
  try { return execSync(cmd, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }); }
  catch { return null; }
}

function tryRead(path: string): string | null {
  try { return readFileSync(path, 'utf-8'); }
  catch { return null; }
}

// ─── Individual Checks ───

function checkSshPasswordAuth(): HardeningResult {
  const config = tryRead('/etc/ssh/sshd_config');
  if (!config) {
    return {
      key: 'ssh-password-auth', status: 'warn', severity: 'medium',
      title: 'SSH Password Auth',
      explanation: 'Could not read /etc/ssh/sshd_config to check password authentication setting.',
      recommendation: 'Ensure PasswordAuthentication is set to no in sshd_config.',
    };
  }
  const match = config.match(/^\s*PasswordAuthentication\s+(yes|no)/mi);
  if (!match || match[1] === 'yes') {
    return {
      key: 'ssh-password-auth', status: 'fail', severity: 'high',
      title: 'SSH Password Authentication Enabled',
      explanation: 'Password authentication is enabled for SSH, making it vulnerable to brute-force attacks.',
      recommendation: 'Set "PasswordAuthentication no" in /etc/ssh/sshd_config and restart sshd. Use key-based auth instead.',
    };
  }
  return {
    key: 'ssh-password-auth', status: 'pass', severity: 'high',
    title: 'SSH Password Authentication Disabled',
    explanation: 'Password authentication is disabled for SSH. Key-based auth is enforced.',
  };
}

function checkSshRootLogin(): HardeningResult {
  const config = tryRead('/etc/ssh/sshd_config');
  if (!config) {
    return {
      key: 'ssh-root-login', status: 'warn', severity: 'high',
      title: 'SSH Root Login',
      explanation: 'Could not read sshd_config.',
      recommendation: 'Set "PermitRootLogin no" in /etc/ssh/sshd_config.',
    };
  }
  const match = config.match(/^\s*PermitRootLogin\s+(\S+)/mi);
  if (!match || match[1] === 'yes') {
    return {
      key: 'ssh-root-login', status: 'fail', severity: 'high',
      title: 'Root SSH Login Enabled',
      explanation: 'Direct root login via SSH is permitted. Attackers frequently target root.',
      recommendation: 'Set "PermitRootLogin no" or "PermitRootLogin prohibit-password" in /etc/ssh/sshd_config.',
    };
  }
  return {
    key: 'ssh-root-login', status: 'pass', severity: 'high',
    title: 'Root SSH Login Restricted',
    explanation: `PermitRootLogin is set to "${match[1]}".`,
  };
}

function checkSshWeakConfig(): HardeningResult {
  const config = tryRead('/etc/ssh/sshd_config');
  if (!config) {
    return {
      key: 'ssh-weak-config', status: 'warn', severity: 'medium',
      title: 'SSH Configuration', explanation: 'Could not read sshd_config.',
    };
  }
  const issues: string[] = [];
  if (!/^\s*Protocol\s+2/mi.test(config) && !/^\s*#\s*Protocol/mi.test(config)) {
    // Modern OpenSSH defaults to protocol 2, so only flag if explicitly set to 1
    if (/^\s*Protocol\s+1/mi.test(config)) issues.push('Protocol 1 is enabled');
  }
  if (/^\s*X11Forwarding\s+yes/mi.test(config)) issues.push('X11 forwarding is enabled');
  const maxAuth = config.match(/^\s*MaxAuthTries\s+(\d+)/mi);
  if (maxAuth && parseInt(maxAuth[1]) > 6) issues.push(`MaxAuthTries is high (${maxAuth[1]})`);

  if (issues.length > 0) {
    return {
      key: 'ssh-weak-config', status: 'warn', severity: 'medium',
      title: 'SSH Configuration Weaknesses',
      explanation: `Found: ${issues.join('; ')}.`,
      recommendation: 'Review and harden sshd_config. Disable unused features.',
    };
  }
  return {
    key: 'ssh-weak-config', status: 'pass', severity: 'medium',
    title: 'SSH Configuration', explanation: 'No obvious SSH config weaknesses found.',
  };
}

function checkAutoUpdates(): HardeningResult {
  // Check for unattended-upgrades (Debian/Ubuntu)
  const unattended = existsSync('/etc/apt/apt.conf.d/20auto-upgrades') ||
    existsSync('/etc/apt/apt.conf.d/50unattended-upgrades');
  // Check for dnf-automatic (RHEL/Fedora)
  const dnfAuto = existsSync('/etc/dnf/automatic.conf');

  if (unattended || dnfAuto) {
    return {
      key: 'auto-updates', status: 'pass', severity: 'high',
      title: 'Automatic Security Updates',
      explanation: 'Automatic security updates appear to be configured.',
    };
  }
  return {
    key: 'auto-updates', status: 'fail', severity: 'high',
    title: 'No Automatic Security Updates',
    explanation: 'No automatic security update mechanism detected.',
    recommendation: 'Install and enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic (RHEL/Fedora).',
  };
}

function checkFirewallActive(): HardeningResult {
  const ufw = tryExec('ufw status');
  if (ufw && ufw.includes('active')) {
    return {
      key: 'firewall-active', status: 'pass', severity: 'high',
      title: 'Firewall Active (UFW)',
      explanation: 'UFW firewall is active.',
    };
  }

  const nft = tryExec('nft list tables');
  if (nft && nft.trim().length > 0) {
    return {
      key: 'firewall-active', status: 'pass', severity: 'high',
      title: 'Firewall Active (nftables)',
      explanation: 'nftables has active tables.',
    };
  }

  const ipt = tryExec('iptables -L -n');
  if (ipt) {
    const rules = ipt.split('\n').filter(l => l.trim() && !l.startsWith('Chain') && !l.startsWith('target'));
    if (rules.length > 0) {
      return {
        key: 'firewall-active', status: 'pass', severity: 'high',
        title: 'Firewall Active (iptables)',
        explanation: `iptables has ${rules.length} rules.`,
      };
    }
  }

  return {
    key: 'firewall-active', status: 'fail', severity: 'high',
    title: 'No Firewall Detected',
    explanation: 'No active firewall (UFW, nftables, or iptables) detected.',
    recommendation: 'Enable a firewall: `ufw enable` or configure nftables/iptables.',
  };
}

function checkExposedPorts(): HardeningResult {
  const ss = tryExec('ss -tlnp');
  if (!ss) {
    return {
      key: 'exposed-ports', status: 'warn', severity: 'medium',
      title: 'Exposed Ports', explanation: 'Could not check listening ports.',
    };
  }

  const riskyPorts = ['3306', '5432', '6379', '27017', '9200', '11211', '2375'];
  const exposed: string[] = [];
  for (const line of ss.split('\n')) {
    if (!line.includes('LISTEN')) continue;
    // Check if listening on 0.0.0.0 or :: (all interfaces)
    if (line.includes('0.0.0.0:') || line.includes(':::')) {
      for (const port of riskyPorts) {
        if (line.includes(`:${port} `) || line.includes(`:${port}\t`)) {
          exposed.push(port);
        }
      }
    }
  }

  if (exposed.length > 0) {
    const portNames: Record<string, string> = {
      '3306': 'MySQL', '5432': 'PostgreSQL', '6379': 'Redis',
      '27017': 'MongoDB', '9200': 'Elasticsearch', '11211': 'Memcached', '2375': 'Docker',
    };
    const desc = exposed.map(p => `${portNames[p] || p} (:${p})`).join(', ');
    return {
      key: 'exposed-ports', status: 'fail', severity: 'high',
      title: 'Risky Ports Exposed',
      explanation: `Services exposed on all interfaces: ${desc}.`,
      recommendation: 'Bind database/cache services to 127.0.0.1 only, or restrict with firewall rules.',
    };
  }
  return {
    key: 'exposed-ports', status: 'pass', severity: 'high',
    title: 'No Risky Ports Exposed',
    explanation: 'No common database/cache ports are listening on all interfaces.',
  };
}

function checkFail2ban(): HardeningResult {
  const checkKey = 'fail2ban-present'; // gitleaks:allow
  const sev = 'medium' as const;
  const f2bStatus = tryExec('fail2ban-client status');
  if (f2bStatus && f2bStatus.includes('Number of jail')) {
    return {
      key: checkKey, status: 'pass', severity: sev,
      title: 'fail2ban Active',
      explanation: 'fail2ban is installed and running.',
    };
  }
  if (existsSync('/etc/fail2ban/fail2ban.conf')) {
    return {
      key: checkKey, status: 'warn', severity: sev,
      title: 'fail2ban Installed but Not Running',
      explanation: 'fail2ban is installed but does not appear to be running.',
      recommendation: 'Start and enable fail2ban: `systemctl enable --now fail2ban`.',
    };
  }
  return {
    key: checkKey, status: 'warn', severity: sev,
    title: 'fail2ban Not Installed',
    explanation: 'fail2ban is not installed. ThreatCrush provides similar protection, but fail2ban adds defense in depth.',
    recommendation: 'Consider installing fail2ban: `apt install fail2ban` or `dnf install fail2ban`.',
  };
}

function checkWorldWritableDirs(): HardeningResult {
  const sensitive = ['/etc', '/usr', '/var/log', '/boot'];
  const worldWritable: string[] = [];

  for (const dir of sensitive) {
    const result = tryExec(`find ${dir} -maxdepth 2 -type d -perm -0002 -not -path '*/tmp*' 2>/dev/null | head -5`);
    if (result && result.trim()) {
      worldWritable.push(...result.trim().split('\n'));
    }
  }

  if (worldWritable.length > 0) {
    return {
      key: 'world-writable-dirs', status: 'fail', severity: 'medium',
      title: 'World-Writable Directories Found',
      explanation: `Found ${worldWritable.length} world-writable directories in sensitive locations: ${worldWritable.slice(0, 3).join(', ')}${worldWritable.length > 3 ? '...' : ''}`,
      recommendation: 'Remove world-writable permission: `chmod o-w <dir>`.',
    };
  }
  return {
    key: 'world-writable-dirs', status: 'pass', severity: 'medium',
    title: 'No World-Writable Directories',
    explanation: 'No world-writable directories found in sensitive locations.',
  };
}

function checkRiskyServices(): HardeningResult {
  const risky = ['telnet', 'rsh', 'rlogin', 'rexec', 'tftp'];
  const found: string[] = [];

  for (const svc of risky) {
    const result = tryExec(`systemctl is-active ${svc}.socket ${svc}.service 2>/dev/null`);
    if (result && result.trim() === 'active') {
      found.push(svc);
    }
  }

  if (found.length > 0) {
    return {
      key: 'risky-services', status: 'fail', severity: 'critical',
      title: 'Risky Services Running',
      explanation: `Insecure services are active: ${found.join(', ')}.`,
      recommendation: `Disable and remove insecure services: \`systemctl disable --now ${found.join(' ')}\`.`,
    };
  }
  return {
    key: 'risky-services', status: 'pass', severity: 'critical',
    title: 'No Risky Services',
    explanation: 'No known insecure services (telnet, rsh, etc.) are running.',
  };
}

// ─── Main ───

function runAllChecks(): HardeningResult[] {
  return [
    checkSshPasswordAuth(),
    checkSshRootLogin(),
    checkSshWeakConfig(),
    checkAutoUpdates(),
    checkFirewallActive(),
    checkExposedPorts(),
    checkFail2ban(),
    checkWorldWritableDirs(),
    checkRiskyServices(),
  ];
}

function computeScore(results: HardeningResult[]): number {
  if (results.length === 0) return 100;
  const weights: Record<string, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  let maxScore = 0;
  let deductions = 0;
  for (const r of results) {
    const w = weights[r.severity] || 1;
    maxScore += w;
    if (r.status === 'fail') deductions += w;
    else if (r.status === 'warn') deductions += w * 0.5;
  }
  if (maxScore === 0) return 100;
  return Math.max(0, Math.round(((maxScore - deductions) / maxScore) * 100));
}

export async function hardenCommand(opts: { json?: boolean }): Promise<void> {
  if (!opts.json) {
    banner();
    logger.info('Running hardening scan...\n');
  }

  const spinner = opts.json ? null : ora({ text: 'Scanning system configuration...', color: 'green' }).start();

  const results = runAllChecks();
  const score = computeScore(results);

  if (spinner) spinner.succeed('Hardening scan complete\n');

  if (opts.json) {
    console.log(JSON.stringify({ score, findings: results }, null, 2));
    return;
  }

  // Score display
  const scoreColor = score >= 80 ? chalk.green : score >= 60 ? chalk.yellow : chalk.red;
  console.log(`  ${chalk.white.bold('Hardening Score:')} ${scoreColor.bold(String(score) + '/100')}`);
  console.log(chalk.gray('  ' + '─'.repeat(60)));
  console.log();

  // Group by status
  const fails = results.filter(r => r.status === 'fail');
  const warns = results.filter(r => r.status === 'warn');
  const passes = results.filter(r => r.status === 'pass');

  if (fails.length > 0) {
    console.log(chalk.red.bold('  FAIL'));
    for (const r of fails) {
      console.log(`  ${chalk.red('✗')} ${chalk.white.bold(r.title)}`);
      console.log(`    ${chalk.gray(r.explanation)}`);
      if (r.recommendation) console.log(`    ${chalk.yellow('Fix:')} ${r.recommendation}`);
      console.log();
    }
  }

  if (warns.length > 0) {
    console.log(chalk.yellow.bold('  WARNING'));
    for (const r of warns) {
      console.log(`  ${chalk.yellow('!')} ${chalk.white.bold(r.title)}`);
      console.log(`    ${chalk.gray(r.explanation)}`);
      if (r.recommendation) console.log(`    ${chalk.yellow('Fix:')} ${r.recommendation}`);
      console.log();
    }
  }

  if (passes.length > 0) {
    console.log(chalk.green.bold('  PASS'));
    for (const r of passes) {
      console.log(`  ${chalk.green('✓')} ${chalk.white(r.title)}`);
    }
    console.log();
  }

  console.log(chalk.gray('  ' + '─'.repeat(60)));
  console.log(`  ${chalk.white.bold(`${results.length} checks:`)} ${chalk.green(`${passes.length} pass`)} ${chalk.yellow(`${warns.length} warn`)} ${chalk.red(`${fails.length} fail`)}`);
  console.log();
}

// Export for daemon use
export { runAllChecks, computeScore };
export type { HardeningResult };
