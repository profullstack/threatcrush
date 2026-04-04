import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import chalk from 'chalk';
import ora from 'ora';
import { generateDefaultConfig, generateModuleConfig } from '../core/config.js';
import { banner, logger } from '../core/logger.js';

interface DetectedService {
  name: string;
  binary: string;
  running: boolean;
  logPath?: string;
}

const SERVICES_TO_DETECT: Array<{
  name: string;
  binaries: string[];
  logPaths: string[];
  moduleConfig: Record<string, unknown>;
}> = [
  {
    name: 'sshd',
    binaries: ['sshd'],
    logPaths: ['/var/log/auth.log', '/var/log/secure'],
    moduleConfig: { log_path: '/var/log/auth.log', max_failed_attempts: 5, ban_duration_minutes: 30 },
  },
  {
    name: 'nginx',
    binaries: ['nginx'],
    logPaths: ['/var/log/nginx/access.log', '/var/log/nginx/error.log'],
    moduleConfig: { access_log: '/var/log/nginx/access.log', error_log: '/var/log/nginx/error.log' },
  },
  {
    name: 'apache',
    binaries: ['apache2', 'httpd'],
    logPaths: ['/var/log/apache2/access.log', '/var/log/httpd/access_log'],
    moduleConfig: { access_log: '/var/log/apache2/access.log' },
  },
  {
    name: 'postgresql',
    binaries: ['postgres', 'postgresql'],
    logPaths: ['/var/log/postgresql/postgresql-main.log'],
    moduleConfig: { log_path: '/var/log/postgresql/' },
  },
  {
    name: 'mysql',
    binaries: ['mysqld', 'mariadbd'],
    logPaths: ['/var/log/mysql/error.log', '/var/log/mariadb/mariadb.log'],
    moduleConfig: { log_path: '/var/log/mysql/' },
  },
  {
    name: 'redis',
    binaries: ['redis-server'],
    logPaths: ['/var/log/redis/redis-server.log'],
    moduleConfig: { log_path: '/var/log/redis/' },
  },
  {
    name: 'bind',
    binaries: ['named', 'bind9'],
    logPaths: ['/var/log/named/', '/var/log/bind/'],
    moduleConfig: { log_path: '/var/log/named/' },
  },
];

function isProcessRunning(name: string): boolean {
  try {
    execSync(`pgrep -x ${name}`, { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function binaryExists(name: string): boolean {
  try {
    execSync(`which ${name}`, { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

function findLogPath(paths: string[]): string | undefined {
  return paths.find((p) => existsSync(p));
}

export async function initCommand(): Promise<void> {
  banner();
  logger.info('Initializing ThreatCrush — scanning system...\n');

  const spinner = ora({ text: 'Detecting services...', color: 'green' }).start();
  const detected: DetectedService[] = [];

  for (const svc of SERVICES_TO_DETECT) {
    const foundBinary = svc.binaries.find((b) => binaryExists(b));
    if (foundBinary) {
      const running = svc.binaries.some((b) => isProcessRunning(b));
      const logPath = findLogPath(svc.logPaths);
      detected.push({
        name: svc.name,
        binary: foundBinary,
        running,
        logPath,
      });
    }
  }

  spinner.succeed(`Found ${detected.length} service(s)\n`);

  // Print findings
  if (detected.length === 0) {
    console.log(chalk.yellow('  No monitored services detected on this system.'));
    console.log(chalk.gray('  ThreatCrush will still work with manual configuration.\n'));
  } else {
    console.log(chalk.green.bold('  Detected Services:'));
    console.log(chalk.gray('  ' + '─'.repeat(60)));
    for (const svc of detected) {
      const status = svc.running
        ? chalk.green('● running')
        : chalk.yellow('○ installed');
      const log = svc.logPath
        ? chalk.gray(` → ${svc.logPath}`)
        : chalk.gray(' → no log found');
      console.log(`  ${status}  ${chalk.white.bold(svc.name.padEnd(14))}${log}`);
    }
    console.log();
  }

  // Generate config files
  const configDir = '/etc/threatcrush';
  const confDDir = `${configDir}/threatcrushd.conf.d`;

  const canWrite = checkWriteAccess(configDir);

  if (!canWrite) {
    console.log(chalk.yellow('  ⚠ Cannot write to /etc/threatcrush/ (run with sudo for full setup)'));
    console.log(chalk.gray('  Printing generated configs instead:\n'));

    // Print main config
    console.log(chalk.green.bold('  Main config (/etc/threatcrush/threatcrushd.conf):'));
    console.log(chalk.gray('  ' + '─'.repeat(60)));
    const mainConfig = generateDefaultConfig(detected.map((d) => d.name));
    for (const line of mainConfig.split('\n')) {
      console.log(chalk.gray('  ') + chalk.white(line));
    }
    console.log();

    // Print module configs
    for (const svc of detected) {
      const svcDef = SERVICES_TO_DETECT.find((s) => s.name === svc.name);
      if (!svcDef) continue;
      const modName = svc.name === 'sshd' ? 'ssh-guard' : 'log-watcher';
      console.log(chalk.green.bold(`  Module config (${confDDir}/${modName}.conf):`));
      const modConfig = generateModuleConfig(modName, {
        ...svcDef.moduleConfig,
        log_path: svc.logPath || svcDef.logPaths[0],
      });
      for (const line of modConfig.split('\n')) {
        console.log(chalk.gray('  ') + chalk.white(line));
      }
      console.log();
    }
  } else {
    const spinner2 = ora({ text: 'Writing configuration files...', color: 'green' }).start();

    mkdirSync(confDDir, { recursive: true });
    mkdirSync('/var/log/threatcrush', { recursive: true });
    mkdirSync('/var/lib/threatcrush', { recursive: true });

    // Write main config
    const mainConfig = generateDefaultConfig(detected.map((d) => d.name));
    writeFileSync(`${configDir}/threatcrushd.conf`, mainConfig);

    // Write module configs
    for (const svc of detected) {
      const svcDef = SERVICES_TO_DETECT.find((s) => s.name === svc.name);
      if (!svcDef) continue;
      const modName = svc.name === 'sshd' ? 'ssh-guard' : 'log-watcher';
      const modConfig = generateModuleConfig(modName, {
        ...svcDef.moduleConfig,
        log_path: svc.logPath || svcDef.logPaths[0],
      });
      writeFileSync(`${confDDir}/${modName}.conf`, modConfig);
    }

    spinner2.succeed('Configuration written successfully');
    console.log();
    console.log(chalk.green('  ✓ Main config:  ') + chalk.white(`${configDir}/threatcrushd.conf`));
    console.log(chalk.green('  ✓ Module dir:   ') + chalk.white(confDDir));
    console.log(chalk.green('  ✓ Log dir:      ') + chalk.white('/var/log/threatcrush/'));
    console.log(chalk.green('  ✓ State dir:    ') + chalk.white('/var/lib/threatcrush/'));
  }

  console.log();
  console.log(chalk.green('  Next steps:'));
  console.log(chalk.gray('    1. Review and edit the config files'));
  console.log(chalk.gray('    2. Run ') + chalk.white('threatcrush monitor') + chalk.gray(' to start monitoring'));
  console.log(chalk.gray('    3. Run ') + chalk.white('threatcrush monitor --tui') + chalk.gray(' for the dashboard'));
  console.log();
}

function checkWriteAccess(dir: string): boolean {
  try {
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    return true;
  } catch {
    return false;
  }
}
