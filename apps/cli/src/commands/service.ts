import { execSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import chalk from 'chalk';
import { banner } from '../core/logger.js';

const UNIT_PATH = '/etc/systemd/system/threatcrushd.service';

function resolveTemplate(): string {
  const templatePath = join(__dirname, 'systemd', 'threatcrushd.service');
  if (!existsSync(templatePath)) {
    throw new Error(`systemd unit template not found at ${templatePath}`);
  }
  return readFileSync(templatePath, 'utf-8');
}

function resolveBinPath(): string {
  // When installed globally the script path is the CLI bin.
  const arg = process.argv[1];
  if (arg && existsSync(arg)) return arg;
  try {
    return execSync('command -v threatcrush', { encoding: 'utf-8' }).trim();
  } catch {
    return 'threatcrush';
  }
}

function isRoot(): boolean {
  return typeof process.getuid === 'function' && process.getuid() === 0;
}

export async function installServiceCommand(): Promise<void> {
  banner();

  if (process.platform !== 'linux') {
    console.log(chalk.yellow('  systemd install is only supported on Linux.'));
    return;
  }

  if (!isRoot()) {
    console.log(chalk.red('  Must run as root (try `sudo threatcrush install-service`).'));
    return;
  }

  const unit = resolveTemplate().replace('{{BIN_PATH}}', resolveBinPath());
  writeFileSync(UNIT_PATH, unit, { mode: 0o644 });
  console.log(chalk.green(`  ✓ Installed unit file: ${UNIT_PATH}`));

  try {
    execSync('systemctl daemon-reload', { stdio: 'inherit' });
    execSync('systemctl enable threatcrushd.service', { stdio: 'inherit' });
    console.log(chalk.green('  ✓ Service enabled on boot.'));
    console.log(chalk.dim('  Start now with: systemctl start threatcrushd'));
    console.log(chalk.dim('  View logs with: journalctl -u threatcrushd -f'));
  } catch (err) {
    console.log(chalk.yellow(`  ! systemctl error: ${(err as Error).message}`));
  }
}

export async function uninstallServiceCommand(): Promise<void> {
  banner();

  if (process.platform !== 'linux') {
    console.log(chalk.yellow('  systemd uninstall is only supported on Linux.'));
    return;
  }
  if (!isRoot()) {
    console.log(chalk.red('  Must run as root (try `sudo threatcrush uninstall-service`).'));
    return;
  }

  try { execSync('systemctl stop threatcrushd.service', { stdio: 'inherit' }); } catch {}
  try { execSync('systemctl disable threatcrushd.service', { stdio: 'inherit' }); } catch {}
  try {
    if (existsSync(UNIT_PATH)) {
      execSync(`rm -f ${UNIT_PATH}`);
      console.log(chalk.green(`  ✓ Removed unit file: ${UNIT_PATH}`));
    }
  } catch {}
  try { execSync('systemctl daemon-reload', { stdio: 'inherit' }); } catch {}

  console.log(chalk.green('  ✓ threatcrushd service removed.'));
}
