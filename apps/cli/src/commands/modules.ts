import { execSync } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync, cpSync, rmSync, readFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import chalk from 'chalk';
import ora from 'ora';
import TOML from '@iarna/toml';
import { banner, logger } from '../core/logger.js';
import { discoverModules } from '../core/module-loader.js';
import { PATHS, ensureRuntimeDirs } from '../daemon/paths.js';
import { findRunningDaemon } from '../daemon/pidfile.js';

const API_URL = process.env.THREATCRUSH_API_URL || 'https://threatcrush.com';

function modulesDir(): string {
  ensureRuntimeDirs();
  return PATHS.moduleDir;
}

function validateManifest(modPath: string): { ok: boolean; error?: string; name?: string; version?: string } {
  const manifestPath = join(modPath, 'mod.toml');
  if (!existsSync(manifestPath)) {
    return { ok: false, error: `mod.toml not found at ${manifestPath}` };
  }
  try {
    const raw = readFileSync(manifestPath, 'utf-8');
    const parsed = TOML.parse(raw) as { module?: { name?: string; version?: string } };
    const name = parsed.module?.name;
    const version = parsed.module?.version;
    if (!name) return { ok: false, error: 'mod.toml is missing [module] name' };
    if (!version) return { ok: false, error: 'mod.toml is missing [module] version' };
    return { ok: true, name, version };
  } catch (err) {
    return { ok: false, error: `Invalid mod.toml: ${(err as Error).message}` };
  }
}

function notifyDaemonIfRunning(): void {
  if (!findRunningDaemon()) return;
  console.log(chalk.dim(`  ℹ threatcrushd is running — restart it to load/unload modules:`));
  console.log(chalk.dim(`    ${chalk.white('threatcrush stop && threatcrush start')}`));
}

export async function modulesListCommand(): Promise<void> {
  banner();

  const modules = discoverModules();

  console.log(chalk.green.bold('  Installed Modules'));
  console.log(chalk.gray('  ' + '─'.repeat(60)));
  console.log(chalk.dim(`  module dir: ${PATHS.moduleDir}\n`));

  if (modules.length === 0) {
    console.log(chalk.gray('  No modules installed.'));
    console.log();
    console.log(chalk.gray('  Browse available modules:'));
    console.log(chalk.white('    threatcrush store'));
    console.log();
    console.log(chalk.gray('  Or install from the marketplace:'));
    console.log(chalk.white('    threatcrush modules install <name>'));
    console.log();
    return;
  }

  console.log(
    chalk.gray('  ') +
      chalk.white.bold('Name'.padEnd(22)) +
      chalk.white.bold('Version'.padEnd(12)) +
      chalk.white.bold('Status'.padEnd(12)) +
      chalk.white.bold('Description'),
  );
  console.log(chalk.gray('  ' + '─'.repeat(60)));

  for (const mod of modules) {
    const enabled = mod.config.enabled !== false;
    const status = enabled ? chalk.green('enabled') : chalk.gray('disabled');
    console.log(
      chalk.gray('  ') +
        chalk.white(mod.manifest.name.padEnd(22)) +
        chalk.gray(mod.manifest.version.padEnd(12)) +
        status.padEnd(21) +
        chalk.gray(mod.manifest.description || '—'),
    );
  }
  console.log();
}

export async function modulesInstallCommand(source: string): Promise<void> {
  banner();

  console.log(chalk.green.bold('  Module Installation'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));
  console.log();

  const dir = modulesDir();

  // ── Local path ──
  if (source.startsWith('./') || source.startsWith('/') || source.startsWith('~')) {
    const absPath = resolve(source.startsWith('~') ? source.replace('~', process.env.HOME || '') : source);
    if (!existsSync(absPath)) {
      console.log(chalk.red(`  ✗ Path not found: ${absPath}\n`));
      return;
    }
    const check = validateManifest(absPath);
    if (!check.ok) {
      console.log(chalk.red(`  ✗ ${check.error}\n`));
      return;
    }
    const dest = join(dir, check.name!);
    if (existsSync(dest)) {
      console.log(chalk.yellow(`  ! ${check.name} is already installed at ${dest}`));
      console.log(chalk.dim(`    Run ${chalk.white(`threatcrush modules remove ${check.name}`)} first.\n`));
      return;
    }
    const spinner = ora({ text: `Copying module files...`, color: 'green' }).start();
    try {
      cpSync(absPath, dest, { recursive: true, dereference: true });
      spinner.succeed(`Installed ${chalk.white(check.name!)} v${check.version} → ${dest}`);
    } catch (err) {
      spinner.fail(`Copy failed: ${(err as Error).message}`);
      return;
    }
    notifyDaemonIfRunning();
    console.log();
    return;
  }

  // ── Git URL (github:user/repo or full https://) ──
  if (source.startsWith('github:') || source.startsWith('https://') || source.startsWith('git@') || source.endsWith('.git')) {
    const gitUrl = source.startsWith('github:')
      ? `https://github.com/${source.slice('github:'.length)}.git`
      : source;

    const name = basename(gitUrl.replace(/\.git$/, ''));
    const dest = join(dir, name);
    if (existsSync(dest)) {
      console.log(chalk.yellow(`  ! ${name} is already installed at ${dest}`));
      console.log(chalk.dim(`    Run ${chalk.white(`threatcrush modules remove ${name}`)} first.\n`));
      return;
    }
    const spinner = ora({ text: `Cloning ${gitUrl}...`, color: 'green' }).start();
    try {
      execSync(`git clone --depth 1 ${gitUrl} ${dest}`, { stdio: 'pipe' });
    } catch (err) {
      spinner.fail(`Clone failed: ${(err as Error).message}`);
      return;
    }
    const check = validateManifest(dest);
    if (!check.ok) {
      spinner.fail(check.error!);
      try { rmSync(dest, { recursive: true, force: true }); } catch {}
      return;
    }
    spinner.succeed(`Installed ${chalk.white(check.name!)} v${check.version} → ${dest}`);
    notifyDaemonIfRunning();
    console.log();
    return;
  }

  // ── Marketplace lookup ──
  const spinner = ora({ text: `Fetching module: ${source}...`, color: 'green' }).start();
  let data: {
    success?: boolean;
    downloads?: number;
    module?: {
      name: string;
      slug: string;
      version: string;
      license: string;
      os_support?: string[];
      install: {
        npm_package?: string;
        git_url?: string;
        tarball_url?: string;
      };
    };
  };

  try {
    const res = await fetch(`${API_URL}/api/modules/${source}/install`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ platform: 'linux-cli' }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      spinner.fail(`Module not found: ${(err as Record<string, string>).error || source}`);
      console.log(chalk.gray(`  Browse: ${API_URL}/store\n`));
      return;
    }
    data = await res.json();
  } catch (err) {
    spinner.fail(`Network error: ${(err as Error).message}`);
    return;
  }

  const mod = data.module;
  if (!mod) {
    spinner.fail('Malformed response from marketplace');
    return;
  }
  spinner.succeed(`Found ${mod.name} v${mod.version}`);

  const install = mod.install;
  const dest = join(dir, mod.slug);
  if (existsSync(dest)) {
    console.log(chalk.yellow(`  ! ${mod.slug} is already installed at ${dest}\n`));
    return;
  }

  if (install.git_url) {
    const cloneSpinner = ora({ text: 'Cloning module repository...', color: 'green' }).start();
    try {
      execSync(`git clone --depth 1 ${install.git_url} ${dest}`, { stdio: 'pipe' });
    } catch (err) {
      cloneSpinner.fail(`Clone failed: ${(err as Error).message}`);
      return;
    }
    const check = validateManifest(dest);
    if (!check.ok) {
      cloneSpinner.fail(check.error!);
      try { rmSync(dest, { recursive: true, force: true }); } catch {}
      return;
    }
    cloneSpinner.succeed(`Installed ${mod.name} v${mod.version} → ${dest}`);
  } else if (install.npm_package) {
    const npmSpinner = ora({ text: `Installing ${install.npm_package}...`, color: 'green' }).start();
    try {
      execSync(`npm install -g ${install.npm_package}`, { stdio: 'pipe' });
      npmSpinner.succeed(`Package ${install.npm_package} installed globally`);
    } catch (err) {
      npmSpinner.fail(`npm install failed: ${(err as Error).message}`);
      return;
    }
  } else if (install.tarball_url) {
    const dlSpinner = ora({ text: 'Downloading module tarball...', color: 'green' }).start();
    try {
      const res = await fetch(install.tarball_url);
      if (!res.ok) { dlSpinner.fail(`HTTP ${res.status}`); return; }
      const tar = join(dir, `${mod.slug}.tar.gz`);
      writeFileSync(tar, Buffer.from(await res.arrayBuffer()));
      execSync(`tar -xzf ${tar} -C ${dir}`, { stdio: 'pipe' });
      rmSync(tar, { force: true });
      const check = validateManifest(dest);
      if (!check.ok) {
        dlSpinner.fail(check.error!);
        return;
      }
      dlSpinner.succeed(`Installed ${mod.name} v${mod.version} → ${dest}`);
    } catch (err) {
      dlSpinner.fail(`Download failed: ${(err as Error).message}`);
      return;
    }
  } else {
    logger.info('No installable artifact provided for this module.');
    return;
  }

  notifyDaemonIfRunning();
  console.log();
}

export async function modulesRemoveCommand(name: string): Promise<void> {
  banner();

  console.log(chalk.green.bold('  Module Removal'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));

  const dir = modulesDir();
  const target = join(dir, name);
  if (!existsSync(target)) {
    console.log(chalk.yellow(`  ! No module named "${name}" in ${dir}\n`));
    return;
  }

  const check = validateManifest(target);
  if (check.ok && check.name !== name) {
    console.log(chalk.yellow(`  ! Directory name "${name}" does not match manifest name "${check.name}"`));
  }

  try {
    rmSync(target, { recursive: true, force: true });
    console.log(chalk.green(`  ✓ Removed ${name} from ${dir}\n`));
  } catch (err) {
    console.log(chalk.red(`  ✗ Failed to remove: ${(err as Error).message}\n`));
    return;
  }

  notifyDaemonIfRunning();
}

export async function modulesCommand(opts: { action?: string; name?: string }): Promise<void> {
  const action = opts.action || 'list';

  switch (action) {
    case 'list':
    case 'available':
    case 'ls':
      await modulesListCommand();
      break;
    case 'install':
    case 'add':
      if (!opts.name) {
        banner();
        console.log(chalk.red('  Module name required.'));
        console.log(chalk.gray('  Usage:'));
        console.log(chalk.gray('    threatcrush modules install <marketplace-name>'));
        console.log(chalk.gray('    threatcrush modules install ./local-path'));
        console.log(chalk.gray('    threatcrush modules install github:user/repo'));
        console.log(chalk.gray('    threatcrush modules install https://github.com/user/repo.git\n'));
        return;
      }
      await modulesInstallCommand(opts.name);
      break;
    case 'remove':
    case 'rm':
    case 'uninstall':
      if (!opts.name) {
        banner();
        console.log(chalk.red('  Module name required.'));
        console.log(chalk.gray('  Usage: threatcrush modules remove <name>\n'));
        return;
      }
      await modulesRemoveCommand(opts.name);
      break;
    default:
      banner();
      console.log(chalk.yellow(`  Unknown action: ${action}`));
      console.log(chalk.gray('  Available actions: list, install, remove\n'));
      await modulesListCommand();
      break;
  }
}
