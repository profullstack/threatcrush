import chalk from 'chalk';
import { banner } from '../core/logger.js';
import { discoverModules } from '../core/module-loader.js';

export async function modulesListCommand(): Promise<void> {
  banner();

  const modules = discoverModules();

  console.log(chalk.green.bold('  Installed Modules'));
  console.log(chalk.gray('  ' + '─'.repeat(60)));

  if (modules.length === 0) {
    console.log(chalk.gray('  No modules installed.'));
    console.log();
    console.log(chalk.gray('  Built-in modules will be available after running:'));
    console.log(chalk.white('    threatcrush init'));
    console.log();
    console.log(chalk.gray('  Or install from the marketplace:'));
    console.log(chalk.white('    threatcrush modules install <name>'));
  } else {
    console.log();
    console.log(
      chalk.gray('  ') +
      chalk.white.bold('Name'.padEnd(20)) +
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
        chalk.white(mod.manifest.name.padEnd(20)) +
        chalk.gray(mod.manifest.version.padEnd(12)) +
        status.padEnd(21) +
        chalk.gray(mod.manifest.description || '—'),
      );
    }
  }

  console.log();
}

export async function modulesInstallCommand(name: string): Promise<void> {
  banner();

  console.log(chalk.green.bold('  Module Installation'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));
  console.log();

  if (name.startsWith('./') || name.startsWith('/')) {
    console.log(chalk.yellow(`  Local module installation from: ${name}`));
    console.log(chalk.gray('  → Linking local module...'));
    console.log(chalk.gray('  → This feature is coming soon.'));
  } else {
    console.log(chalk.yellow(`  Installing module: ${chalk.white.bold(name)}`));
    console.log();
    console.log(chalk.gray('  Module marketplace is not yet available.'));
    console.log(chalk.gray('  Stay tuned — module store launching soon at:'));
    console.log(chalk.cyan('    https://threatcrush.com/modules'));
  }

  console.log();
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
        console.log(chalk.gray('  Usage: threatcrush modules install <name>\n'));
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
      banner();
      console.log(chalk.yellow(`  Removing module: ${chalk.white.bold(opts.name)}`));
      console.log(chalk.gray('  → Module removal is coming soon.\n'));
      break;
    default:
      banner();
      console.log(chalk.yellow(`  Unknown action: ${action}`));
      console.log(chalk.gray('  Available actions: list, install, remove\n'));
      await modulesListCommand();
      break;
  }
}
