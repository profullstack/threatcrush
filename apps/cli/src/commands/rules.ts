import chalk from 'chalk';
import { banner } from '../core/logger.js';
import { loadAllRules } from '../daemon/rules/loader.js';

export async function rulesListCommand(): Promise<void> {
  banner();

  const rules = loadAllRules();

  console.log(chalk.green.bold('  Detection Rules'));
  console.log(chalk.gray('  ' + '─'.repeat(70)));
  console.log(
    chalk.gray('  ') +
    chalk.white.bold('ID'.padEnd(28)) +
    chalk.white.bold('Severity'.padEnd(12)) +
    chalk.white.bold('Category'.padEnd(12)) +
    chalk.white.bold('Threshold'.padEnd(12)) +
    chalk.white.bold('Title'),
  );
  console.log(chalk.gray('  ' + '─'.repeat(70)));

  for (const rule of rules) {
    const sevColor = rule.severity === 'critical' ? chalk.red :
      rule.severity === 'high' ? chalk.red :
      rule.severity === 'medium' ? chalk.yellow : chalk.green;

    console.log(
      chalk.gray('  ') +
      chalk.white(rule.id.padEnd(28)) +
      sevColor(rule.severity.padEnd(12)) +
      chalk.gray(rule.category.padEnd(12)) +
      chalk.white(String(rule.threshold).padEnd(12)) +
      chalk.gray(rule.title),
    );
  }

  console.log();
  console.log(chalk.gray(`  ${rules.length} rule(s) loaded`));
  console.log(chalk.gray(`  Custom rules: /etc/threatcrush/rules.d/*.json`));
  console.log();
}

export async function rulesShowCommand(ruleId: string): Promise<void> {
  banner();

  const rules = loadAllRules();
  const rule = rules.find(r => r.id === ruleId);

  if (!rule) {
    console.log(chalk.red(`  Rule not found: ${ruleId}`));
    console.log(chalk.gray('  Run `threatcrush rules list` to see available rules.\n'));
    return;
  }

  console.log(chalk.green.bold(`  Rule: ${rule.id}`));
  console.log(chalk.gray('  ' + '─'.repeat(60)));
  console.log(`  Title:        ${chalk.white(rule.title)}`);
  console.log(`  Description:  ${chalk.gray(rule.description)}`);
  console.log(`  Version:      ${chalk.gray(rule.version)}`);
  console.log(`  Category:     ${chalk.gray(rule.category)}`);
  console.log(`  Severity:     ${chalk.yellow(rule.severity)}`);
  console.log(`  Source types: ${chalk.gray(rule.source_types.join(', '))}`);
  console.log(`  Threshold:    ${chalk.white(String(rule.threshold))} events in ${chalk.white(String(rule.window_seconds))}s`);
  console.log(`  Cooldown:     ${chalk.gray(String(rule.cooldown_seconds))}s`);
  console.log(`  Tags:         ${chalk.gray(rule.tags.join(', '))}`);
  console.log(`  Enabled:      ${rule.enabled ? chalk.green('yes') : chalk.red('no')}`);
  if (rule.remediation) {
    console.log(`  Remediation:  ${chalk.gray(rule.remediation.description || rule.remediation.action || 'none')}`);
    if (rule.remediation.ttl_seconds) {
      console.log(`  Block TTL:    ${chalk.gray(String(rule.remediation.ttl_seconds))}s`);
    }
  }
  console.log();
  console.log(chalk.gray('  Match condition:'));
  console.log(chalk.gray(`    ${rule.match.field} ${rule.match.operator} "${rule.match.value}"`));
  console.log();
}

export async function rulesCommand(opts: { action?: string; id?: string }): Promise<void> {
  const action = opts.action || 'list';
  switch (action) {
    case 'list':
    case 'ls':
      await rulesListCommand();
      break;
    case 'show':
    case 'info':
      if (!opts.id) {
        console.log(chalk.red('  Rule ID required. Usage: threatcrush rules show <rule-id>\n'));
        return;
      }
      await rulesShowCommand(opts.id);
      break;
    default:
      console.log(chalk.yellow(`  Unknown action: ${action}`));
      console.log(chalk.gray('  Available: list, show\n'));
      break;
  }
}
