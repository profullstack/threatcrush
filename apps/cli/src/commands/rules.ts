import chalk from 'chalk';
import { banner } from '../core/logger.js';
import { loadAllRules } from '../daemon/rules/loader.js';
import { RuleEngine, type RuleMatch } from '../daemon/rules/engine.js';
import { loadConfig } from '../core/config.js';
import { parsePostgresAuthFailure, postgresAuthEvent } from '../daemon/workers/docker-logs.js';

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
    if (rule.remediation.action === 'block') {
      console.log(`  Ban length:   ${chalk.gray('escalation ladder, doubling from first_ban: 5m → 10m → 20m → 40m … up to max_ban')}`);
    }
  }
  console.log();
  console.log(chalk.gray('  Match condition:'));
  const show = (m: RuleMatch, prefix: string, depth: number): void => {
    console.log(chalk.gray(`${'  '.repeat(depth + 2)}${prefix}${m.field} ${m.operator} "${m.value}"`));
    for (const sub of m.and ?? []) show(sub, 'and ', depth + 1);
    for (const sub of m.or ?? []) show(sub, 'or ', depth + 1);
  };
  show(rule.match, '', 0);
  console.log();
}

/**
 * Dry run: feed one log line (repeated) through the daemon's parser and the
 * rule engine, and say whether the rule fires and whether auto-defence would
 * ban. Nothing touches the firewall. Today it reads container log lines from
 * Postgres (the docker-logs source), e.g.
 *
 *   threatcrush rules test postgres-auth-bruteforce --repeat 5 \
 *     --line '45.156.87.10 2026-11-19 16:42:07.224 UTC [1] postgres@postgres FATAL:  password authentication failed for user "postgres"'
 */
export async function rulesTestCommand(ruleId: string, line: string, repeat = 1, json = false): Promise<boolean> {
  const config = loadConfig();
  const protectedList = [...(config.remediation?.protected ?? []), ...(config.remediation?.allowlist ?? [])].map(String);
  const rules = loadAllRules();
  const rule = rules.find((r) => r.id === ruleId);
  const parsed = parsePostgresAuthFailure(line);
  const event = postgresAuthEvent(line, 'dry-run', protectedList);
  const fired: Array<{ rule_id: string; source_ip?: string; description: string }> = [];
  if (rule && event) {
    const engine = new RuleEngine((d) => fired.push({ rule_id: d.rule_id, source_ip: d.source_ip, description: d.description }));
    engine.loadRules([rule]);
    for (let i = 0; i < Math.max(1, repeat); i++) engine.evaluate({ ...event, timestamp: new Date() });
  }
  const wouldBan = fired.length > 0 && rule?.remediation?.action === 'block' && !!fired[0].source_ip;
  const result = {
    rule: rule ? rule.id : null,
    parsed,
    event: event ? { module: event.module, severity: event.severity, source_ip: event.source_ip, message: event.message } : null,
    skipped_reason: !rule ? 'unknown rule' : !parsed ? 'not a recognised line' : !parsed.ip ? 'no client address in the line' : !event ? 'protected/private source, never banned' : undefined,
    repeat,
    threshold: rule?.threshold,
    fired: fired.length > 0,
    would_ban: wouldBan,
    detections: fired,
  };
  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    banner();
    console.log(chalk.green.bold(`  Dry run: ${ruleId}`));
    console.log(`  Parsed:     ${chalk.gray(parsed ? JSON.stringify(parsed) : 'no match')}`);
    console.log(`  Event:      ${chalk.gray(event ? `${event.module} ${event.severity} ${event.source_ip} ${event.message}` : result.skipped_reason ?? 'none')}`);
    console.log(`  Fed:        ${repeat}x (threshold ${rule?.threshold ?? '?'})`);
    console.log(`  Fires:      ${fired.length ? chalk.red('yes') : chalk.green('no')}`);
    console.log(`  Would ban:  ${wouldBan ? chalk.red(fired[0].source_ip) : chalk.green('no')}`);
    console.log(chalk.gray('  (dry run: nothing was blocked)\n'));
  }
  return fired.length > 0;
}

export async function rulesCommand(opts: { action?: string; id?: string; line?: string; repeat?: number; json?: boolean }): Promise<void> {
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
    case 'test':
      if (!opts.id || !opts.line) {
        console.log(chalk.red('  Usage: threatcrush rules test <rule-id> --line "<log line>" [--repeat N] [--json]\n'));
        process.exitCode = 1;
        return;
      }
      await rulesTestCommand(opts.id, opts.line, opts.repeat ?? 1, opts.json === true);
      break;
    default:
      console.log(chalk.yellow(`  Unknown action: ${action}`));
      console.log(chalk.gray('  Available: list, show, test\n'));
      break;
  }
}
