import { existsSync } from 'node:fs';
import chalk from 'chalk';
import ora from 'ora';
import { banner, logger } from '../core/logger.js';
import type { RunResult, Severity } from '../core/run-result.js';
import { runExploreEngine, type ExploreOptions } from '../explore/index.js';

export interface ExploreCliOptions {
  goal?: string;
  hint?: string[];
  aiUrl?: string;
  aiModel?: string;
  maxSteps?: string;
  maxToolCalls?: string;
  timeout?: string;
  json?: boolean;
  graph?: boolean;
  upload?: boolean;
}

const SEV_COLOR: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red,
  medium: chalk.yellow,
  low: chalk.cyan,
  info: chalk.gray,
};

export async function exploreCommand(
  dir: string,
  opts: ExploreCliOptions,
  upload?: (r: RunResult) => Promise<void>,
): Promise<RunResult> {
  if (!opts.json) {
    banner();
    console.log(chalk.green.bold('  Explore — blackboard state-space code audit'));
    console.log(chalk.gray('  ' + '─'.repeat(58)));
  }

  if (!existsSync(dir)) {
    logger.error(`No such directory: ${dir}`);
    return {
      type: 'explore', target: dir, findings: [],
      severity_summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      summary: `no such directory: ${dir}`, error: 'no such path',
    };
  }

  const runOpts: ExploreOptions = {
    goal: opts.goal,
    hints: opts.hint,
    aiUrl: opts.aiUrl,
    model: opts.aiModel,
    maxSteps: opts.maxSteps ? Math.max(1, Number(opts.maxSteps) || 12) : undefined,
    maxToolCalls: opts.maxToolCalls ? Math.max(1, Number(opts.maxToolCalls) || 6) : undefined,
    timeoutMs: opts.timeout ? Math.max(10, Number(opts.timeout) || 600) * 1000 : undefined,
  };

  const spinner = opts.json ? null : ora({ text: 'Starting exploration...', color: 'green' }).start();
  const warnings: string[] = [];

  const { result, engine, target } = await runExploreEngine(dir, {
    ...runOpts,
    onStep: (s) => {
      const tag = s.findingSeverity ? ` ${SEV_COLOR[s.findingSeverity](s.findingSeverity)}` : '';
      if (spinner) spinner.text = `step ${s.step} [${s.kind}] ${s.outcome}${tag ? ' +finding' : ''}`;
    },
    onTool: (c) => { if (spinner) spinner.text = `  ${c.tool} ${c.path ?? c.needle ?? ''}`; },
    onError: (k, m) => {
      // stderr, so it never pollutes --json on stdout but is never swallowed.
      warnings.push(`${k}: ${m}`);
      if (spinner) { spinner.stop(); logger.warn(`${k} step failed: ${m}`); spinner.start(); }
      else logger.warn(`${k} step failed: ${m}`);
    },
  });
  spinner?.stop();

  if (!opts.json) {
    console.log(
      chalk.gray(
        target.local
          ? `  model: ${target.label} (code stays on this endpoint)`
          : `  model: masked code goes to the ${target.label}; use --ai-url http://localhost:11434/v1 to keep it local`,
      ),
    );
  }

  if (upload && opts.upload !== false && !result.error) {
    try {
      await upload(result);
    } catch (e) {
      if (!opts.json) logger.warn(`upload failed: ${(e as Error).message}`);
    }
  }

  if (opts.json) {
    console.log(JSON.stringify({ ...result, steps: engine.steps, errors: engine.errors, warnings, graph: engine.board.render() }, null, 2));
    return result;
  }

  console.log();
  for (const s of engine.steps) console.log(chalk.gray(`  ${String(s.step).padStart(2)} [${s.kind}] ${s.outcome}`));
  console.log();

  if (result.findings.length === 0) {
    console.log(`  ${chalk.green('✓')} No vulnerabilities concluded.`);
  } else {
    const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    for (const f of [...result.findings].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))) {
      console.log(`  ${SEV_COLOR[f.severity]('✖ ' + f.severity.toUpperCase().padEnd(8))} ${f.message}`);
      if (f.location) console.log(chalk.gray(`      ${f.location}${f.details?.cwe ? ` · ${f.details.cwe}` : ''}`));
    }
  }

  if (opts.graph) {
    console.log();
    console.log(chalk.white.bold('  Graph'));
    console.log(engine.board.render().split('\n').map((l) => '  ' + chalk.gray(l)).join('\n'));
  }

  console.log();
  console.log(`  ${chalk.white(result.summary)}${engine.completed ? chalk.green(' ✓ goal met') : ''}`);
  console.log();
  return result;
}
