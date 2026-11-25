import readline from 'node:readline';
import chalk from 'chalk';
import ora from 'ora';
import { banner, logger } from '../core/logger.js';
import type { RunResult, Severity } from '../core/run-result.js';
import { runRedteam, defaultFetcher, type RedteamOptions } from '../redteam/index.js';
import type { AiPrioritizeConfig } from '../redteam/plan.js';

export interface RedteamCliOptions {
  authorized?: boolean;
  max?: string;
  timeout?: string;
  htmlOnly?: boolean;
  ai?: boolean;
  json?: boolean;
}

const AUTHORIZED_NOTE =
  'Redteam autonomously maps and probes a target. Run it ONLY against systems you own or have explicit written authorization to test. Unauthorized scanning may be illegal.';

function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return Promise.resolve(false);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (ans) => { rl.close(); resolve(/^y(es)?$/i.test(ans.trim())); });
  });
}

const SEV_COLOR: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold, high: chalk.red, medium: chalk.yellow, low: chalk.cyan, info: chalk.gray,
};

function aiConfig(enabled?: boolean): AiPrioritizeConfig | undefined {
  if (!enabled) return undefined;
  const computeUrl = process.env.TC_COMPUTE_URL;
  if (!computeUrl) {
    logger.warn('--ai set but TC_COMPUTE_URL is not configured; using the deterministic planner.');
    return undefined;
  }
  return { computeUrl, model: process.env.TC_COMPUTE_MODEL, apiKey: process.env.TC_COMPUTE_KEY };
}

export async function redteamCommand(target: string, opts: RedteamCliOptions): Promise<RunResult> {
  banner();
  console.log(chalk.green.bold('  Redteam — autonomous security pass (recon → probe → report)'));
  console.log(chalk.gray('  ' + '─'.repeat(58)));
  console.log(chalk.yellow(`  ${AUTHORIZED_NOTE}`));
  console.log();

  if (!opts.authorized) {
    const okay = await confirm(chalk.yellow(`  I own ${target} or am authorized to test it [y/N]: `));
    if (!okay) {
      logger.error('Authorization not confirmed. Re-run with --authorized once you have permission.');
      return {
        type: 'redteam', target, findings: [],
        severity_summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        summary: 'aborted: authorization not confirmed', error: 'authorization not confirmed',
      };
    }
  }

  const runOpts: RedteamOptions = {
    maxActions: opts.max ? Number(opts.max) : 25,
    timeoutMs: opts.timeout ? Number(opts.timeout) : 8000,
    htmlOnly: opts.htmlOnly,
    ai: aiConfig(opts.ai),
  };

  logger.info(`Mapping ${chalk.white(target)}...`);
  const spinner = ora({ text: 'Recon + probing...', color: 'green' }).start();
  const { result, surface, steps } = await runRedteam(target, defaultFetcher, {
    ...runOpts,
    onStep: (s, done, total) => { spinner.text = `Probing ${done}/${total}: ${s.method} ${s.path}`; },
  });
  spinner.stop();

  if (opts.json) {
    console.log(JSON.stringify({ ...result, surface: { routes: surface.routes, notes: surface.notes }, steps }, null, 2));
    return result;
  }

  console.log();
  for (const n of surface.notes) console.log(chalk.gray(`  recon: ${n}`));
  console.log(chalk.gray(`  mapped ${surface.routes.length} route(s), probed ${steps.length}`));
  console.log();

  if (result.findings.length === 0) {
    console.log(`  ${chalk.green('✓')} No issues found.`);
  } else {
    const order: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
    const sorted = [...result.findings].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
    for (const f of sorted) {
      console.log(`  ${SEV_COLOR[f.severity]('✖ ' + f.severity.toUpperCase().padEnd(8))} ${f.message}`);
      if (f.details?.remediation) console.log(chalk.gray(`      ${String(f.details.remediation)}`));
    }
  }
  console.log();
  console.log(`  ${chalk.white(result.summary)}`);
  console.log();
  return result;
}
