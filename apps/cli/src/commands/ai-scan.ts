import { readFileSync } from 'node:fs';
import chalk from 'chalk';
import ora from 'ora';
import { banner, logger } from '../core/logger.js';
import type { RunResult } from '../core/run-result.js';
import { runAiScan, httpSender } from '../aiscan/runner.js';
import { selectProbes, type ProbeCategory } from '../aiscan/probes.js';
import { runMosh } from '../aiscan/mosh.js';
import { sendUsagePing } from '../core/usage-ping.js';

export interface AiScanCliOptions {
  categories?: string;   // comma list
  template?: string;
  header?: string[];     // repeatable "K: V"
  responsePath?: string;
  delay?: string;        // ms
  json?: boolean;
}

function parseHeaders(pairs: string[] = []): Record<string, string> {
  const out: Record<string, string> = {};
  for (const p of pairs) {
    const i = p.indexOf(':');
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return out;
}

const AUTHORIZED_NOTE =
  'AI red-team scanning sends probing prompts to a target. Only run it against an endpoint you own or are explicitly authorized to test.';

export async function aiScanCommand(url: string, opts: AiScanCliOptions): Promise<RunResult> {
  banner();
  console.log(chalk.green.bold('  AI Red-Team Scan'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));
  console.log(chalk.yellow(`  ${AUTHORIZED_NOTE}`));
  console.log();

  const categories = (opts.categories?.split(',').map((s) => s.trim()).filter(Boolean) ?? []) as ProbeCategory[];
  const send = httpSender({
    url,
    template: opts.template,
    headers: parseHeaders(opts.header),
    responsePath: opts.responsePath,
  });

  const probes = selectProbes(categories);
  logger.info(`Probing ${chalk.white(url)} with ${probes.length} check(s)...\n`);
  const spinner = ora({ text: 'Running probes...', color: 'green' }).start();
  const t0 = Date.now();

  const result = await runAiScan(url, send, {
    categories,
    delayMs: opts.delay ? Number(opts.delay) : 0,
    onProbe: (p, ok) => {
      spinner.text = `${p.owasp} ${p.id} ${ok ? chalk.red('✖ breached') : chalk.gray('ok')}`;
    },
  });
  spinner.stop();
  await sendUsagePing({
    event: 'ai-scan', probes: probes.length, findings: result.findings.length,
    severity: result.severity_summary, duration_ms: Date.now() - t0, failed: Boolean(result.error),
  });

  if (opts.json) {
    console.log(JSON.stringify(result, null, 2));
    return result;
  }

  if (result.findings.length === 0) {
    console.log(`  ${chalk.green('✓')} ${result.summary}`);
  } else {
    for (const f of result.findings) {
      const tag = f.severity === 'high' || f.severity === 'critical' ? chalk.red : chalk.yellow;
      console.log(`  ${tag('✖')} ${tag(f.severity.toUpperCase().padEnd(8))} ${f.message}`);
      console.log(chalk.gray(`      ${(f.details?.remediation as string) ?? ''}`));
    }
    console.log();
    console.log(`  ${chalk.white(result.summary)}`);
  }
  console.log();
  return result;
}

/** `threatcrush ai-scan run <file.mosh>` — drive the scanner from a script. */
export async function aiScanMoshCommand(file: string, args: string[]): Promise<void> {
  banner();
  console.log(chalk.green.bold('  AI Red-Team Script (.mosh)'));
  console.log(chalk.gray('  ' + '─'.repeat(50)));
  console.log(chalk.yellow(`  ${AUTHORIZED_NOTE}`));
  console.log();

  let source: string;
  try {
    source = readFileSync(file, 'utf-8');
  } catch (err) {
    logger.error(`Cannot read ${file}: ${(err as Error).message}`);
    process.exitCode = 1;
    return;
  }

  const t0 = Date.now();
  const res = await runMosh(source, { argv: args, out: (s) => console.log('  ' + s) });
  await sendUsagePing({
    event: 'ai-scan-run', scans: res.scans.length, findings: res.scans.reduce((n, s) => n + s.findings.length, 0),
    duration_ms: Date.now() - t0, failed: Boolean(res.failed),
  });
  if (res.failed) {
    console.log();
    console.log(`  ${chalk.red('✗ script failed:')} ${res.failed}`);
    process.exitCode = 1;
    return;
  }
  const breached = res.scans.reduce((n, s) => n + s.findings.length, 0);
  console.log();
  console.log(`  ${breached === 0 ? chalk.green('✓') : chalk.red('✖')} ${res.scans.length} scan(s), ${breached} guardrail failure(s)`);
  console.log();
}
