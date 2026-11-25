import chalk from 'chalk';
import ora from 'ora';
import { banner, logger } from '../core/logger.js';
import type { RunResult } from '../core/run-result.js';
import { runShields, renderGrid, portsForTest, type RunShieldsOptions, type ShieldsTest } from '../shields/index.js';
import { tcpProber } from '../shields/tcp.js';
import type { PortResult } from '../shields/scan.js';

export interface ShieldsCliOptions {
  all?: boolean;
  fileSharing?: boolean;
  ports?: string;
  timeout?: string;
  concurrency?: string;
  json?: boolean;
}

const AUTHORIZED_NOTE =
  'Shields tests a firewall by connecting to its ports from the outside. Only run it against your OWN public IP, or a host you are authorized to test.';

/** Resolve this machine's own public IPv4 via our own service, then ipify. */
async function resolveOwnIp(): Promise<string | null> {
  const tryFetch = async (url: string, pick: (t: string) => string | null): Promise<string | null> => {
    try {
      const resp = await fetch(url, { signal: AbortSignal.timeout(5000) });
      if (!resp.ok) return null;
      return pick((await resp.text()).trim());
    } catch {
      return null;
    }
  };
  const isV4 = (s: string | null): s is string => !!s && /^\d{1,3}(\.\d{1,3}){3}$/.test(s);

  // my.ip.pit.world?format=json → { "v4": "1.2.3.4", ... }
  const ours = await tryFetch('https://my.ip.pit.world?format=json', (t) => {
    try { return (JSON.parse(t) as { v4?: string }).v4 ?? null; } catch { return null; }
  });
  if (isV4(ours)) return ours;

  const ipify = await tryFetch('https://api.ipify.org', (t) => t);
  if (isV4(ipify)) return ipify;
  return null;
}

function chosenTest(opts: ShieldsCliOptions): ShieldsTest {
  if (opts.all) return 'all';
  if (opts.fileSharing) return 'file-sharing';
  return 'common';
}

function colorByState(state: PortResult['state'], text: string): string {
  return state === 'open' ? chalk.red.bold(text)
    : state === 'closed' ? chalk.yellow(text)
      : chalk.gray(text);
}

function abort(target: string, reason: string): RunResult {
  return {
    type: 'shields', target, findings: [],
    severity_summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    summary: `aborted: ${reason}`, error: reason,
  };
}

export async function shieldsCommand(target: string | undefined, opts: ShieldsCliOptions): Promise<RunResult> {
  banner();
  console.log(chalk.green.bold('  Shields — firewall port-exposure self-test'));
  console.log(chalk.gray('  ' + '─'.repeat(56)));
  console.log(chalk.gray("  Inspired by GRC's ShieldsUP!; independent, not affiliated with GRC."));
  console.log(chalk.yellow(`  ${AUTHORIZED_NOTE}`));
  console.log();

  let host = target;
  let resolvedSelf = false;
  if (!host) {
    const spinner = ora({ text: 'Resolving your public IPv4...', color: 'green' }).start();
    const ip = await resolveOwnIp();
    spinner.stop();
    if (!ip) {
      logger.error('Could not determine your public IP. Pass a target explicitly: threatcrush shields <host>');
      return abort('unknown', 'could not resolve public IP');
    }
    host = ip;
    resolvedSelf = true;
    logger.info(`Testing your own public IP ${chalk.white(host)}`);
    logger.info(chalk.gray('Note: scanning your own IP from this same machine can hairpin through your router; a cloud/VPS box reflects its real exposure.'));
  } else {
    logger.info(`Testing ${chalk.white(host)} (host you confirm you own or are authorized to test)`);
  }

  const runOpts: RunShieldsOptions = {
    test: chosenTest(opts),
    ports: opts.ports,
    timeoutMs: opts.timeout ? Number(opts.timeout) : 3000,
    concurrency: opts.concurrency ? Number(opts.concurrency) : 64,
  };

  const total = portsForTest(runOpts).length;
  const spinner = ora({ text: `Probing ${total} port(s)...`, color: 'green' }).start();
  const { summary, result, results } = await runShields(host, tcpProber, {
    ...runOpts,
    onPort: (_r, done) => { spinner.text = `Probing ports... ${done}/${total}`; },
  });
  spinner.stop();

  if (opts.json) {
    console.log(JSON.stringify({ ...result, grade: summary.grade, counts: summary }, null, 2));
    return result;
  }

  console.log();
  console.log(`  ${chalk.red.bold('●')} open   ${chalk.yellow('○')} closed   ${chalk.gray('·')} stealth`);
  console.log();

  // The full 0–1055 sweep is 1056 glyphs; only grid the named/custom tests.
  if (runOpts.test !== 'all') {
    console.log(renderGrid(results, colorByState));
    console.log();
  }

  if (summary.open > 0) {
    for (const f of result.findings.filter((x) => x.type === 'open-port')) {
      console.log(`  ${chalk.red('✖')} ${chalk.red(f.severity.toUpperCase().padEnd(8))} ${f.message}`);
    }
    console.log();
  }

  const gradeColor = summary.grade === 'stealth' ? chalk.green.bold
    : summary.grade === 'good' ? chalk.green
      : summary.grade === 'warning' ? chalk.yellow
        : chalk.red.bold;
  console.log(`  ${gradeColor(summary.grade.toUpperCase())}  ${summary.verdict}`);
  console.log(chalk.gray(`  ${summary.open} open · ${summary.closed} closed · ${summary.stealth} stealth of ${summary.total}`));
  if (resolvedSelf && summary.grade === 'good') {
    console.log(chalk.gray('  Tip: configure your firewall to DROP unsolicited packets for full stealth.'));
  }
  console.log();
  return result;
}
