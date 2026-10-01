import chalk from 'chalk';
import { isLoggedIn, readCliConfig } from '../core/cli-config.js';
import { findRunningDaemon } from '../daemon/pidfile.js';
import { PATHS } from '../daemon/paths.js';

const LOGO = chalk.green(`
  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
     ██║   ███████║██████╔╝█████╗  ███████║   ██║
     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝`) + chalk.dim(`
                    C R U S H
`);

interface Step {
  heading: string;
  hint?: string;
  cmd: string;
}

function nextSteps(): Step[] {
  const steps: Step[] = [];
  const loggedIn = isLoggedIn();
  const daemonRunning = !!findRunningDaemon();

  if (!loggedIn) {
    steps.push({
      heading: 'Sign in to threatcrush.com',
      hint: 'Stores your license, orgs, and property list.',
      cmd: 'threatcrush login',
    });
  }

  if (!daemonRunning) {
    steps.push({
      heading: 'Start the daemon',
      hint: `Runs in background, exposes an IPC socket at ${PATHS.socket}.`,
      cmd: 'threatcrush start',
    });
  }

  if (loggedIn) {
    steps.push({
      heading: 'Add a target to scan or pentest',
      hint: 'A URL, API, domain, IP, or repo that ThreatCrush will watch.',
      cmd: 'threatcrush properties add <name> <target>',
    });
    steps.push({
      heading: 'Run it now',
      hint: 'Auto-detects scan vs pentest based on the property kind.',
      cmd: 'threatcrush properties run',
    });
  } else {
    steps.push({
      heading: 'Scan a local codebase',
      hint: 'Fast static analysis for secrets and common vulnerabilities.',
      cmd: 'threatcrush scan .',
    });
    steps.push({
      heading: 'Pentest a URL',
      hint: 'Basic automated checks (SQLi / XSS / traversal / headers).',
      cmd: 'threatcrush pentest https://example.com',
    });
  }

  steps.push({
    heading: 'Open the live dashboard',
    hint: 'hqtui dashboard — subscribes to events from the daemon.',
    cmd: 'threatcrush tui',
  });

  return steps;
}

export function welcomeCommand(): void {
  console.log(LOGO);

  const cfg = readCliConfig();
  const loggedIn = isLoggedIn();
  const daemonRunning = !!findRunningDaemon();

  const signedInLine = loggedIn
    ? `${chalk.green('● signed in')} ${chalk.dim('as')} ${chalk.white(cfg.email || cfg.user_id || 'unknown')}`
    : `${chalk.gray('○ not signed in')}`;
  const daemonLine = daemonRunning
    ? `${chalk.green('● daemon running')} ${chalk.dim('at')} ${chalk.gray(PATHS.socket)}`
    : `${chalk.gray('○ daemon stopped')}`;

  console.log(`  ${signedInLine}`);
  console.log(`  ${daemonLine}\n`);

  console.log(chalk.green.bold('  Suggested next steps'));
  console.log(chalk.gray('  ' + '─'.repeat(60)));

  const steps = nextSteps();
  steps.forEach((step, i) => {
    const num = chalk.green(`  ${i + 1}.`);
    console.log(`${num} ${chalk.white.bold(step.heading)}`);
    if (step.hint) console.log(`     ${chalk.dim(step.hint)}`);
    console.log(`     ${chalk.green('$')} ${chalk.white(step.cmd)}\n`);
  });

  console.log(chalk.gray('  ' + '─'.repeat(60)));
  console.log(chalk.dim('  Run ') + chalk.white('threatcrush help') + chalk.dim(' to see every command.'));
  console.log(chalk.dim('  Docs: ') + chalk.white('https://threatcrush.com\n'));
}
