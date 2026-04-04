import chalk from 'chalk';
import type { EventSeverity } from '../types/events.js';

const SEVERITY_COLORS: Record<EventSeverity, (s: string) => string> = {
  info: chalk.green,
  low: chalk.cyan,
  medium: chalk.yellow,
  high: chalk.red,
  critical: chalk.bgRed.white.bold,
};

const LEVEL_COLORS: Record<string, (s: string) => string> = {
  debug: chalk.gray,
  info: chalk.green,
  warn: chalk.yellow,
  error: chalk.red,
};

export function severityColor(severity: EventSeverity, text: string): string {
  return (SEVERITY_COLORS[severity] || chalk.white)(text);
}

export function formatTimestamp(date: Date = new Date()): string {
  return chalk.gray(date.toISOString().replace('T', ' ').slice(0, 19));
}

export function formatEvent(
  module: string,
  severity: EventSeverity,
  message: string,
  ip?: string,
): string {
  const ts = formatTimestamp();
  const sev = severityColor(severity, `[${severity.toUpperCase()}]`.padEnd(10));
  const mod = chalk.cyan(`[${module}]`.padEnd(14));
  const src = ip ? chalk.magenta(` (${ip})`) : '';
  return `${ts} ${sev} ${mod} ${message}${src}`;
}

export const logger = {
  debug: (msg: string) => console.log(`${formatTimestamp()} ${LEVEL_COLORS.debug('[DEBUG]')}   ${msg}`),
  info: (msg: string) => console.log(`${formatTimestamp()} ${LEVEL_COLORS.info('[INFO]')}    ${msg}`),
  warn: (msg: string) => console.log(`${formatTimestamp()} ${LEVEL_COLORS.warn('[WARN]')}    ${msg}`),
  error: (msg: string) => console.error(`${formatTimestamp()} ${LEVEL_COLORS.error('[ERROR]')}   ${msg}`),
  success: (msg: string) => console.log(`${formatTimestamp()} ${chalk.green('[OK]')}      ${msg}`),
  threat: (msg: string, ip?: string) => {
    const src = ip ? chalk.magenta(` from ${ip}`) : '';
    console.log(`${formatTimestamp()} ${chalk.red.bold('[THREAT]')}  ${chalk.red(msg)}${src}`);
  },
};

export function banner(): void {
  console.log(chalk.green.bold(`
  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗ ██████╗██████╗ ██╗   ██╗███████╗██╗  ██╗
  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██╔══██╗██║   ██║██╔════╝██║  ██║
     ██║   ███████║██████╔╝█████╗  ███████║   ██║   ██║     ██████╔╝██║   ██║███████╗███████║
     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ██║     ██╔══██╗██║   ██║╚════██║██╔══██║
     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ╚██████╗██║  ██║╚██████╔╝███████║██║  ██║
     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
  `));
  console.log(chalk.gray('  All-in-one security agent daemon — v0.1.0\n'));
}
