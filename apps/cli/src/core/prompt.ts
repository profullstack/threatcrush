import readline from 'node:readline';
import { Writable } from 'node:stream';

/** Is there a person at a terminal to answer questions? `</dev/null`, pipes and CI are not. */
export function stdinIsInteractive(): boolean {
  return Boolean(process.stdin.isTTY);
}

/**
 * One reader for the whole run when stdin is a pipe or file.
 *
 * A readline interface per question loses input: the first one reads the whole
 * chunk (`email\npassword\n`), answers its question, and the rest goes with it
 * when it closes. So piped answers are queued here and handed out in order.
 */
interface PipedReader {
  rl: readline.Interface;
  lines: string[];
  waiting: ((line: string | null) => void) | null;
  ended: boolean;
}

let piped: PipedReader | null = null;

function pipedReader(): PipedReader {
  if (piped) return piped;
  const rl = readline.createInterface({ input: process.stdin, terminal: false });
  const reader: PipedReader = { rl, lines: [], waiting: null, ended: false };
  rl.on('line', (line) => {
    const waiting = reader.waiting;
    if (waiting) {
      reader.waiting = null;
      waiting(line);
    } else {
      reader.lines.push(line);
    }
  });
  rl.on('close', () => {
    reader.ended = true;
    const waiting = reader.waiting;
    reader.waiting = null;
    waiting?.(null);
  });
  piped = reader;
  return reader;
}

function askPiped(question: string, mask: boolean): Promise<string | null> {
  process.stdout.write(question);
  const reader = pipedReader();
  const settle = (line: string | null): string | null => {
    // Nothing is echoed from a pipe, so end the prompt line ourselves. A paused
    // stdin also lets the process exit once the command is done.
    if (mask || line === null) process.stdout.write('\n');
    if (!reader.ended) reader.rl.pause();
    return line;
  };
  if (reader.lines.length > 0) return Promise.resolve(settle(reader.lines.shift()!));
  if (reader.ended) return Promise.resolve(settle(null));
  reader.rl.resume();
  return new Promise((resolve) => {
    reader.waiting = (line) => resolve(settle(line));
  });
}

function askTerminal(question: string, mask: boolean): Promise<string | null> {
  const output = mask ? new Writable({ write(_chunk, _enc, cb) { cb(); } }) : process.stdout;
  const rl = readline.createInterface({ input: process.stdin, output, terminal: true });
  return new Promise((resolve) => {
    let settled = false;
    // Ctrl-D closes the interface without ever calling the question callback.
    rl.on('close', () => {
      if (settled) return;
      settled = true;
      process.stdout.write('\n');
      resolve(null);
    });
    if (mask) process.stdout.write(question);
    rl.question(mask ? '' : question, (answer) => {
      settled = true;
      rl.close();
      if (mask) process.stdout.write('\n');
      resolve(answer);
    });
  });
}

/**
 * Ask one question. Resolves to `null` when stdin ends before an answer comes:
 * `rl.question` alone never settles then, so the event loop drains and the
 * process exits 0 with the prompt still on screen and nothing done.
 */
export function ask(question: string, opts: { mask?: boolean } = {}): Promise<string | null> {
  const mask = opts.mask ?? false;
  return stdinIsInteractive() ? askTerminal(question, mask) : askPiped(question, mask);
}
