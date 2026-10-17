import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { clipboardSequence } from '@profullstack/hqtui';

/**
 * Put text on the operator's clipboard from inside the dashboard.
 *
 * OSC 52 alone was not enough (2026-10-07: `y` "did nothing"). The sequence
 * only works when every hop agrees: iTerm2 drops it unless "Applications in
 * terminal may access clipboard" is on, and tmux drops the DCS-wrapped form
 * unless `allow-passthrough` is on (off by default since 3.3). So copy goes
 * every way that can work and reports which ones it used:
 *
 *   1. a native helper when there is a display to own a clipboard
 *      (pbcopy locally, wl-copy, xclip, xsel), the only route that cannot be
 *      silently refused;
 *   2. tmux's own buffer (`load-buffer -w` also forwards to the outer terminal);
 *   3. OSC 52 to the terminal, raw and (in tmux) wrapped, which is what reaches
 *      a laptop over ssh/mosh/hqsh;
 *   4. a file, so the text is never lost when the terminal refuses.
 */

export interface ClipboardDeps {
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
  /** Runs a helper with `input` on stdin; true when it exited 0. */
  run: (cmd: string, args: string[], input: string) => boolean;
  write: (data: string) => void;
  saveFile: (path: string, text: string) => void;
  fileDir: string;
}

export interface CopyResult {
  /** Routes that accepted the text, e.g. ['xclip', 'osc52']. */
  via: string[];
  /** Where the text was also saved, if it was. */
  file?: string;
}

const defaultDeps = (): ClipboardDeps => ({
  env: process.env,
  platform: process.platform,
  run: (cmd, args, input) => {
    try {
      const r = spawnSync(cmd, args, { input, stdio: ['pipe', 'ignore', 'ignore'], timeout: 1500 });
      return !r.error && r.status === 0;
    } catch {
      return false;
    }
  },
  write: (data) => { process.stdout.write(data); },
  saveFile: (path, text) => {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text, { mode: 0o600 });
  },
  fileDir: join(homedir(), '.threatcrush'),
});

/** Native helpers worth trying for this environment, best first. */
export function nativeHelpers(env: NodeJS.ProcessEnv, platform: NodeJS.Platform): Array<[string, string[]]> {
  const overSsh = !!(env.SSH_CONNECTION || env.SSH_TTY);
  const helpers: Array<[string, string[]]> = [];
  // pbcopy over ssh writes the *server's* pasteboard, not the operator's.
  if (platform === 'darwin' && !overSsh) helpers.push(['pbcopy', []]);
  if (env.WAYLAND_DISPLAY) helpers.push(['wl-copy', []]);
  // DISPLAY over ssh means X forwarding, which does reach the operator.
  if (env.DISPLAY) {
    helpers.push(['xclip', ['-selection', 'clipboard']]);
    helpers.push(['xsel', ['--clipboard', '--input']]);
  }
  return helpers;
}

export function copyToClipboard(text: string, deps: ClipboardDeps = defaultDeps()): CopyResult {
  const via: string[] = [];
  const { env } = deps;

  for (const [cmd, args] of nativeHelpers(env, deps.platform)) {
    if (deps.run(cmd, args, text)) {
      via.push(cmd);
      break;
    }
  }

  if (env.TMUX) {
    // -w (tmux 3.2+) also sets the outer terminal's clipboard; older tmux
    // rejects the flag, so fall back to filling the buffer alone.
    if (deps.run('tmux', ['load-buffer', '-w', '-'], text) || deps.run('tmux', ['load-buffer', '-'], text)) {
      via.push('tmux');
    }
  }

  // Always offer OSC 52: a helper on the server cannot reach a laptop on the
  // other end of ssh, and the terminal ignores what it refuses. Inside tmux
  // send both forms: raw is handled by `set-clipboard on`, the wrapped one by
  // `allow-passthrough on`.
  try {
    deps.write(clipboardSequence(text));
    if (env.TMUX) deps.write(clipboardSequence(text, true));
    via.push('osc52');
  } catch {
    // Over the OSC 52 size limit; the helpers and the file still have it.
  }

  let file: string | undefined;
  try {
    const path = join(deps.fileDir, 'last-copy.txt');
    deps.saveFile(path, text.endsWith('\n') ? text : `${text}\n`);
    file = path;
  } catch {
    // Read-only home: nothing else to do.
  }

  return { via, file };
}

/** One status-bar line saying where the text went. */
export function describeCopy(result: CopyResult, home = homedir()): string {
  const file = result.file ? result.file.replace(home, '~') : null;
  const native = result.via.filter((v) => v !== 'osc52');
  if (native.length > 0) {
    return `copied (${result.via.join(' + ')})${file ? ` · also ${file}` : ''}`;
  }
  if (result.via.includes('osc52')) {
    // OSC 52 cannot be confirmed: the terminal never answers. Say so, and
    // name the setting that blocks it most often.
    return `sent to terminal clipboard (OSC 52; iTerm2: allow clipboard access)${file ? ` · saved ${file}` : ''}`;
  }
  return file ? `could not reach a clipboard · saved ${file}` : 'copy failed: no clipboard available';
}
