import { describe, expect, it } from 'vitest';
import { copyToClipboard, describeCopy, nativeHelpers, type ClipboardDeps } from '../clipboard.js';

function fakeDeps(env: NodeJS.ProcessEnv, works: string[] = [], platform: NodeJS.Platform = 'linux') {
  const ran: string[] = [];
  const written: string[] = [];
  const files: Record<string, string> = {};
  const deps: ClipboardDeps = {
    env,
    platform,
    run: (cmd, args) => {
      ran.push([cmd, ...args].join(' '));
      return works.includes(cmd) && !(cmd === 'tmux' && args.includes('-w') && works.includes('old-tmux'));
    },
    write: (d) => { written.push(d); },
    saveFile: (p, t) => { files[p] = t; },
    fileDir: '/home/op/.threatcrush',
  };
  return { deps, ran, written, files };
}

const b64 = (s: string) => Buffer.from(s).toString('base64');

describe('copyToClipboard', () => {
  it('over plain ssh (no display, no tmux) sends raw OSC 52 and saves a file', () => {
    const { deps, ran, written, files } = fakeDeps({ SSH_CONNECTION: '1 2 3 4' });
    const r = copyToClipboard('ban failed: EROFS', deps);
    expect(ran).toEqual([]);
    expect(written).toEqual([`\x1b]52;c;${b64('ban failed: EROFS')}\x07`]);
    expect(r.via).toEqual(['osc52']);
    expect(files['/home/op/.threatcrush/last-copy.txt']).toBe('ban failed: EROFS\n');
  });

  it('inside tmux fills the tmux buffer and sends both raw and wrapped OSC 52', () => {
    const { deps, ran, written } = fakeDeps({ TMUX: '/tmp/tmux-1/default,1,0' }, ['tmux']);
    const r = copyToClipboard('x', deps);
    expect(ran).toEqual(['tmux load-buffer -w -']);
    expect(written).toHaveLength(2);
    expect(written[0].startsWith('\x1b]52;c;')).toBe(true);
    expect(written[1].startsWith('\x1bPtmux;')).toBe(true);
    expect(r.via).toEqual(['tmux', 'osc52']);
  });

  it('falls back to load-buffer without -w on old tmux', () => {
    const { deps, ran } = fakeDeps({ TMUX: 't' }, ['tmux', 'old-tmux']);
    expect(copyToClipboard('x', deps).via).toContain('tmux');
    expect(ran).toEqual(['tmux load-buffer -w -', 'tmux load-buffer -']);
  });

  it('uses the first native helper that works when there is a display', () => {
    const { deps, ran } = fakeDeps({ DISPLAY: ':0' }, ['xsel']);
    const r = copyToClipboard('x', deps);
    expect(ran).toEqual(['xclip -selection clipboard', 'xsel --clipboard --input']);
    expect(r.via).toEqual(['xsel', 'osc52']);
  });

  it('never uses pbcopy over ssh: that is the server pasteboard', () => {
    expect(nativeHelpers({ SSH_TTY: '/dev/pts/1' }, 'darwin')).toEqual([]);
    expect(nativeHelpers({}, 'darwin')[0][0]).toBe('pbcopy');
  });
});

describe('describeCopy', () => {
  it('names the native route when one worked', () => {
    expect(describeCopy({ via: ['xclip', 'osc52'], file: '/h/.threatcrush/last-copy.txt' }, '/h'))
      .toBe('copied (xclip + osc52) · also ~/.threatcrush/last-copy.txt');
  });

  it('does not claim success for OSC 52 alone, and names the iTerm2 setting', () => {
    const line = describeCopy({ via: ['osc52'], file: '/h/.threatcrush/last-copy.txt' }, '/h');
    expect(line).toContain('OSC 52');
    expect(line).toContain('iTerm2');
    expect(line).toContain('~/.threatcrush/last-copy.txt');
  });
});
