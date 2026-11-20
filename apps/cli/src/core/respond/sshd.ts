/**
 * `threatcrush respond sshd --lockdown`: two sshd drop-ins and the checks that
 * make them mean what they say.
 *
 * sshd takes the FIRST value it reads for most keywords, and a `Match` block
 * runs to the end of the configuration, swallowing every directive after it.
 * So the global settings go in a file that sorts first and the localhost Match
 * goes in a file that sorts last. Both lessons were learned by hand on
 * 2026-11-20.
 */

export const DROPIN_DIR = '/etc/ssh/sshd_config.d';
export const LOCKDOWN_FILE = '00-0-threatcrush-lockdown.conf';
export const ROOT_LOCALHOST_FILE = '99-threatcrush-root-localhost.conf';

/** The keywords lockdown sets, lower case as `sshd -T` prints them. */
export const LOCKDOWN_SETTINGS: Record<string, string> = {
  permitrootlogin: 'no',
  passwordauthentication: 'no',
  kbdinteractiveauthentication: 'no',
};

const SPELLING: Record<string, string> = {
  permitrootlogin: 'PermitRootLogin',
  passwordauthentication: 'PasswordAuthentication',
  kbdinteractiveauthentication: 'KbdInteractiveAuthentication',
  challengeresponseauthentication: 'ChallengeResponseAuthentication',
};

export function lockdownDropins(opts: { allowRootLocalhost: boolean }): Array<{ name: string; content: string }> {
  const header = '# Written by `threatcrush respond sshd --lockdown`.';
  const files = [{
    name: LOCKDOWN_FILE,
    content: [
      header,
      '# Sorts FIRST in sshd_config.d: sshd keeps the first value it reads for each keyword.',
      'PermitRootLogin no',
      'PasswordAuthentication no',
      'KbdInteractiveAuthentication no',
      '',
    ].join('\n'),
  }];
  if (opts.allowRootLocalhost) {
    files.push({
      name: ROOT_LOCALHOST_FILE,
      content: [
        header,
        '# Sorts LAST in sshd_config.d: a Match block swallows every directive after it.',
        '# Keep nothing below this block.',
        'Match Address 127.0.0.1,::1',
        '    PermitRootLogin prohibit-password',
        '',
      ].join('\n'),
    });
  }
  return files;
}

/** glob(3) order in the C locale, which is what sshd runs under. */
export function sortDropins(names: string[]): string[] {
  return [...names].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/** Keywords (lower case) set outside any Match block, with the first value each gets. */
export function globalSettings(text: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(\S+?)(?:\s*=\s*|\s+)(.*)$/.exec(line);
    const kw = (m ? m[1] : line).toLowerCase();
    if (kw === 'match') break;
    if (!out.has(kw)) out.set(kw, (m?.[2] ?? '').trim());
  }
  return out;
}

export function globalKeywords(text: string): Set<string> {
  return new Set(globalSettings(text).keys());
}

/** An earlier setting only defeats lockdown when its value differs from ours. */
function conflicts(kw: string, value: string): boolean {
  const want = LOCKDOWN_SETTINGS[kw] ?? (kw === 'challengeresponseauthentication' ? 'no' : undefined);
  return want !== undefined && value.toLowerCase() !== want;
}

export interface OrderingCheck {
  /** Problems that make lockdown ineffective; writing is refused. */
  blockers: string[];
  warnings: string[];
}

/**
 * Will our drop-ins actually win? `existing` maps every *.conf already in the
 * drop-in directory (excluding ours) to its content.
 */
export function checkOrdering(input: {
  mainConfig: string;
  dropinDir: string;
  existing: Record<string, string>;
  allowRootLocalhost: boolean;
}): OrderingCheck {
  const blockers: string[] = [];
  const warnings: string[] = [];
  const ours = new Set([LOCKDOWN_FILE, ROOT_LOCALHOST_FILE]);
  const others = Object.keys(input.existing).filter((n) => n.endsWith('.conf') && !ours.has(n));

  // 1. The main config must include the drop-in directory at all.
  const lines = input.mainConfig.split('\n');
  const dir = input.dropinDir.replace(/\/$/, '');
  const includeIdx = lines.findIndex((raw) => {
    const m = /^\s*include\s+(.+)$/i.exec(raw);
    return m !== null && m[1].split(/\s+/).some((p) => p.startsWith(`${dir}/`) || p === `${dir}/*.conf` || p.startsWith('sshd_config.d/'));
  });
  if (input.mainConfig.trim() && includeIdx === -1) {
    blockers.push(`sshd_config has no "Include ${dir}/*.conf": drop-ins would never be read`);
  }

  // 2. A setting before the Include in sshd_config wins over every drop-in.
  if (includeIdx > 0) {
    const before = globalSettings(lines.slice(0, includeIdx).join('\n'));
    for (const kw of Object.keys(LOCKDOWN_SETTINGS)) {
      const v = before.get(kw);
      if (v !== undefined && conflicts(kw, v)) blockers.push(`sshd_config sets ${SPELLING[kw]} ${v} above its Include line; that value wins over ${LOCKDOWN_FILE}`);
    }
  }

  // 3. A drop-in that sorts before ours and sets the same keyword wins.
  const watched = [...Object.keys(LOCKDOWN_SETTINGS), 'challengeresponseauthentication'];
  for (const name of sortDropins(others)) {
    if (name >= LOCKDOWN_FILE) break;
    const settings = globalSettings(input.existing[name]);
    for (const kw of watched) {
      const v = settings.get(kw);
      if (v !== undefined && conflicts(kw, v)) blockers.push(`${dir}/${name} sorts before ${LOCKDOWN_FILE} and sets ${SPELLING[kw] ?? kw} ${v}; it wins`);
    }
  }

  if (input.allowRootLocalhost) {
    // 4. Anything read after the Match file is swallowed by it.
    const after = sortDropins(others).filter((n) => n > ROOT_LOCALHOST_FILE);
    for (const name of after) blockers.push(`${dir}/${name} sorts after ${ROOT_LOCALHOST_FILE}; its directives would land inside the Match block`);
    if (includeIdx !== -1) {
      const tail = globalKeywords(lines.slice(includeIdx + 1).join('\n'));
      if (tail.size) {
        warnings.push(`sshd_config has directives after its Include line (${[...tail].slice(0, 6).join(', ')}${tail.size > 6 ? ', ...' : ''}); on OpenSSH versions where a Match in an included file stays open they fall inside it. sshd -t below decides.`);
      }
    }
  }
  return { blockers, warnings };
}

/** Selected keywords from `sshd -T` output (first value wins, as in sshd). */
export function effectiveValues(dumpT: string, keys = Object.keys(LOCKDOWN_SETTINGS)): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of dumpT.split('\n')) {
    const m = /^(\S+)\s+(.*)$/.exec(raw.trim());
    if (!m) continue;
    const k = m[1].toLowerCase();
    if (keys.includes(k) && !(k in out)) out[k] = m[2].trim();
  }
  return out;
}

/** Which effective values differ from what lockdown promises. */
export function lockdownMismatches(remote: Record<string, string>, local: Record<string, string> | null): string[] {
  const out: string[] = [];
  for (const [k, want] of Object.entries(LOCKDOWN_SETTINGS)) {
    if (remote[k] === undefined) continue;
    if (remote[k].toLowerCase() !== want) out.push(`${SPELLING[k]} is "${remote[k]}" for root from a remote address, expected "${want}"`);
  }
  if (local) {
    const v = (local.permitrootlogin ?? '').toLowerCase();
    // sshd -T prints prohibit-password under its old name.
    if (v && v !== 'prohibit-password' && v !== 'without-password') {
      out.push(`PermitRootLogin is "${local.permitrootlogin}" for root from 127.0.0.1, expected "prohibit-password"`);
    }
  }
  return out;
}
