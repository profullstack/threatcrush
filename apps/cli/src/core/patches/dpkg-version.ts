/**
 * Debian package version ordering, as `dpkg --compare-versions` does it
 * (deb-version(7)): `[epoch:]upstream[-revision]`, where `~` sorts before
 * everything, even the end of the string, and letters sort before non-letters.
 *
 * Needed because OSV's Debian and Ubuntu ranges are dpkg versions, and a semver
 * or plain string compare gets `1:2.0` vs `3.0` and `1.0~rc1` vs `1.0` wrong.
 */

interface Parsed { epoch: number; upstream: string; revision: string }

function parse(version: string): Parsed {
  let rest = version.trim();
  let epoch = 0;
  const colon = rest.indexOf(':');
  if (colon > 0 && /^\d+$/.test(rest.slice(0, colon))) {
    epoch = Number(rest.slice(0, colon));
    rest = rest.slice(colon + 1);
  }
  const dash = rest.lastIndexOf('-');
  return dash >= 0
    ? { epoch, upstream: rest.slice(0, dash), revision: rest.slice(dash + 1) }
    : { epoch, upstream: rest, revision: '' };
}

function order(ch: string | undefined): number {
  if (ch === undefined) return 0;
  if (ch === '~') return -1;
  if (/[A-Za-z]/.test(ch)) return ch.charCodeAt(0);
  return ch.charCodeAt(0) + 256;
}

/** dpkg's verrevcmp: alternate non-digit and digit runs. */
function compareFragment(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    let firstDiff = 0;
    while ((i < a.length && !/\d/.test(a[i])) || (j < b.length && !/\d/.test(b[j]))) {
      const ac = i < a.length && !/\d/.test(a[i]) ? a[i] : undefined;
      const bc = j < b.length && !/\d/.test(b[j]) ? b[j] : undefined;
      const diff = order(ac) - order(bc);
      if (diff !== 0) return diff;
      i++;
      j++;
    }
    while (a[i] === '0') i++;
    while (b[j] === '0') j++;
    while (i < a.length && /\d/.test(a[i]) && j < b.length && /\d/.test(b[j])) {
      if (!firstDiff) firstDiff = a.charCodeAt(i) - b.charCodeAt(j);
      i++;
      j++;
    }
    if (i < a.length && /\d/.test(a[i])) return 1;
    if (j < b.length && /\d/.test(b[j])) return -1;
    if (firstDiff) return firstDiff;
  }
  return 0;
}

/** Negative when `a` is older than `b`, zero when equal, positive when newer. */
export function compareDebianVersions(a: string, b: string): number {
  const x = parse(a);
  const y = parse(b);
  if (x.epoch !== y.epoch) return x.epoch - y.epoch;
  return compareFragment(x.upstream, y.upstream) || compareFragment(x.revision, y.revision);
}
