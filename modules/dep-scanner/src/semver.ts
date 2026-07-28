/**
 * Just enough semver to match advisories, with no dependency.
 *
 * A dependency scanner that drags in a dependency tree of its own is a poor
 * advertisement for itself, so this module ships zero runtime dependencies
 * (matching `spend-guard`). That is affordable here because OSV does not use
 * npm range syntax: an advisory's affected set is expressed as ordered
 * `introduced` / `fixed` **events** over concrete versions, so matching needs
 * version *comparison*, not a full range grammar. `^1.2.x` never has to be
 * parsed.
 *
 * Precedence follows semver 2.0.0 §11, including the parts people get wrong:
 * numeric prerelease identifiers compare numerically, alphanumeric ones
 * compare as ASCII, numeric sorts below alphanumeric, a larger set of
 * identifiers wins ties, and a prerelease always sorts *below* its release.
 * That last rule is the one that matters most in practice — `1.0.0-rc.1` is
 * vulnerable when the advisory says "introduced in 1.0.0" is not yet true.
 */

export interface ParsedVersion {
  major: number;
  minor: number;
  patch: number;
  /** Dot-separated prerelease identifiers; empty for a release. */
  prerelease: readonly (string | number)[];
}

const VERSION = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

/**
 * Parse a version, or return null if it is not semver-shaped.
 *
 * Returning null rather than throwing is deliberate: ecosystems carry
 * non-semver versions (Debian epochs, Go pseudo-versions, `latest`), and a
 * scanner must degrade to "cannot compare" instead of crashing a scan.
 */
export function parseVersion(input: string): ParsedVersion | null {
  const match = VERSION.exec(input.trim());
  if (!match) return null;

  const [, major, minor, patch, prerelease] = match;
  return {
    major: Number(major),
    minor: Number(minor ?? 0),
    patch: Number(patch ?? 0),
    prerelease: prerelease
      ? prerelease.split('.').map((id) => (/^\d+$/.test(id) ? Number(id) : id))
      : [],
  };
}

/** -1, 0 or 1. Non-parseable versions sort last and never compare equal. */
export function compareVersions(a: string, b: string): number {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (!left || !right) return left ? -1 : right ? 1 : 0;

  for (const key of ['major', 'minor', 'patch'] as const) {
    if (left[key] !== right[key]) return left[key] < right[key] ? -1 : 1;
  }

  // A release outranks any of its prereleases.
  if (left.prerelease.length === 0 && right.prerelease.length === 0) return 0;
  if (left.prerelease.length === 0) return 1;
  if (right.prerelease.length === 0) return -1;

  return comparePrerelease(left.prerelease, right.prerelease);
}

function comparePrerelease(
  a: readonly (string | number)[],
  b: readonly (string | number)[],
): number {
  const length = Math.max(a.length, b.length);

  for (let i = 0; i < length; i += 1) {
    // A larger set of identifiers wins when all preceding ones are equal.
    if (i >= a.length) return -1;
    if (i >= b.length) return 1;

    const left = a[i]!;
    const right = b[i]!;
    if (left === right) continue;

    const leftNumeric = typeof left === 'number';
    const rightNumeric = typeof right === 'number';
    // Numeric identifiers always sort below alphanumeric ones.
    if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
    if (leftNumeric && rightNumeric) return left < right ? -1 : 1;
    return String(left) < String(right) ? -1 : 1;
  }

  return 0;
}

/** One OSV range event: a version where vulnerability starts or stops. */
export interface RangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
}

export interface OsvRange {
  type?: string;
  events?: RangeEvent[];
}

/**
 * Is `version` inside an OSV range?
 *
 * OSV semantics: events are ordered checkpoints along the version line.
 * `introduced` opens an affected interval, `fixed` closes it exclusively, and
 * `last_affected` closes it inclusively. `introduced: "0"` means "from the
 * beginning", which is the common case for advisories with no known-good
 * ancestor.
 *
 * Unsorted event lists are tolerated by sorting first — OSV records in the
 * wild are not reliably ordered, and reading them positionally produces
 * silent false negatives, which is the failure this module exists to avoid.
 */
export function isVersionAffected(version: string, range: OsvRange): boolean {
  const events = range.events ?? [];
  if (events.length === 0) return false;

  const points = events
    .map((event) => {
      const at = event.introduced ?? event.fixed ?? event.last_affected ?? '';
      return { event, at };
    })
    // "0" is the sentinel lower bound and must sort before every real version.
    .sort((x, y) => (x.at === '0' ? -1 : y.at === '0' ? 1 : compareVersions(x.at, y.at)));

  let affected = false;
  for (const { event, at } of points) {
    if (event.introduced !== undefined) {
      if (at === '0' || compareVersions(version, at) >= 0) affected = true;
      continue;
    }
    if (event.fixed !== undefined && compareVersions(version, at) >= 0) {
      affected = false;
      continue;
    }
    if (event.last_affected !== undefined && compareVersions(version, at) > 0) {
      affected = false;
    }
  }

  return affected;
}

/**
 * The lowest fixed version at or above `version`, if the advisory names one.
 *
 * A finding without a remediation path is an interrupt rather than
 * information (PRD 0002 R8), so this is what turns an advisory into an action.
 */
export function fixedVersionFor(version: string, ranges: readonly OsvRange[]): string | null {
  const fixes = ranges
    .flatMap((range) => range.events ?? [])
    .map((event) => event.fixed)
    .filter((fixed): fixed is string => Boolean(fixed))
    .filter((fixed) => compareVersions(fixed, version) > 0)
    .sort(compareVersions);

  return fixes[0] ?? null;
}
