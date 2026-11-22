/**
 * Links from a finding to the write-up of the attack it is evidence of.
 *
 * The `attack-vectors/` collection at the repository root holds one markdown
 * entry per technique seen against a real fleet: the chain, the indicators of
 * compromise, and which rule here catches it. A finding that carries the link
 * lets an operator read *why* the construct matters, not only that it matched.
 */

export const ATTACK_VECTORS_BASE = 'https://github.com/profullstack/threatcrush/blob/master/attack-vectors/';

/** Every entry in `attack-vectors/`, by slug. A test pins that each file exists. */
export const ATTACK_VECTOR_SLUGS = [
  'github-app-installation-idor',
  'unrotated-github-app-keys',
  'ci-forced-command-compose',
  'sftp-jail-reads-root',
  'planted-authorized-keys',
] as const;

export type AttackVectorSlug = (typeof ATTACK_VECTOR_SLUGS)[number];

export function attackVector(slug: AttackVectorSlug): string {
  return `${ATTACK_VECTORS_BASE}${slug}.md`;
}
