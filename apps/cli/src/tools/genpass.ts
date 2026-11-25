/**
 * Perfect Passwords — cryptographically strong random strings.
 *
 * An independent re-implementation of the idea behind GRC's Perfect Passwords
 * page (not affiliated with GRC): generate high-entropy random strings for keys,
 * passwords and salts. Uses a CSPRNG with rejection sampling so every character
 * is uniformly distributed (no modulo bias). The RNG is injectable for tests;
 * the default is Node's crypto.
 */

import { randomBytes } from 'node:crypto';

export const CHARSETS = {
  hex: '0123456789abcdef',
  alnum: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  // printable ASCII minus space and quotes/backslash that break shells/JSON
  ascii: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<=>?@[]^_{|}~',
  base58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
} as const;

export type CharsetName = keyof typeof CHARSETS;

export type RandomSource = (n: number) => Uint8Array;

const defaultRandom: RandomSource = (n) => new Uint8Array(randomBytes(n));

/**
 * Generate `length` characters drawn uniformly from `alphabet` using rejection
 * sampling (reject bytes in the biased tail so each symbol is equally likely).
 */
export function generatePassword(length: number, alphabet: string, random: RandomSource = defaultRandom): string {
  if (length <= 0) return '';
  const chars = [...new Set([...alphabet])];
  const n = chars.length;
  if (n < 2) throw new Error('alphabet must have at least 2 distinct characters');
  // Largest multiple of n that fits in a byte; bytes >= limit are rejected.
  const limit = 256 - (256 % n);
  let out = '';
  while (out.length < length) {
    const need = length - out.length;
    const buf = random(need * 2); // over-draw to cover rejections
    for (let i = 0; i < buf.length && out.length < length; i++) {
      const b = buf[i];
      if (b < limit) out += chars[b % n];
    }
  }
  return out;
}

export interface PasswordSet {
  hex64: string;
  alnum63: string;
  ascii63: string;
}

/** The three strings GRC's page hands you each load, our charset equivalents. */
export function perfectSet(random: RandomSource = defaultRandom): PasswordSet {
  return {
    hex64: generatePassword(64, CHARSETS.hex, random),
    alnum63: generatePassword(63, CHARSETS.alnum, random),
    ascii63: generatePassword(63, CHARSETS.ascii, random),
  };
}
