import { createPrivateKey, createPublicKey } from "node:crypto";
import { BIP39_ENGLISH } from "./bip39-english";

/**
 * A backstop on everything raised as an incident: the CLI never sends secret
 * values, and if a bug ever made it try, the API refuses the whole report.
 * The answer names the kind and the field, never the value.
 *
 * Shapes refused:
 *   - PEM private keys
 *   - a Solana keypair in base58 (64 bytes whose second half is the ed25519
 *     public key of the first half; a 64-byte transaction signature is not)
 *   - a JSON array of 64 byte values (a Solana keypair file)
 *   - 12 or more BIP39 English words in a row (a mnemonic)
 *   - 0x + 64 hex (an EVM private key), except in a `ref` that names a
 *     transaction (`<chain>:tx:0x…`), where the same shape is a tx hash
 */

export interface SecretHit {
  kind: "pem-private-key" | "solana-keypair" | "byte-array-keypair" | "mnemonic" | "hex-private-key";
  path: string;
}

// threatcrush-disable-next-line secret-private-key
const PEM = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
const BYTE_ARRAY = /\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]/;
const HEX_KEY = /0x[0-9a-fA-F]{64}(?![0-9a-fA-F])/;
const TX_REF = /^[a-z0-9]+:tx:/i;
const B58_TOKEN = /[1-9A-HJ-NP-Za-km-z]{80,90}/g;
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const WORDS = new Set(BIP39_ENGLISH);
const MNEMONIC_RUN = 12;
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function base58Decode(s: string): Buffer | null {
  const ZERO = BigInt(0), BASE = BigInt(58), BYTE = BigInt(0xff), EIGHT = BigInt(8);
  let n = ZERO;
  for (const ch of s) {
    const v = B58_ALPHABET.indexOf(ch);
    if (v < 0) return null;
    n = n * BASE + BigInt(v);
  }
  const bytes: number[] = [];
  while (n > ZERO) {
    bytes.unshift(Number(n & BYTE));
    n >>= EIGHT;
  }
  for (const ch of s) {
    if (ch !== "1") break;
    bytes.unshift(0);
  }
  return Buffer.from(bytes);
}

/** True when 64 bytes are seed || ed25519_pub(seed): a Solana secret key. */
export function isEd25519Keypair(bytes: Uint8Array): boolean {
  if (bytes.length !== 64) return false;
  try {
    const priv = createPrivateKey({
      key: Buffer.concat([ED25519_PKCS8_PREFIX, Buffer.from(bytes.subarray(0, 32))]),
      format: "der",
      type: "pkcs8",
    });
    const x = createPublicKey(priv).export({ format: "jwk" }).x;
    return typeof x === "string" && Buffer.from(x, "base64url").equals(Buffer.from(bytes.subarray(32)));
  } catch {
    return false;
  }
}

function hasMnemonicRun(s: string): boolean {
  let run = 0;
  for (const token of s.split(/[\s,;]+/)) {
    if (token && WORDS.has(token)) {
      run++;
      if (run >= MNEMONIC_RUN) return true;
    } else if (token) {
      run = 0;
    }
  }
  return false;
}

/** The first secret-shaped thing in one string, or null. */
export function secretKindIn(value: string, opts: { txRef?: boolean } = {}): SecretHit["kind"] | null {
  if (PEM.test(value)) return "pem-private-key";
  if (BYTE_ARRAY.test(value)) return "byte-array-keypair";
  if (!(opts.txRef && TX_REF.test(value)) && HEX_KEY.test(value)) return "hex-private-key";
  for (const m of value.match(B58_TOKEN) ?? []) {
    const bytes = base58Decode(m);
    if (bytes && isEd25519Keypair(bytes)) return "solana-keypair";
  }
  if (hasMnemonicRun(value)) return "mnemonic";
  return null;
}

/** Walk any JSON value; the first secret-shaped string wins. Arrays of 64 bytes count too. */
export function findSecret(value: unknown, path = "body"): SecretHit | null {
  if (typeof value === "string") {
    const kind = secretKindIn(value, { txRef: /\.ref$/.test(path) });
    return kind ? { kind, path } : null;
  }
  if (Array.isArray(value)) {
    if (
      value.length === 64 &&
      value.every((v) => Number.isInteger(v) && (v as number) >= 0 && (v as number) <= 255)
    ) {
      return { kind: "byte-array-keypair", path };
    }
    for (let i = 0; i < value.length; i++) {
      const hit = findSecret(value[i], `${path}[${i}]`);
      if (hit) return hit;
    }
    return null;
  }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      // Keys are caller-controlled too: check them, and never echo an odd one.
      const keyPath = `${path}.${/^[A-Za-z_][A-Za-z0-9_]{0,39}$/.test(k) ? k : "<key>"}`;
      const keyKind = secretKindIn(k);
      if (keyKind) return { kind: keyKind, path: keyPath };
      const hit = findSecret(v, keyPath);
      if (hit) return hit;
    }
  }
  return null;
}
