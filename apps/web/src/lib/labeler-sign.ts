import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";

/**
 * Signed labels for c0mpute DIP-0036 ("Layer moderation").
 *
 * A label is a statement by this labeler about one subject. The signature is
 * ed25519 over a line-based canonical string, chosen so a Rust verifier can
 * rebuild it byte for byte without a JSON canonicalisation library:
 *
 *   c0mpute-label-v1\n<src>\n<uri>\n<val>\n<0|1>\n<cts>\n<exp>
 *
 * No field may contain a newline or any other control character, so the
 * framing is unambiguous. `cts`/`exp` are RFC 3339 UTC with second precision.
 */

export const LABEL_DOMAIN = "c0mpute-label-v1";
export const LABELER_DID = "did:web:threatcrush.com";

export type LabelValue = "malware" | "phishing" | "cryptominer" | "spam";
export const LABEL_VALUES: readonly LabelValue[] = ["malware", "phishing", "cryptominer", "spam"];

export interface Label {
  kind: "label";
  ver: 1;
  src: string;
  uri: string;
  val: LabelValue;
  neg: boolean;
  cts: string;
  exp: string;
  evidence?: string;
  /** base64url ed25519 signature over canonicalLabel(). */
  sig: string;
}

export type UnsignedLabel = Omit<Label, "sig" | "kind" | "ver">;

const SAFE = /^[\x21-\x7e]+$/; // printable ASCII, no spaces or controls
const TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
/** Subjects this labeler issues: a file by SHA-256. */
export const SHA256_URI = /^sha256:[0-9a-f]{64}$/;

export function isoSeconds(ms: number): string {
  return new Date(Math.floor(ms / 1000) * 1000).toISOString().replace(".000Z", "Z");
}

export function canonicalLabel(l: Pick<Label, "src" | "uri" | "val" | "neg" | "cts" | "exp">): string {
  for (const [k, v] of [["src", l.src], ["uri", l.uri], ["val", l.val]] as const) {
    if (typeof v !== "string" || v.length === 0 || v.length > 600 || !SAFE.test(v)) throw new Error(`label ${k} is not printable ASCII`);
  }
  if (!TS.test(l.cts) || !TS.test(l.exp)) throw new Error("label cts/exp must be RFC 3339 UTC seconds");
  return [LABEL_DOMAIN, l.src, l.uri, l.val, l.neg ? "1" : "0", l.cts, l.exp].join("\n");
}

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** The signing key from a 32-byte hex seed, read at request time (Next inlines literal env reads). */
export function labelerKey(env: NodeJS.ProcessEnv = process.env): KeyObject | null {
  const name = "THREATCRUSH_LABELER_SEED";
  const seed = (env[name] ?? "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(seed)) return null;
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seed, "hex")]), format: "der", type: "pkcs8" });
}

/** Raw 32-byte public key, base64url. */
export function publicKeyB64(key: KeyObject): string {
  const der = createPublicKey(key).export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(der.length - 32)).toString("base64url");
}

export function signLabel(u: UnsignedLabel, key: KeyObject): Label {
  const sig = edSign(null, Buffer.from(canonicalLabel(u), "utf8"), key).toString("base64url");
  const out: Label = { kind: "label", ver: 1, src: u.src, uri: u.uri, val: u.val, neg: u.neg, cts: u.cts, exp: u.exp, sig };
  if (u.evidence) out.evidence = u.evidence;
  return out;
}

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Verify with a raw base64url public key. Never throws; false on anything malformed. */
export function verifyLabel(l: Label, publicKey: string): boolean {
  try {
    const raw = Buffer.from(publicKey, "base64url");
    const sig = Buffer.from(l.sig, "base64url");
    if (raw.length !== 32 || sig.length !== 64) return false;
    const pub = createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });
    return edVerify(null, Buffer.from(canonicalLabel(l), "utf8"), pub, sig);
  } catch {
    return false;
  }
}
