import { generateKeyPairSync, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { findSecret, isEd25519Keypair, secretKindIn } from "../secret-guard";
import { IncidentError, mergeReport, parseIncidentReport } from "../report";
import { BIP39_ENGLISH } from "../bip39-english";

/** A PEM private-key header, assembled at runtime so no fixture in the repo looks like a key. */
const pem = (kind: string) => ["-----BEGIN", `${kind}PRIVATE`, "KEY-----"].join(" ").replace("BEGIN  ", "BEGIN ");

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function b58(bytes: Uint8Array): string {
  let n = BigInt(`0x${Buffer.from(bytes).toString("hex") || "0"}`);
  let out = "";
  const ZERO = BigInt(0), BASE = BigInt(58);
  while (n > ZERO) { out = B58[Number(n % BASE)] + out; n /= BASE; }
  for (const b of bytes) { if (b !== 0) break; out = `1${out}`; }
  return out;
}

/** A fresh, throwaway Solana-style keypair: seed || pubkey. Generated per run, never a real wallet. */
function fixtureKeypair(): Uint8Array {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const d = Buffer.from(privateKey.export({ format: "jwk" }).d!, "base64url");
  const x = Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url");
  return new Uint8Array(Buffer.concat([d, x]));
}

const base = () => ({
  title: "Wallet drained", severity: "critical", source: "investigate", dedupe_key: "investigate:sol:abc",
  summary: "Sweep after a new SSH key.", report_version: 1,
  findings: [{ id: "f1", module: "chain", severity: "critical", title: "Full-balance sweep", evidence: "evidence", at: "2026-10-28T04:56:00Z" }],
  timeline: [{ at: "2026-10-28T04:56:00Z", module: "chain", summary: "wallet swept", evidence: true, ref: "sol:tx:5abc" }],
  recommendations: [{ action: "Rotate the key", target: "deploy key", priority: "now" }],
});

function refusal(body: unknown): IncidentError {
  try { parseIncidentReport(body); } catch (e) { return e as IncidentError; }
  throw new Error("expected a refusal");
}

describe("secret guard", () => {
  const kp = fixtureKeypair();
  const kpB58 = b58(kp);
  const mnemonic = Array.from({ length: 12 }, (_, i) => BIP39_ENGLISH[(i * 97 + 5) % 2048]).join(" ");
  const hexKey = `0x${randomBytes(32).toString("hex")}`;

  it("recognises a base58 Solana keypair but not a 64-byte signature or an address", () => {
    expect(isEd25519Keypair(kp)).toBe(true);
    expect(secretKindIn(`key ${kpB58} here`)).toBe("solana-keypair");
    expect(secretKindIn(b58(randomBytes(64)))).toBeNull(); // a signature-shaped blob
    expect(secretKindIn(b58(kp.subarray(32)))).toBeNull(); // the public address
  });

  it("recognises PEM, byte arrays, mnemonics and 0x hex keys; allows tx refs", () => {
    expect(secretKindIn(pem("OPENSSH "))).toBe("pem-private-key");
    expect(secretKindIn(JSON.stringify(Array.from(kp)))).toBe("byte-array-keypair");
    expect(findSecret({ a: Array.from(kp) })?.kind).toBe("byte-array-keypair");
    expect(secretKindIn(mnemonic)).toBe("mnemonic");
    expect(secretKindIn("new key installed then the wallet was swept to a collector address from three wallets")).toBeNull();
    expect(secretKindIn(hexKey)).toBe("hex-private-key");
    expect(findSecret({ timeline: [{ ref: `evm:tx:${hexKey}` }] })).toBeNull();
    expect(findSecret({ timeline: [{ summary: `evm:tx:${hexKey}` }] })?.kind).toBe("hex-private-key");
  });

  it("refuses a report carrying any of them with 422, and never echoes the value", () => {
    for (const secret of [kpB58, mnemonic, hexKey, JSON.stringify(Array.from(kp)), `${pem("")}\nMIIE`]) {
      const bodies = [
        { ...base(), summary: `found ${secret}` },
        { ...base(), findings: [{ ...base().findings[0], detail: secret }] },
        { ...base(), extra: { nested: [secret] } },
        { ...base(), [secret]: 1 },
      ];
      for (const body of bodies) {
        const e = refusal(body);
        expect(e.status).toBe(422);
        expect(e.message).not.toContain(secret);
        expect(e.message).not.toContain(secret.slice(0, 16));
      }
    }
  });
});

describe("parseIncidentReport", () => {
  it("accepts a valid report and sorts the timeline", () => {
    const r = parseIncidentReport({ ...base(), timeline: [base().timeline[0], { at: "2026-10-28T04:44:00Z", module: "host", summary: "new key", evidence: true }] });
    expect(r.timeline.map((t) => t.summary)).toEqual(["new key", "wallet swept"]);
    expect(r.team_id).toBeNull();
  });

  it("rejects bad shapes with 400", () => {
    expect(refusal({ ...base(), severity: "urgent" }).status).toBe(400);
    expect(refusal({ ...base(), source: "cron" }).status).toBe(400);
    expect(refusal({ ...base(), dedupe_key: "" }).status).toBe(400);
    expect(refusal({ ...base(), team_id: "nope" }).status).toBe(400);
    expect(refusal({ ...base(), findings: [{ ...base().findings[0], evidence: "maybe" }] }).status).toBe(400);
    expect(refusal({ ...base(), timeline: [{ at: "yesterday", module: "x", summary: "y", evidence: true }] }).status).toBe(400);
    expect(refusal({ ...base(), findings: Array.from({ length: 201 }, (_, i) => ({ ...base().findings[0], id: `f${i}` })) }).status).toBe(400);
  });

  it("merges a re-raise: findings by id, timeline deduped", () => {
    const first = parseIncidentReport(base());
    const again = parseIncidentReport({
      ...base(),
      findings: [{ ...base().findings[0], title: "Sweep (updated)" }, { id: "f2", module: "host", severity: "high", title: "New key", evidence: "evidence" }],
      timeline: [...base().timeline, { at: "2026-10-28T04:44:00Z", module: "host", summary: "new key", evidence: true }],
    });
    const m = mergeReport(first, again);
    expect(m.findings.map((f) => f.title)).toEqual(["Sweep (updated)", "New key"]);
    expect(m.timeline).toHaveLength(2);
    expect(m.timeline[0].summary).toBe("new key");
  });
});
