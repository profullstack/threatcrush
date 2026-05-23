import "server-only";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

export type CipherBlob = {
  ciphertext: string;
  iv: string;
  tag: string;
};

const AUTH_TAG_LENGTH = 16;

function getSettingsKey(): Buffer {
  const raw = process.env.SETTINGS_ENCRYPTION_KEY;
  if (!raw) {
    throw new Error("SETTINGS_ENCRYPTION_KEY is not configured");
  }

  const decoded = Buffer.from(raw, "base64");
  if (decoded.length === 32) return decoded;

  const utf8 = Buffer.from(raw, "utf8");
  if (utf8.length === 32) return utf8;

  throw new Error("SETTINGS_ENCRYPTION_KEY must be 32 bytes or base64-encoded 32 bytes");
}

export function settingsCryptoConfigured(): boolean {
  try {
    getSettingsKey();
    return true;
  } catch {
    return false;
  }
}

export function encryptSettingsSecret(secret: Record<string, string>): CipherBlob {
  const key = getSettingsKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv, { authTagLength: AUTH_TAG_LENGTH });
  const plaintext = Buffer.from(JSON.stringify(secret), "utf8");
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
  };
}

export function decryptSettingsSecret(blob: CipherBlob | null): Record<string, string> {
  if (!blob) return {};

  const key = getSettingsKey();
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(blob.iv, "base64"), {
    authTagLength: AUTH_TAG_LENGTH,
  });
  decipher.setAuthTag(Buffer.from(blob.tag, "base64"));

  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(blob.ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");

  const parsed = JSON.parse(plaintext) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};

  const out: Record<string, string> = {};
  for (const [keyName, value] of Object.entries(parsed as Record<string, unknown>)) {
    if (typeof value === "string") out[keyName] = value;
  }
  return out;
}
