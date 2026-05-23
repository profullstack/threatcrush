"use client";

export const E2E_SECRET_PREFIX = "tc_e2e_secret_v1:";

const KEY_STORAGE_PREFIX = "tc_secret_key_v1:";
const AAD_PREFIX = "threatcrush:settings-secret:v1:";

type SecretEnvelope = {
  v: 1;
  alg: "AES-GCM";
  iv: string;
  ciphertext: string;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function storageKey(userId: string) {
  return `${KEY_STORAGE_PREFIX}${userId}`;
}

function assertWebCrypto() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("Browser encryption is unavailable in this environment");
  }
}

function getRawKey(userId: string, create: boolean): Uint8Array {
  const keyName = storageKey(userId);
  const existing = window.localStorage.getItem(keyName);
  if (existing) return base64UrlDecode(existing);
  if (!create) {
    throw new Error("This secret was encrypted in another browser. Save it again here to reveal it on this device.");
  }

  const raw = new Uint8Array(32);
  globalThis.crypto.getRandomValues(raw);
  window.localStorage.setItem(keyName, base64UrlEncode(raw));
  return raw;
}

async function importSecretKey(userId: string, usages: KeyUsage[], create: boolean): Promise<CryptoKey> {
  assertWebCrypto();
  return globalThis.crypto.subtle.importKey(
    "raw",
    toArrayBuffer(getRawKey(userId, create)),
    "AES-GCM",
    false,
    usages,
  );
}

function aad(userId: string) {
  return encoder.encode(`${AAD_PREFIX}${userId}`);
}

export function isE2ESecret(value: string | null | undefined): value is string {
  return typeof value === "string" && value.startsWith(E2E_SECRET_PREFIX);
}

export async function encryptClientSecret(userId: string, value: string): Promise<string> {
  const key = await importSecretKey(userId, ["encrypt"], true);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv), additionalData: toArrayBuffer(aad(userId)) },
    key,
    toArrayBuffer(encoder.encode(value)),
  );

  const envelope: SecretEnvelope = {
    v: 1,
    alg: "AES-GCM",
    iv: base64UrlEncode(iv),
    ciphertext: base64UrlEncode(new Uint8Array(ciphertext)),
  };

  return `${E2E_SECRET_PREFIX}${base64UrlEncode(encoder.encode(JSON.stringify(envelope)))}`;
}

export async function decryptClientSecret(userId: string, value: string): Promise<string> {
  if (!isE2ESecret(value)) return value;

  const rawEnvelope = decoder.decode(base64UrlDecode(value.slice(E2E_SECRET_PREFIX.length)));
  const envelope = JSON.parse(rawEnvelope) as SecretEnvelope;
  if (envelope.v !== 1 || envelope.alg !== "AES-GCM") {
    throw new Error("Unsupported encrypted secret format");
  }

  const key = await importSecretKey(userId, ["decrypt"], false);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await globalThis.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(base64UrlDecode(envelope.iv)),
        additionalData: toArrayBuffer(aad(userId)),
      },
      key,
      toArrayBuffer(base64UrlDecode(envelope.ciphertext)),
    );
  } catch {
    throw new Error("Could not decrypt this secret in this browser. Save it again here to reveal it on this device.");
  }

  return decoder.decode(plaintext);
}
