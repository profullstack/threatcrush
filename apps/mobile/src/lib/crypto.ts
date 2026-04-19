/**
 * E2E Encryption stubs using tweetnacl.
 * Provides box (asymmetric) and secretbox (symmetric) wrappers.
 */

import nacl from 'tweetnacl';
import { decodeUTF8, encodeUTF8, encodeBase64, decodeBase64 } from 'tweetnacl-util';

export interface KeyPair {
  publicKey: string; // base64
  secretKey: string; // base64
}

/** Generate a new keypair for box encryption */
export function generateKeyPair(): KeyPair {
  const pair = nacl.box.keyPair();
  return {
    publicKey: encodeBase64(pair.publicKey),
    secretKey: encodeBase64(pair.secretKey),
  };
}

/** Encrypt a message with recipient's public key (box) */
export function boxEncrypt(
  message: string,
  recipientPublicKey: string,
  senderSecretKey: string,
): { encrypted: string; nonce: string } {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const msgBytes = decodeUTF8(message);
  const encrypted = nacl.box(
    msgBytes,
    nonce,
    decodeBase64(recipientPublicKey),
    decodeBase64(senderSecretKey),
  );
  if (!encrypted) throw new Error('Encryption failed');
  return {
    encrypted: encodeBase64(encrypted),
    nonce: encodeBase64(nonce),
  };
}

/** Decrypt a box-encrypted message */
export function boxDecrypt(
  encrypted: string,
  nonce: string,
  senderPublicKey: string,
  recipientSecretKey: string,
): string {
  const decrypted = nacl.box.open(
    decodeBase64(encrypted),
    decodeBase64(nonce),
    decodeBase64(senderPublicKey),
    decodeBase64(recipientSecretKey),
  );
  if (!decrypted) throw new Error('Decryption failed');
  return encodeUTF8(decrypted);
}

/** Generate a random secretbox key */
export function generateSecretKey(): string {
  return encodeBase64(nacl.randomBytes(nacl.secretbox.keyLength));
}

/** Encrypt with symmetric key (secretbox) */
export function secretboxEncrypt(
  message: string,
  key: string,
): { encrypted: string; nonce: string } {
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const encrypted = nacl.secretbox(decodeUTF8(message), nonce, decodeBase64(key));
  if (!encrypted) throw new Error('Encryption failed');
  return {
    encrypted: encodeBase64(encrypted),
    nonce: encodeBase64(nonce),
  };
}

/** Decrypt with symmetric key (secretbox) */
export function secretboxDecrypt(encrypted: string, nonce: string, key: string): string {
  const decrypted = nacl.secretbox.open(
    decodeBase64(encrypted),
    decodeBase64(nonce),
    decodeBase64(key),
  );
  if (!decrypted) throw new Error('Decryption failed');
  return encodeUTF8(decrypted);
}
