/**
 * TLS certificate fingerprint reader (server side).
 *
 * Independent re-implementation of the idea behind GRC's Fingerprints page (not
 * affiliated). Reads the certificate a public host presents so a visitor can
 * compare it to what their own browser sees (MITM/interception detection).
 *
 * Safety: refuses private/loopback/link-local hosts so it cannot be turned into
 * an internal network probe.
 */

import tls from "node:tls";
import net from "node:net";

export interface FingerprintResult {
  host: string;
  port: number;
  sha256: string;
  sha1: string;
  subjectCN?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  serialNumber?: string;
  san?: string;
}

export function isForbiddenHost(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "localhost" || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (net.isIP(h)) {
    const p = h.split(".").map(Number);
    if (p[0] === 10 || p[0] === 127 || p[0] === 0) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 169 && p[1] === 254) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (h.includes(":")) return true; // skip IPv6 literals for the public check
  }
  return false;
}

export function cleanHost(input: string): string {
  return input.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
}

export async function getFingerprint(host: string, port = 443, timeoutMs = 8000): Promise<FingerprintResult> {
  return new Promise<FingerprintResult>((resolve, reject) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate(true);
      socket.destroy();
      if (!cert || Object.keys(cert).length === 0) return reject(new Error("no certificate presented"));
      const subject = cert.subject as { CN?: string } | undefined;
      const issuer = cert.issuer as { O?: string; CN?: string } | undefined;
      resolve({
        host, port,
        sha256: cert.fingerprint256 ?? "",
        sha1: cert.fingerprint ?? "",
        subjectCN: subject?.CN,
        issuer: issuer?.O ?? issuer?.CN,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        serialNumber: cert.serialNumber,
        san: cert.subjectaltname,
      });
    });
    socket.setTimeout(timeoutMs, () => { socket.destroy(); reject(new Error("TLS connection timed out")); });
    socket.on("error", (err) => { socket.destroy(); reject(err); });
  });
}
