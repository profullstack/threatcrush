/**
 * TLS Fingerprints — read the certificate a site presents and report its
 * fingerprint, so you can compare it to what your own browser sees.
 *
 * An independent re-implementation of the idea behind GRC's Fingerprints page
 * (not affiliated with GRC): if the fingerprint your browser sees differs from
 * the one a neutral vantage sees, something is intercepting your TLS (a
 * corporate proxy, antivirus MITM, or an attacker). Reading a public
 * certificate is a safe, read-only operation for any host.
 *
 * The TLS connection is injectable (`CertSource`) so the formatting/comparison
 * logic is pure and testable; the default source uses Node's tls module.
 */

import tls from 'node:tls';

export interface PeerCert {
  fingerprint256?: string;
  fingerprint?: string; // SHA-1
  subject?: { CN?: string } | Record<string, unknown>;
  issuer?: { O?: string; CN?: string } | Record<string, unknown>;
  valid_from?: string;
  valid_to?: string;
  serialNumber?: string;
  subjectaltname?: string;
}

export type CertSource = (host: string, port: number, timeoutMs: number) => Promise<PeerCert>;

/** Normalise a fingerprint for comparison: uppercase hex, no separators. */
export function normalizeFingerprint(fp: string): string {
  return fp.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
}

export function fingerprintsMatch(a: string, b: string): boolean {
  const na = normalizeFingerprint(a);
  const nb = normalizeFingerprint(b);
  return na.length > 0 && na === nb;
}

const nodeCertSource: CertSource = (host, port, timeoutMs) =>
  new Promise<PeerCert>((resolve, reject) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
      const cert = socket.getPeerCertificate(true) as unknown as PeerCert;
      socket.destroy();
      if (!cert || Object.keys(cert).length === 0) reject(new Error('no certificate presented'));
      else resolve(cert);
    });
    socket.setTimeout(timeoutMs, () => { socket.destroy(); reject(new Error('TLS connection timed out')); });
    socket.on('error', (err) => { socket.destroy(); reject(err); });
  });

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

export async function getFingerprint(
  host: string,
  port = 443,
  opts: { timeoutMs?: number; source?: CertSource } = {},
): Promise<FingerprintResult> {
  const source = opts.source ?? nodeCertSource;
  const cert = await source(host, port, opts.timeoutMs ?? 8000);
  const subject = cert.subject as { CN?: string } | undefined;
  const issuer = cert.issuer as { O?: string; CN?: string } | undefined;
  return {
    host,
    port,
    sha256: cert.fingerprint256 ?? '',
    sha1: cert.fingerprint ?? '',
    subjectCN: subject?.CN,
    issuer: issuer?.O ?? issuer?.CN,
    validFrom: cert.valid_from,
    validTo: cert.valid_to,
    serialNumber: cert.serialNumber,
    san: cert.subjectaltname,
  };
}
