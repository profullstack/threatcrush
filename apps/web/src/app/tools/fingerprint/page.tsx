"use client";

import { useState } from "react";

interface Fp {
  host: string; port: number; sha256: string; sha1: string;
  subjectCN?: string; issuer?: string; validFrom?: string; validTo?: string; san?: string; error?: string;
}

export default function FingerprintPage() {
  const [host, setHost] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<Fp | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function run(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true); setError(null); setResult(null);
    try {
      const res = await fetch("/api/fingerprint", {
        method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ host }),
      });
      const data = (await res.json()) as Fp;
      if (!res.ok) setError(data.error ?? "Could not read certificate"); else setResult(data);
    } catch {
      setError("Request failed. Try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="pt-24 pb-20 min-h-screen bg-tc-darker">
      <section className="mx-auto max-w-2xl px-6">
        <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">{"// TLS FINGERPRINT"}</p>
        <h1 className="text-4xl font-black text-white mb-3">Is your TLS being intercepted?</h1>
        <p className="text-tc-text-dim text-sm mb-6">
          We read the certificate a site presents from our server and show its SHA-256 fingerprint.
          Compare it to the fingerprint your own browser shows for the same site — if they differ, a
          proxy, antivirus, or attacker is intercepting your encrypted connection. Independent
          re-implementation of GRC&apos;s Fingerprints idea; not affiliated.
        </p>

        <form onSubmit={run} className="flex gap-3">
          <input
            type="text" value={host} onChange={(e) => setHost(e.target.value)}
            placeholder="example.com" autoComplete="off" spellCheck={false}
            className="flex-1 rounded-xl border border-tc-border bg-tc-card px-4 py-3 text-white font-mono focus:border-tc-green outline-none"
          />
          <button disabled={loading || !host} className="rounded-xl bg-tc-green px-6 py-3 font-bold text-black hover:opacity-90 disabled:opacity-50">
            {loading ? "Reading…" : "Check"}
          </button>
        </form>

        {error && <div className="mt-6 rounded-xl border border-red-500/40 bg-red-500/5 p-4 text-sm text-red-300">{error}</div>}

        {result && (
          <div className="mt-6 rounded-2xl border border-tc-border bg-tc-card p-6 space-y-2 text-sm">
            <div className="text-tc-text-dim mb-1">Our server sees this certificate for <span className="text-white font-mono">{result.host}</span>:</div>
            <Row label="SHA-256" value={result.sha256} mono />
            <Row label="SHA-1" value={result.sha1} mono />
            <Row label="Subject" value={result.subjectCN ?? "?"} />
            <Row label="Issuer" value={result.issuer ?? "?"} />
            <Row label="Valid" value={`${result.validFrom ?? "?"} → ${result.validTo ?? "?"}`} />
            <p className="pt-3 mt-2 border-t border-tc-border text-xs text-tc-text-dim">
              Now open the same site in your browser, view the certificate, and compare the SHA-256
              fingerprint. A mismatch means your connection is being intercepted.
            </p>
          </div>
        )}
      </section>
    </main>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-4">
      <span className="text-tc-text-dim shrink-0">{label}</span>
      <span className={`text-white text-right break-all ${mono ? "font-mono text-xs" : ""}`}>{value}</span>
    </div>
  );
}
