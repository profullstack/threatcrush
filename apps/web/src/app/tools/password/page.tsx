"use client";

import { useCallback, useEffect, useState } from "react";

const CHARSETS: Record<string, string> = {
  ascii: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<=>?@[]^_{|}~",
  alnum: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  hex: "0123456789abcdef",
  base58: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
};

/** Uniform draw from alphabet using the browser CSPRNG + rejection sampling. */
function generate(length: number, alphabet: string): string {
  const chars = [...new Set([...alphabet])];
  const n = chars.length;
  const limit = 256 - (256 % n);
  let out = "";
  while (out.length < length) {
    const buf = new Uint8Array((length - out.length) * 2);
    crypto.getRandomValues(buf);
    for (let i = 0; i < buf.length && out.length < length; i++) if (buf[i] < limit) out += chars[buf[i] % n];
  }
  return out;
}

export default function PasswordPage() {
  const [length, setLength] = useState(24);
  const [charset, setCharset] = useState("ascii");
  const [value, setValue] = useState("");
  const [copied, setCopied] = useState(false);

  const regen = useCallback(() => { setValue(generate(length, CHARSETS[charset])); setCopied(false); }, [length, charset]);
  useEffect(() => { regen(); }, [regen]);

  return (
    <main className="pt-24 pb-20 min-h-screen bg-tc-darker">
      <section className="mx-auto max-w-2xl px-6">
        <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">{"// PERFECT PASSWORDS"}</p>
        <h1 className="text-4xl font-black text-white mb-3">Strong random strings</h1>
        <p className="text-tc-text-dim text-sm mb-6">
          Cryptographically strong random strings for keys, passwords and salts — generated in your
          browser with <code className="text-tc-green">crypto.getRandomValues</code> and never sent
          anywhere. Independent re-implementation of GRC&apos;s Perfect Passwords idea; not affiliated.
        </p>

        <div className="rounded-2xl border border-tc-border bg-tc-card p-6">
          <div className="flex flex-wrap gap-4 mb-4 items-end">
            <label className="text-sm text-tc-text-dim">
              Length: <span className="text-white font-mono">{length}</span>
              <input type="range" min={8} max={128} value={length} onChange={(e) => setLength(Number(e.target.value))} className="block w-48 mt-1 accent-[#00ff41]" />
            </label>
            <label className="text-sm text-tc-text-dim">
              Alphabet
              <select value={charset} onChange={(e) => setCharset(e.target.value)} className="block mt-1 rounded-lg border border-tc-border bg-tc-darker px-3 py-1.5 text-white text-sm">
                <option value="ascii">ASCII (symbols)</option>
                <option value="alnum">Alphanumeric</option>
                <option value="hex">Hex</option>
                <option value="base58">Base58</option>
              </select>
            </label>
          </div>
          <div className="rounded-xl border border-tc-border bg-tc-darker p-4 font-mono text-tc-green break-all text-sm min-h-[3rem]">{value}</div>
          <div className="flex gap-3 mt-4">
            <button onClick={regen} className="rounded-xl bg-tc-green px-5 py-2.5 font-bold text-black hover:opacity-90">Regenerate</button>
            <button
              onClick={() => { navigator.clipboard?.writeText(value); setCopied(true); }}
              className="rounded-xl border border-tc-border px-5 py-2.5 font-bold text-white hover:border-tc-green"
            >
              {copied ? "Copied ✓" : "Copy"}
            </button>
          </div>
        </div>
      </section>
    </main>
  );
}
