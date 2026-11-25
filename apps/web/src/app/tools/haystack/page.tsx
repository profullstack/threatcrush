"use client";

import { useMemo, useState } from "react";
import { analyzePassword } from "@/lib/haystack";

export default function HaystackPage() {
  const [pw, setPw] = useState("");
  const r = useMemo(() => (pw ? analyzePassword(pw) : null), [pw]);

  return (
    <main className="pt-24 pb-20 min-h-screen bg-tc-darker">
      <section className="mx-auto max-w-2xl px-6">
        <p className="font-mono text-sm text-tc-green mb-3 tracking-wider">{"// PASSWORD HAYSTACKS"}</p>
        <h1 className="text-4xl font-black text-white mb-3">How strong is your password?</h1>
        <p className="text-tc-text-dim text-sm mb-2">
          This shows the worst case: how long it would take to try every possible string of the same
          length and character mix. It runs entirely in your browser — nothing is sent anywhere.
        </p>
        <p className="text-xs text-tc-text-dim mb-6">
          It is <strong className="text-white">not</strong> a guess-ability score: a long but common
          password (&quot;Password123!&quot;) looks strong here yet falls instantly to a dictionary
          attack. Use it to understand length and character variety, not as proof of safety. Independent
          re-implementation of GRC&apos;s Haystacks idea; not affiliated.
        </p>

        <input
          type="text"
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          placeholder="Type or paste a password"
          autoComplete="off"
          spellCheck={false}
          className="w-full rounded-xl border border-tc-border bg-tc-card px-4 py-3 text-white font-mono focus:border-tc-green outline-none"
        />

        {r && (
          <div className="mt-6 rounded-2xl border border-tc-border bg-tc-card p-6 space-y-2 text-sm">
            <Row label="Length" value={String(r.length)} />
            <Row label="Character set" value={`${r.sets.join(", ") || "—"} (${r.poolSize} symbols)`} />
            <Row label="Entropy" value={`${r.entropyBits} bits`} />
            <Row label="Combinations" value={r.searchSpace} mono />
            <div className="pt-3 mt-2 border-t border-tc-border">
              <div className="text-tc-text-dim mb-2">Time to exhaustively search:</div>
              <Row label="Online (1k/s)" value={r.times.online} />
              <Row label="Offline fast (100B/s)" value={r.times.offlineFast} />
              <Row label="Massive array (100T/s)" value={r.times.massiveArray} />
            </div>
          </div>
        )}
      </section>
    </main>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-4">
      <span className="text-tc-text-dim">{label}</span>
      <span className={`text-white text-right break-all ${mono ? "font-mono text-xs" : ""}`}>{value}</span>
    </div>
  );
}
