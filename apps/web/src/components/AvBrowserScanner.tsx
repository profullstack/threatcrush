"use client";

import { useCallback, useRef, useState } from "react";
import {
  applyReputation,
  DEFAULT_HEURISTIC_BYTES,
  lookupHashes,
  scanBytes,
  sha256Hex,
  type AvFileResult,
} from "@threatcrush/av";

/**
 * The CrushAV engine running in the visitor's browser. Files are read locally;
 * only SHA-256 fingerprints of files worth checking go to /api/av/lookup. Works
 * on any device with a modern browser, including iPhones and Chromebooks
 * where no antivirus app can scan files.
 */

const MAX_HASH_BYTES = 512 * 1024 * 1024;
const LOOKUP_KINDS = new Set(["pe", "elf", "macho", "script", "lnk", "ole", "zip", "pdf", "dex", "rtf"]);

type Row = AvFileResult & { status: "scanning" | "done" };

const VERDICT_STYLE: Record<string, string> = {
  malicious: "border-red-500/60 bg-red-500/10 text-red-300",
  suspicious: "border-yellow-500/60 bg-yellow-500/10 text-yellow-200",
  clean: "border-tc-green/40 bg-tc-green/5 text-tc-green",
  error: "border-tc-border bg-tc-dark text-tc-text-dim",
};
const VERDICT_LABEL: Record<string, string> = {
  malicious: "Malware",
  suspicious: "Suspicious",
  clean: "Nothing found",
  error: "Could not read",
};

function fmtSize(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

async function scanFile(file: File): Promise<AvFileResult> {
  const name = (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
  try {
    const head = new Uint8Array(await file.slice(0, DEFAULT_HEURISTIC_BYTES).arrayBuffer());
    let sha256: string | null = null;
    if (file.size <= DEFAULT_HEURISTIC_BYTES) sha256 = await sha256Hex(head);
    else if (file.size <= MAX_HASH_BYTES) sha256 = await sha256Hex(new Uint8Array(await file.arrayBuffer()));
    const r = await scanBytes({ name, bytes: head, size: file.size, sha256 });
    return file.size > MAX_HASH_BYTES ? { ...r, note: "too large to fingerprint in a browser; heuristics only" } : r;
  } catch (e) {
    return { path: name, size: file.size, sha256: null, kind: "unknown", verdict: "error", detections: [], note: String(e) };
  }
}

export function AvBrowserScanner() {
  const [rows, setRows] = useState<Row[]>([]);
  const [busy, setBusy] = useState(false);
  const [drag, setDrag] = useState(false);
  const [lookupNote, setLookupNote] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);

  const run = useCallback(async (files: File[]) => {
    if (!files.length) return;
    setBusy(true);
    setLookupNote(null);
    const start: Row[] = files.map((f) => ({ path: f.name, size: f.size, sha256: null, kind: "unknown", verdict: "clean", detections: [], status: "scanning" }));
    setRows(start);
    const results: AvFileResult[] = [];
    for (let i = 0; i < files.length; i++) {
      const r = await scanFile(files[i]);
      results.push(r);
      setRows((prev) => prev.map((row, j) => (j === i ? { ...r, status: "done" } : row)));
    }
    const wanted = results.filter((r) => r.sha256 && (LOOKUP_KINDS.has(r.kind) || r.detections.length)).map((r) => r.sha256!);
    if (wanted.length) {
      const reps = await lookupHashes(wanted, { endpoint: "/api/av/lookup" });
      setLookupNote(`Checked ${wanted.length} fingerprint${wanted.length === 1 ? "" : "s"} against known malware and known-good software.`);
      setRows(results.map((r) => ({ ...(r.sha256 ? applyReputation(r, reps.get(r.sha256)) : r), status: "done" as const })));
    }
    setBusy(false);
  }, []);

  const counts = rows.reduce<Record<string, number>>((acc, r) => ({ ...acc, [r.verdict]: (acc[r.verdict] ?? 0) + (r.status === "done" ? 1 : 0) }), {});
  const order = { malicious: 0, suspicious: 1, error: 2, clean: 3 } as Record<string, number>;
  const sorted = [...rows].sort((a, b) => order[a.verdict] - order[b.verdict]);

  return (
    <div className="rounded-xl border border-tc-border bg-tc-dark p-4 sm:p-6">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDrag(true);
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDrag(false);
          void run(Array.from(e.dataTransfer.files));
        }}
        className={`flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed px-4 py-10 text-center transition-colors ${
          drag ? "border-tc-green bg-tc-green/10" : "border-tc-border"
        }`}
      >
        <p className="text-lg font-semibold">Drop files here to scan them</p>
        <p className="max-w-md text-sm text-tc-text-dim">
          Your files never leave this device. CrushAV reads them in your browser and only sends a fingerprint (SHA-256) to
          check against known malware.
        </p>
        <div className="flex flex-wrap justify-center gap-2">
          <button
            type="button"
            disabled={busy}
            onClick={() => fileInput.current?.click()}
            className="rounded-md bg-tc-green px-4 py-2 font-semibold text-black hover:opacity-90 disabled:opacity-50"
          >
            Choose files
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => folderInput.current?.click()}
            className="rounded-md border border-tc-border px-4 py-2 hover:border-tc-green disabled:opacity-50"
          >
            Scan a folder
          </button>
        </div>
        <input ref={fileInput} type="file" multiple hidden onChange={(e) => void run(Array.from(e.target.files ?? []))} />
        <input
          ref={folderInput}
          type="file"
          hidden
          // Not in React's types, supported by every current browser.
          {...({ webkitdirectory: "" } as Record<string, string>)}
          onChange={(e) => void run(Array.from(e.target.files ?? []))}
        />
      </div>

      {rows.length > 0 && (
        <div className="mt-6" aria-live="polite">
          <p className="text-sm text-tc-text-dim">
            {busy ? "Scanning… " : "Done. "}
            {rows.length} file{rows.length === 1 ? "" : "s"}
            {counts.malicious ? ` · ${counts.malicious} malware` : ""}
            {counts.suspicious ? ` · ${counts.suspicious} suspicious` : ""}
            {!busy && !counts.malicious && !counts.suspicious ? " · nothing found" : ""}
          </p>
          {lookupNote && <p className="mt-1 text-xs text-tc-text-dim">{lookupNote}</p>}
          <ul className="mt-3 space-y-2">
            {sorted.map((r, i) => (
              <li key={`${r.path}-${i}`} className={`rounded-md border p-3 ${VERDICT_STYLE[r.verdict]}`}>
                <div className="flex flex-wrap items-baseline justify-between gap-2">
                  <span className="break-all font-mono text-sm text-tc-text">{r.path}</span>
                  <span className="shrink-0 text-xs font-semibold uppercase tracking-wide">
                    {r.status === "scanning" ? "Scanning…" : VERDICT_LABEL[r.verdict]} · {fmtSize(r.size)}
                  </span>
                </div>
                {r.detections
                  .filter((d) => d.impact !== "info")
                  .map((d) => (
                    <div key={d.id} className="mt-2 text-sm">
                      <p className="font-semibold">{d.name}</p>
                      <p className="text-tc-text-dim">{d.description}</p>
                    </div>
                  ))}
                {r.detections
                  .filter((d) => d.impact === "info")
                  .map((d) => (
                    <p key={d.id} className="mt-1 text-xs text-tc-text-dim">
                      ℹ {d.name}: {d.description}
                    </p>
                  ))}
                {r.note && <p className="mt-1 text-xs text-tc-text-dim">{r.note}</p>}
              </li>
            ))}
          </ul>
          {(counts.malicious ?? 0) > 0 && (
            <p className="mt-4 rounded-md border border-red-500/40 p-3 text-sm">
              <strong>What to do:</strong> don&apos;t open the flagged file. Delete it (and empty the trash). If you already
              opened it, disconnect from the internet, run a full scan with the CrushAV app or your built-in antivirus, and
              change passwords from a different device.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
