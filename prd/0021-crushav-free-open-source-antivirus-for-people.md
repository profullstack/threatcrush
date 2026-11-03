---
openprd: "0.2"
id: "0021"
title: "CrushAV: free, open-source antivirus for people"
status: Phase 1 shipped
authors:
  - anthony@profullstack.com
created: 2026-11-02
updated: 2026-11-02
repo: profullstack/threatcrush
discussion:
implementation:
  - https://github.com/profullstack/threatcrush (feat/crushav)
tags: [antivirus, consumer, clamav, desktop, mobile, browser, open-source]
supersedes:
superseded-by:
---

## Problem

People pay a yearly subscription for antivirus that often renews at around $100,
nags them with upsells, and explains nothing. Many of them do not need to:
Windows ships Defender, and what is missing is a trustworthy second opinion that
says in plain English why a file is dangerous. Mac, Linux, Chromebook and phone
users usually have nothing scanning their downloads at all.

PRD 0019 deliberately left Windows/macOS endpoint antivirus and home users out
of scope for the ThreatCrush server platform. This PRD adds them as a separate,
free product built from the same parts.

## Goals

- One free, MIT-licensed engine (`@threatcrush/av`) that runs unchanged in Node,
  Electron, browsers and React Native, so every surface gives the same verdict.
- A false-positive rate low enough that people keep trusting it: nothing a
  trusted software source ships is ever called suspicious by a heuristic alone.
- Every detection explains what the file does and what to do, in plain English.
- Privacy: files never leave the device; only SHA-256 fingerprints are looked up,
  and that can be switched off.

## Non-Goals

- Kernel drivers, on-access blocking hooks, or replacing Microsoft Defender. We
  tell Windows users to keep Defender on.
- Charging for it, trials, or upsells inside the scanner.
- Scanning inside other apps on iOS (the OS forbids it; we say so instead of
  selling a VPN as antivirus).

## Design

Three engines, merged per file into `malicious | suspicious | clean`:

1. **Heuristic rules** (`packages/av/src/rules.ts`, 23 rules): disguised
   executables, double extensions, RTLO names, PowerShell encoded/download-run,
   WSH droppers, booby-trapped LNKs, Office auto-macros, PDF /Launch, reverse
   shells, webshells, coin miners, shadow-copy wiping, ransom notes, Mimikatz
   strings, AMOS-style macOS stealers, ClickFix pages, HTML smuggling, SVG
   redirects. Each rule is scoped to the file types where the pattern means an
   attack, and anything legitimate software also does is at most `suspicious`.
2. **ClamAV** (`packages/av/src/node/clamav.ts`), when installed: one
   `clamdscan`/`clamscan --file-list` run per scan; PUA/Heuristics names map to
   `suspicious`.
3. **Hash reputation** (`POST /api/av/lookup`, MCP `av_hash_lookup`): CIRCL
   hashlookup (known malicious, and a 0-100 known-good trust from NSRL and OS
   package sets) plus MalwareBazaar when `ABUSECH_AUTH_KEY` is configured.
   Known-good downgrades suspicious heuristics to info; known-bad adds a
   detection. abuse.ch retired its keyless bulk exports (410 Gone, measured
   2026-11-02), so no bulk hash list is bundled.

Quarantine XORs the file into `~/.threatcrush/quarantine/<id>.bin` with a JSON
record, verifies the copy before deleting the original, and restores exactly.

## Surfaces (phase 1, shipped)

| Surface | What |
|---|---|
| CLI | `threatcrush av scan [paths] [--full] [--quarantine] [--offline] [--json]`, `av watch`, `av status`, `av quarantine list/add/restore/delete`, `av test` |
| Desktop | Virus Scan page: quick/full/folder scan, quarantine, reveal, real-time protection with notifications, offline switch |
| Web | `/antivirus`: in-browser scanner (works on iPhone/Android/Chromebook), install paths, honest FAQ |
| Mobile | Antivirus screen, reachable without an account: Android folder scan via the Storage Access Framework; iOS points to the web scanner |
| API / MCP | `POST /api/av/lookup` (public, rate limited 30/min/IP, 100 hashes per call), `av_hash_lookup` (no key) |

## Measured

- Before release: 147,613 real files (`/usr`, `/etc`, `/opt`, a large monorepo
  with security fixtures and built bundles) scanned in 155 s: 0 malicious,
  0 suspicious after two rounds of rule scoping (first round: 5 hits on binaries,
  49 on Node bundles, 1 on a test file; each fixed and pinned by a regression test).

## Next

- Phase 2: native file picker on mobile (`expo-document-picker`) and a share
  target, so "Open in ThreatCrush" scans any attachment on iOS and Android.
- Phase 2: desktop installs ClamAV on request (winget/brew/apt) and runs
  `freshclam`.
- Phase 3: community signatures: hashes users quarantine (opt-in) that two
  engines agree on feed a published list at `/api/av/signatures`.
- Browser extension: scan downloads as they finish.
