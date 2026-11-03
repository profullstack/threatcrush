import type { Metadata } from "next";
import { RULES } from "@threatcrush/av";
import { AvBrowserScanner } from "@/components/AvBrowserScanner";

export const metadata: Metadata = {
  title: "CrushAV: free, open-source antivirus for Windows, Mac, Linux and phones",
  description:
    "Scan files for malware for free, right in your browser or with the CrushAV app. Open source (MIT), no subscription, no upsells. Heuristics for droppers, fake documents, ransomware and Mac stealers, plus ClamAV's millions of signatures.",
  alternates: { canonical: "https://threatcrush.com/antivirus" },
};

const CATCHES = [
  ["Programs disguised as documents", "invoice.pdf that is really an .exe, double extensions, reversed-name tricks"],
  ["Malware droppers", "booby-trapped shortcuts, JS/VBS/HTA attachments, hidden PowerShell download-and-run"],
  ["Ransomware", "tools that wipe your backups before encrypting, and the ransom notes left behind"],
  ["Mac password stealers", "fake macOS password prompts that grab your keychain and browser data"],
  ["Fake \"verify you are human\" pages", "ClickFix pages that put a malware command on your clipboard"],
  ["Dodgy Office files and PDFs", "macros that run on open, PDFs that try to launch programs"],
  ["Website backdoors and miners", "PHP/ASP/JSP webshells on your site, cryptocurrency miners on your PC"],
  ["Known malware by fingerprint", "ClamAV's millions of signatures plus a lookup of the file's fingerprint"],
];

const PLATFORMS: Array<{ name: string; body: string; cmd?: string; href?: string; cta?: string }> = [
  {
    name: "Windows & Mac",
    body: "Download the ThreatCrush desktop app and open Virus Scan. Quick scan, full scan, pick a folder, quarantine with one click, and real-time protection that checks every download as it lands.",
    href: "https://github.com/profullstack/threatcrush/releases/latest",
    cta: "Download the desktop app",
  },
  {
    name: "Linux (and Mac/Windows terminals)",
    body: "One command installs the CLI. Then scan, watch your Downloads folder, or quarantine from the terminal.",
    cmd: "curl -fsSL https://threatcrush.com/install.sh | sh\nthreatcrush av scan            # quick scan\nthreatcrush av scan --full     # whole home folder\nthreatcrush av watch           # real-time protection",
  },
  {
    name: "iPhone, iPad, Android, Chromebook",
    body: "Use the scanner on this page: it runs in your phone's browser. Pick files or downloads and they are checked on the device. The ThreatCrush mobile app gets a scan screen (including a whole-folder scan on Android) in its next store release.",
  },
];

const FAQ: Array<[string, string]> = [
  [
    "Is it really free?",
    "Yes. CrushAV is open source under the MIT licence and costs nothing, with no trial that expires and no \"your protection is at risk\" upsells. ThreatCrush makes its money protecting servers for businesses; CrushAV is the part for people.",
  ],
  [
    "Should I turn off Windows Security (Defender)?",
    "No. Keep it on. Microsoft Defender is built into Windows, free and good. Think of CrushAV as a second opinion that also explains, in plain English, why a file is dangerous. On a Mac or Linux machine, where nothing is scanning your downloads by default, CrushAV's real-time protection fills that gap.",
  ],
  [
    "Does it catch everything?",
    "No antivirus does, and anyone who says otherwise is selling something. CrushAV combines three checks: rules for the tricks real attacks use today, ClamAV's open signature database (when installed; the desktop app and CLI show you the one command for your system), and a fingerprint lookup against known malware and known-good software. We would rather say \"nothing found\" than scare you with false alarms, so legitimate files from trusted software sources are never flagged as merely suspicious.",
  ],
  [
    "What do you see of my files?",
    "Nothing. Files are read on your device. For programs, scripts and documents that can carry code, CrushAV sends only the file's SHA-256 fingerprint, a one-way code that cannot be turned back into the file, to check it against known malware. Turn that off with --offline in the CLI or the \"Offline\" switch in the desktop app.",
  ],
  [
    "Why can't any app scan my whole iPhone?",
    "iOS does not let one app look inside another, so \"iPhone antivirus\" apps are mostly VPNs and link checkers. Keep iOS updated, install apps only from the App Store, and scan files you are unsure about with the scanner on this page.",
  ],
];

export default function AntivirusPage() {
  return (
    <main className="min-h-screen bg-tc-darker text-tc-text">
      <section className="border-b border-tc-border bg-gradient-to-b from-tc-dark to-tc-darker">
        <div className="mx-auto max-w-5xl px-4 py-14 sm:py-20">
          <p className="font-mono text-sm text-tc-green">// crushav</p>
          <h1 className="mt-3 text-3xl font-bold sm:text-5xl">Free antivirus that tells you the truth.</h1>
          <p className="mt-4 max-w-2xl text-lg text-tc-text-dim">
            Big-name antivirus suites often renew at around $100 a year and still bury you in pop-ups. CrushAV is free, open
            source, and explains every detection in plain English. Scan a file right now, no install, no account.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <a href="#scan" className="rounded-md bg-tc-green px-5 py-2.5 font-semibold text-black hover:opacity-90">
              Scan files now
            </a>
            <a href="#install" className="rounded-md border border-tc-border px-5 py-2.5 hover:border-tc-green">
              Install on your computer
            </a>
            <a
              href="https://github.com/profullstack/threatcrush/tree/master/packages/av"
              className="rounded-md border border-tc-border px-5 py-2.5 hover:border-tc-green"
            >
              Read the source
            </a>
          </div>
        </div>
      </section>

      <section id="scan" className="mx-auto max-w-5xl scroll-mt-20 px-4 py-12">
        <h2 className="text-2xl font-semibold">Scan files in your browser</h2>
        <p className="mt-2 max-w-2xl text-tc-text-dim">
          Works on any computer, phone or tablet. Nothing is uploaded.
        </p>
        <div className="mt-6">
          <AvBrowserScanner />
        </div>
      </section>

      <section className="mx-auto max-w-5xl px-4 py-12">
        <h2 className="text-2xl font-semibold">What CrushAV catches</h2>
        <p className="mt-2 text-tc-text-dim">
          {RULES.length} detection rules for the attacks people actually get hit with, plus ClamAV&apos;s signature database.
        </p>
        <ul className="mt-6 grid gap-4 sm:grid-cols-2">
          {CATCHES.map(([title, detail]) => (
            <li key={title} className="rounded-lg border border-tc-border bg-tc-dark p-4">
              <p className="font-semibold">{title}</p>
              <p className="mt-1 text-sm text-tc-text-dim">{detail}</p>
            </li>
          ))}
        </ul>
      </section>

      <section id="install" className="mx-auto max-w-5xl scroll-mt-20 px-4 py-12">
        <h2 className="text-2xl font-semibold">Get it everywhere</h2>
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          {PLATFORMS.map((p) => (
            <div key={p.name} className="flex flex-col rounded-lg border border-tc-border bg-tc-dark p-5">
              <h3 className="text-lg font-semibold">{p.name}</h3>
              <p className="mt-2 flex-1 text-sm text-tc-text-dim">{p.body}</p>
              {p.cmd && (
                <pre className="mt-4 overflow-x-auto rounded-md bg-black/50 p-3 font-mono text-xs text-tc-green">{p.cmd}</pre>
              )}
              {p.href && (
                <a href={p.href} className="mt-4 inline-block rounded-md bg-tc-green px-4 py-2 text-center font-semibold text-black hover:opacity-90">
                  {p.cta}
                </a>
              )}
            </div>
          ))}
        </div>
      </section>

      <section className="mx-auto max-w-3xl px-4 py-12">
        <h2 className="text-2xl font-semibold">Questions</h2>
        <div className="mt-6 space-y-3">
          {FAQ.map(([q, a]) => (
            <details key={q} className="rounded-lg border border-tc-border bg-tc-dark p-4">
              <summary className="cursor-pointer font-semibold">{q}</summary>
              <p className="mt-3 text-tc-text-dim">{a}</p>
            </details>
          ))}
        </div>
      </section>
    </main>
  );
}
