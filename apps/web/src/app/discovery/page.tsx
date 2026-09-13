import Link from "next/link";
import { loadOpenThreat, type OpenThreatItem } from "@/lib/open-threats";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Discovery — open threats ThreatCrush identified",
  description:
    "Threats ThreatCrush identified in the open: findings in public repositories scanned by the ThreatCrush GitHub App, published as an OpenThreat descriptor at /.well-known/openthreat.json. Never private repositories, never customer data.",
  alternates: { canonical: "/discovery" },
};

const linkClass = "text-tc-green underline underline-offset-4 hover:opacity-80";

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="rounded bg-black/40 px-1.5 py-0.5 font-mono text-[0.9em] text-tc-green">
      {children}
    </code>
  );
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-300",
  low: "text-tc-text-dim",
  info: "text-tc-text-dim",
};

function when(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toISOString().slice(0, 16).replace("T", " ") + " UTC";
}

function Row({ t }: { t: OpenThreatItem }) {
  return (
    <tr className="border-t border-tc-green/10 align-top">
      <td className={`px-3 py-2 font-mono text-xs uppercase ${SEVERITY_CLASS[t.severity ?? "info"]}`}>
        {t.severity ?? "unstated"}
      </td>
      <td className="px-3 py-2">
        <div className="text-tc-text">{t.title}</div>
        <div className="font-mono text-xs text-tc-text-dim">
          {t.rule}
          {t.cwe ? ` · ${t.cwe}` : ""}
        </div>
      </td>
      <td className="px-3 py-2">
        {t.subject ? (
          <a className={linkClass} href={t.subject.url} rel="noopener noreferrer">
            {t.subject.name}
          </a>
        ) : (
          <span className="text-tc-text-dim">unstated</span>
        )}
        {t.location ? (
          <div className="font-mono text-xs text-tc-text-dim">
            {t.location.file}:{t.location.line}
          </div>
        ) : t.category === "secret" ? (
          <div className="text-xs text-tc-text-dim">location withheld (secret)</div>
        ) : null}
      </td>
      <td className="px-3 py-2 font-mono text-xs">
        <span className={t.status === "fixed" ? "text-tc-green" : "text-tc-text"}>{t.status}</span>
      </td>
      <td className="px-3 py-2 font-mono text-xs text-tc-text-dim whitespace-nowrap">
        {when(t.last_seen)}
      </td>
    </tr>
  );
}

export default async function DiscoveryPage() {
  let threats: OpenThreatItem[] = [];
  let updated = "";
  let unavailable = false;
  try {
    const descriptor = await loadOpenThreat();
    threats = descriptor.threats;
    updated = descriptor.updated;
  } catch {
    unavailable = true;
  }

  const open = threats.filter((t) => t.status === "open").length;
  const fixed = threats.filter((t) => t.status === "fixed").length;
  const repos = new Set(threats.map((t) => t.subject?.name).filter(Boolean)).size;

  return (
    <main className="min-h-screen bg-tc-darker matrix-bg pt-24">
      <div className="mx-auto max-w-5xl px-6 py-16">
        <header className="mb-10">
          <p className="font-mono-green text-sm uppercase tracking-widest">// in the open</p>
          <h1 className="mt-3 text-4xl font-bold text-tc-text">
            <span className="text-tc-green glow-green">Discovery</span>
          </h1>
          <p className="mt-4 text-tc-text-dim">
            The threats ThreatCrush identified in the open: findings in public repositories
            scanned by the ThreatCrush GitHub App, listed here as they were found and marked
            fixed when a later scan no longer finds them. Nothing on this page comes from a
            private repository or from a customer&apos;s servers, and the{" "}
            <a className={linkClass} href="#policy">
              policy
            </a>{" "}
            below says exactly what is withheld. The same list is served as an{" "}
            <a className={linkClass} href="https://logicsrc.com/openthreat" rel="noopener noreferrer">
              OpenThreat
            </a>{" "}
            descriptor at <Code>/.well-known/openthreat.json</Code>, so any directory can read it.
          </p>
          {updated && (
            <p className="mt-2 text-sm text-tc-text-dim">
              Updated {when(updated)} · {open} open · {fixed} fixed · {repos} repositories
            </p>
          )}
        </header>

        <section>
          {unavailable ? (
            <p className="text-tc-text-dim">
              The list could not be built right now. The descriptor at{" "}
              <Code>/.well-known/openthreat.json</Code> answers with the same state.
            </p>
          ) : threats.length === 0 ? (
            <div className="rounded-lg border border-tc-green/20 bg-black/40 p-6 text-tc-text-dim">
              <p>
                Nothing to list yet. Findings appear here after the ThreatCrush GitHub App scans a
                public repository on an installation that has announcements on.
              </p>
              <p className="mt-3">
                <a className={linkClass} href="https://github.com/apps/threatcrush" rel="noopener noreferrer">
                  Install the app
                </a>{" "}
                on a public repository to be the first.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto rounded-lg border border-tc-green/20 bg-black/40">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left font-mono text-xs uppercase text-tc-text-dim">
                    <th className="px-3 py-2">Severity</th>
                    <th className="px-3 py-2">Finding</th>
                    <th className="px-3 py-2">Subject</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {threats.map((t) => (
                    <Row key={`${t.id}:${t.status}`} t={t} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section id="policy" className="mt-16 space-y-4 text-tc-text">
          <h2 className="text-xl font-semibold text-tc-green">Policy</h2>
          <p className="text-tc-text-dim">What this page publishes, and what it never will.</p>
          <ul className="list-disc space-y-2 pl-6 text-tc-text-dim">
            <li>
              <strong className="text-tc-text">Public repositories only.</strong> A finding is listed
              only when the repository was public at the time of the scan. Private repositories are
              never scanned into this list, whatever the finding.
            </li>
            <li>
              <strong className="text-tc-text">No customer data.</strong> Nothing from a ThreatCrush
              organization, a monitored server, a property, a pentest or a live detection appears
              here. Those belong to the people who pay for them.
            </li>
            <li>
              <strong className="text-tc-text">Secrets are never located.</strong> A committed
              credential is published as a rule, a severity and a repository, with no file, no line
              and no excerpt. It is already exposed; this page will not be the map to it. No finding
              of any kind carries the matched source line.
            </li>
            <li>
              <strong className="text-tc-text">Announcements are on by default.</strong> Installing
              the GitHub App on a public repository lists its findings here. The person who installed
              it can turn announcements off for that installation from{" "}
              <Link href="/account" className={linkClass}>
                app settings
              </Link>{" "}
              after signing in with the same GitHub account; the installation&apos;s repositories
              leave the list within five minutes.
            </li>
            <li>
              <strong className="text-tc-text">Fixed is a fact, not a promise.</strong> A finding is
              marked fixed when a later scan of the same repository no longer reports it. A finding
              that reappears is open again.
            </li>
            <li>
              <strong className="text-tc-text">Everything here is TLP:CLEAR.</strong> It is served
              from ThreatCrush&apos;s own origin, which is the whole verification a reader needs.
            </li>
          </ul>
        </section>

        <footer className="mt-16 border-t border-tc-green/20 pt-6 text-sm text-tc-text-dim">
          Descriptor: <Code>{`${process.env.NEXT_PUBLIC_APP_URL?.replace(/\/$/, "") || "https://threatcrush.com"}/.well-known/openthreat.json`}</Code>{" "}
          · Specification:{" "}
          <a className={linkClass} href="https://logicsrc.com/openthreat" rel="noopener noreferrer">
            logicsrc.com/openthreat
          </a>{" "}
          · Also read by{" "}
          <a className={linkClass} href="https://nichedb.dev/c/threats" rel="noopener noreferrer">
            nichedb.dev
          </a>
        </footer>
      </div>
    </main>
  );
}
