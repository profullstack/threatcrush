import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Docs — ThreatCrush",
  description:
    "Install ThreatCrush, run the daemon, and use every CLI command: detection, IP bans, hardening checks, code scanning, pentest checks, organizations and the cloud dashboard.",
  alternates: { canonical: "/docs" },
};

type Command = {
  name: string;
  description: string;
  /** Set for commands that ship in the next CLI release rather than the one on npm today. */
  isNew?: boolean;
};

const commandGroups: { title: string; commands: Command[] }[] = [
  {
    title: "Set up",
    commands: [
      { name: "threatcrush init", description: "Offers to sign you in, detects SSH, nginx, Apache, PostgreSQL, MySQL, Redis and BIND on this host, and writes a config for them." },
      { name: "threatcrush login [-e <email>]", description: "Sign in to your threatcrush.com account." },
      { name: "threatcrush logout", description: "Clear the stored threatcrush.com credentials." },
      { name: "threatcrush whoami", description: "Show the account you are signed in as." },
    ],
  },
  {
    title: "Detect and run the daemon",
    commands: [
      { name: "threatcrush monitor [-m <modules>] [--tui]", description: "Watch nginx, auth, syslog and journald for attacks in the foreground. -m limits it to some modules (e.g. ssh-guard,log-watcher)." },
      { name: "threatcrush tui [--demo]", description: "Interactive dashboard connected to the daemon (alias: dashboard). --demo runs on canned events." },
      { name: "sudo threatcrush install-service", description: "Install the threatcrushd systemd unit so the daemon starts on boot. uninstall-service removes it." },
      { name: "threatcrush start | stop | restart", description: "Start the daemon in the background, stop it, or restart it." },
      { name: "threatcrush daemon", description: "Run threatcrushd in the foreground — the ExecStart for systemd or Docker." },
      { name: "threatcrush status", description: "Show daemon status and loaded modules." },
      { name: "threatcrush logs", description: "Tail the daemon logs." },
      { name: "threatcrush rules [list | show <id>]", description: "List the detection rules, or show one. Add your own JSON rules in /etc/threatcrush/rules.d." },
    ],
  },
  {
    title: "Respond",
    commands: [
      { name: "threatcrush block <ip> [--ttl <duration>]", description: "Ban an IP at the firewall (nftables, iptables or fail2ban), optionally for a time such as 30m, 1h or 1d." },
      { name: "threatcrush unblock <ip>", description: "Lift a ban." },
      { name: "threatcrush blocklist", description: "Show active bans." },
      { name: "threatcrush allowlist [list | add <ip/cidr> | remove <ip/cidr>]", description: "Manage the addresses the daemon will never ban." },
      { name: "threatcrush harden [--json]", description: "Check SSH password and root login, sshd weaknesses, automatic security updates, an active firewall, risky exposed ports and fail2ban." },
    ],
  },
  {
    title: "Scan",
    commands: [
      { name: "threatcrush scan [path]", description: "Scan a codebase for secrets and risky code patterns. Options: -f text|json|sarif, -o <file>, --fail-on <severities>, --deps (check lockfile versions against OSV.dev), --exclude <glob>, --missing-controls, --path-prefix <prefix>." },
      { name: "threatcrush pentest <url>", description: "Check a URL's security headers, CSP, CORS, cookie flags, banners, directory listings and error leaks, then probe for SQL errors, path traversal and unsafe HTTP methods." },
    ],
  },
  {
    title: "Organizations and the cloud dashboard",
    commands: [
      { name: "threatcrush orgs [list | create <name> | use <slug>]", description: "List your organizations, create one, or switch the current one (alias: org)." },
      { name: "threatcrush servers list", description: "List the servers in the current organization (alias: server)." },
      { name: "threatcrush servers link [--org <id|slug>] [--name <name>]", description: "Link this machine to a server in your organization, reusing one with the same hostname or creating it. While signed in and linked, the daemon sends detections, hardening findings, bans and heartbeats to the dashboard, and carries out bans you queue there.", isNew: true },
      { name: "threatcrush servers unlink", description: "Stop sending this machine's data to the dashboard. threatcrush status shows whether a machine is linked.", isNew: true },
      { name: "threatcrush properties [list | add | remove | run | runs | import]", description: "Manage the targets (URLs, APIs, domains, IPs, repos) in the current organization, run scans and pentest checks against them, see run history, and bulk-import from .json, .csv or .tsv (alias: props)." },
      { name: "threatcrush connect [target]", description: "Open an SSH session to a server in your organization (--org, -u, -p, -i)." },
    ],
  },
  {
    title: "Modules",
    commands: [
      { name: "threatcrush modules [list | install | remove | available] [name]", description: "Manage security modules." },
      { name: "threatcrush store", description: "Browse the module marketplace." },
      { name: "threatcrush store search <query>", description: "Search the marketplace." },
      { name: "threatcrush store publish <url>", description: "Submit a module from a git or web URL. Publishing is free; listings go live after review." },
    ],
  },
  {
    title: "Install lifecycle",
    commands: [
      { name: "threatcrush update [--cli | --modules | --desktop]", description: "Update the CLI and the installed bundle." },
      { name: "threatcrush remove", description: "Uninstall ThreatCrush and the installed bundle (alias: uninstall)." },
    ],
  },
];

const notYet = [
  "Code-signed macOS and Windows desktop builds — today they trigger Gatekeeper and SmartScreen warnings",
  "The mobile app in the App Store and Google Play",
  "The browser extension in the Chrome, Firefox and Edge stores — sideload it from source for now",
  "The @threatcrush/sdk package on npm",
];

export default function DocsPage() {
  return (
    <main className="min-h-screen bg-tc-darker text-tc-text">
      <div className="mx-auto max-w-5xl px-6 pt-28 pb-16">
        <div className="mb-12">
          <Link href="/" className="text-sm text-tc-green hover:underline">← Back to ThreatCrush</Link>
          <p className="mt-6 font-mono text-sm text-tc-green tracking-wider">// DOCS</p>
          <h1 className="mt-3 text-4xl font-black text-white">ThreatCrush Docs</h1>
          <p className="mt-4 max-w-3xl text-base text-tc-text-dim">
            How to install ThreatCrush, run the daemon, and use every CLI command.
            Run <code className="rounded bg-black/40 px-2 py-1 font-mono text-tc-green">threatcrush help &lt;command&gt;</code> for the full options of any command.
          </p>
        </div>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <h2 className="text-2xl font-bold text-white">Install</h2>
          <div className="mt-4 space-y-3 text-sm text-tc-text-dim">
            <p>
              <span className="text-tc-green font-semibold">Preferred install:</span>{" "}
              <code className="rounded bg-black/40 px-2 py-1 font-mono text-tc-green">curl -fsSL https://threatcrush.com/install.sh | sh</code>
            </p>
            <ul className="list-disc space-y-2 pl-6">
              <li><span className="text-white">Linux server</span> → installs the CLI, which includes the daemon.</li>
              <li><span className="text-white">Desktop (Linux, macOS, Windows)</span> → installs the CLI and points you to the desktop app, a separate download from <a href="https://github.com/profullstack/threatcrush/releases/latest" className="text-tc-green hover:underline">GitHub Releases</a>. The desktop app talks to a ThreatCrush daemon on the same machine; log monitoring and firewall bans need Linux.</li>
            </ul>
            <p>
              After install, lifecycle commands are <code className="rounded bg-black/40 px-2 py-1 font-mono text-tc-green">threatcrush update</code> and{" "}
              <code className="rounded bg-black/40 px-2 py-1 font-mono text-tc-green">threatcrush remove</code>.
            </p>
          </div>
        </section>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <p className="font-mono text-sm text-tc-green tracking-wider">// QUICK START</p>
          <h2 className="mt-2 text-2xl font-bold text-white">Protect a Linux server</h2>
          <ol className="mt-4 list-decimal space-y-2 pl-6 text-sm text-tc-text-dim">
            <li><code className="font-mono text-tc-green">threatcrush init</code> — optionally sign in, and write a config for the services on this host.</li>
            <li><code className="font-mono text-tc-green">sudo threatcrush install-service</code> — run the daemon under systemd. It detects attacks and bans their source IPs on its own; no account is needed for that.</li>
            <li><code className="font-mono text-tc-green">threatcrush servers link</code> — optional: send this server&apos;s detections, findings and bans to your organization&apos;s dashboard.</li>
          </ol>
        </section>

        <section className="mb-12">
          <div className="mb-6">
            <p className="font-mono text-sm text-tc-green tracking-wider">// COMMANDS</p>
            <h2 className="mt-2 text-2xl font-bold text-white">Command reference</h2>
            <p className="mt-2 text-sm text-tc-text-dim">
              Everything below ships in the CLI on npm, except commands marked <span className="text-yellow-400">New</span>, which arrive in the next release.
            </p>
          </div>

          <div className="space-y-10">
            {commandGroups.map((group) => (
              <div key={group.title}>
                <h3 className="mb-4 text-lg font-semibold text-white">{group.title}</h3>
                <div className="space-y-3">
                  {group.commands.map((command) => (
                    <div key={command.name} className="rounded-xl border border-tc-border bg-tc-card p-5">
                      <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                        <div className="flex-1">
                          <code className="font-mono text-sm text-tc-green">{command.name}</code>
                          <p className="mt-2 text-sm text-tc-text-dim">{command.description}</p>
                        </div>
                        {command.isNew ? (
                          <span className="self-start rounded-full border border-yellow-500/30 bg-yellow-500/10 px-3 py-1 text-xs font-semibold text-yellow-400">
                            New
                          </span>
                        ) : (
                          <span className="self-start rounded-full border border-tc-green/30 bg-tc-green/10 px-3 py-1 text-xs font-semibold text-tc-green">
                            Shipped
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>

        <section className="mb-12 rounded-2xl border border-tc-border bg-tc-card p-8">
          <p className="font-mono text-sm text-yellow-400 tracking-wider">// NOT YET</p>
          <h2 className="mt-2 text-2xl font-bold text-white">Not available yet</h2>
          <ul className="mt-5 list-disc space-y-3 pl-6 text-sm text-tc-text-dim">
            {notYet.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>

        <section className="rounded-2xl border border-tc-border bg-tc-card p-8">
          <p className="font-mono text-sm text-tc-green tracking-wider">// MODULE AUTHORS</p>
          <h2 className="mt-2 text-2xl font-bold text-white">Building and publishing modules</h2>
          <p className="mt-4 text-sm text-tc-text-dim">
            If you want to contribute to the marketplace, start with the module author docs.
            They explain how the store works today, what metadata we fetch, and how to publish through the web UI or CLI.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <Link href="/docs/modules" className="rounded-lg bg-tc-green px-5 py-3 font-semibold text-black hover:bg-tc-green-dim">
              Read module docs →
            </Link>
            <Link href="/docs/releases" className="rounded-lg border border-tc-border px-5 py-3 font-semibold text-tc-text-dim hover:border-tc-green/30 hover:text-tc-green">
              Release automation docs
            </Link>
            <Link href="/store" className="rounded-lg border border-tc-border px-5 py-3 font-semibold text-tc-text-dim hover:border-tc-green/30 hover:text-tc-green">
              Browse module store
            </Link>
            <Link href="/store/publish" className="rounded-lg border border-tc-border px-5 py-3 font-semibold text-tc-text-dim hover:border-tc-green/30 hover:text-tc-green">
              Publish a module
            </Link>
          </div>
        </section>
      </div>
    </main>
  );
}
