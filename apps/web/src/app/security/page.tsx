export const metadata = {
  title: "Security & Data Handling — ThreatCrush",
  description:
    "What the ThreatCrush CLI sends over the network (nothing, by default), what telemetry exists and how it is switched on, and the minimum GitHub permissions the scan workflow needs.",
};

const linkClass = "text-tc-green underline underline-offset-4 hover:opacity-80";

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="rounded bg-black/40 px-1.5 py-0.5 font-mono text-[0.9em] text-tc-green">
      {children}
    </code>
  );
}

function Block({ children }: { children: string }) {
  return (
    <pre className="mt-3 overflow-x-auto rounded-lg border border-tc-green/20 bg-black/50 p-4 text-sm">
      <code className="font-mono text-tc-text-dim">{children}</code>
    </pre>
  );
}

export default function SecurityPage() {
  return (
    <main className="min-h-screen bg-tc-darker matrix-bg pt-24">
      <div className="mx-auto max-w-3xl px-6 py-16">
        <header className="mb-10">
          <p className="font-mono-green text-sm uppercase tracking-widest">// transparency</p>
          <h1 className="mt-3 text-4xl font-bold text-tc-text">
            Security &amp; <span className="text-tc-green glow-green">Data Handling</span>
          </h1>
          <p className="mt-4 text-tc-text-dim">
            ThreatCrush is a scanner people run over their own source, often inside CI, with a
            token in scope. That is a position of some trust, so this page states plainly what the
            tool does with your code and your network — and gives you the commands to check every
            claim on it yourself rather than take our word for it.
          </p>
          <p className="mt-2 text-sm text-tc-text-dim">Last updated: August 16, 2026</p>
        </header>

        <div className="space-y-10 text-tc-text">
          <section>
            <h2 className="text-xl font-semibold text-tc-green">
              1. <Code>threatcrush scan</Code> makes no network requests
            </h2>
            <p className="mt-2 text-tc-text-dim">
              The scan reads files and writes a report. It opens no sockets — not to us, not to
              anyone. There is no licence check, no usage ping, no &ldquo;anonymous statistics&rdquo;
              and no update check on the scan path.
            </p>
            <p className="mt-2 text-tc-text-dim">
              You do not have to believe that. Trace the syscalls and count them:
            </p>
            <Block>{`strace -f -qq -e trace=socket,connect,sendto,sendmsg \\
  -o net.trace threatcrush scan .

wc -l net.trace     # 0`}</Block>
            <p className="mt-3 text-tc-text-dim">
              Validate the method with a control, so an empty file means &ldquo;no
              connections&rdquo; rather than &ldquo;strace was not watching&rdquo;:
            </p>
            <Block>{`strace -f -qq -e trace=socket,connect,sendto,sendmsg -o ctl.trace \\
  node -e "fetch('https://registry.npmjs.org/')"

wc -l ctl.trace     # 57`}</Block>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">
              2. One flag opts into the network, and it says so
            </h2>
            <p className="mt-2 text-tc-text-dim">
              <Code>--deps</Code> queries{" "}
              <a className={linkClass} href="https://osv.dev" rel="noopener noreferrer">
                api.osv.dev
              </a>{" "}
              for advisories affecting the versions in your lockfile. It sends package names and
              versions; it does not send your source. Its own help text is marked{" "}
              <Code>(network)</Code>, and it is off unless you type it.
            </p>
            <p className="mt-2 text-tc-text-dim">
              Everything else in <Code>scan</Code> is local. Other CLI commands — signing in,
              publishing modules, managing servers — are network features by definition and are not
              part of scanning.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">3. Telemetry is off unless you turn it on</h2>
            <p className="mt-2 text-tc-text-dim">
              There is error-reporting code in the package, and we would rather describe it than
              have you find it. It is gated on an environment variable you set, there is no DSN
              baked into the build, and it is initialised only by the long-running{" "}
              <Code>daemon</Code> command — never by <Code>scan</Code>:
            </p>
            <Block>{`async function initTelemetry(context) {
  const dsn = process.env.SENTRY_DSN;
  if (!dsn) return;              // unset in CI -> returns here
  await loadSentry();            // @sentry/node imported only past this line
  ...
}`}</Block>
            <p className="mt-3 text-tc-text-dim">
              With <Code>SENTRY_DSN</Code> unset — the default everywhere, including every CI
              runner — the function returns before <Code>@sentry/node</Code> is even imported. If
              you do set it, events go to <em>your</em> Sentry project, performance tracing is
              disabled, and <Code>authorization</Code> and <Code>cookie</Code> headers are stripped
              before send.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">4. Your code stays where it is</h2>
            <ul className="mt-2 list-disc space-y-1 pl-6 text-tc-text-dim">
              <li>No source, diff, filename or finding is uploaded anywhere by <Code>scan</Code>.</li>
              <li>
                Reports are written where you point them — stdout, a file, a CI job summary, a
                SARIF artifact.
              </li>
              <li>
                Matched credential material is redacted before it reaches a terminal, a log or a
                SARIF file. A scanner that prints the secret it found has moved that secret
                somewhere new, and CI logs are retained.
              </li>
              <li>Nothing is written outside the paths you name.</li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">5. Minimum CI permissions</h2>
            <p className="mt-2 text-tc-text-dim">
              A scan needs to read your code. That is all it needs. If you deliver findings through
              the job summary and an artifact, the whole workflow runs read-only:
            </p>
            <Block>{`permissions:
  contents: read`}</Block>
            <p className="mt-3 text-tc-text-dim">
              Add scopes only for the outputs you actually want, and only the scope each one needs:
            </p>
            <ul className="mt-2 list-disc space-y-1 pl-6 text-tc-text-dim">
              <li>
                <Code>security-events: write</Code> — required only to upload SARIF to the Security
                tab.
              </li>
              <li>
                <Code>pull-requests: write</Code> — required only to post findings as a PR comment.
              </li>
            </ul>
            <p className="mt-3 text-tc-text-dim">
              Use <Code>pull_request</Code>, not <Code>pull_request_target</Code>: the latter runs
              with repository secrets in scope against a checkout of untrusted contributor code. We
              do not ship a workflow that uses it.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">6. Supply chain</h2>
            <p className="mt-2 text-tc-text-dim">
              Pin the version <em>and</em> the bytes. A version pin says which release to fetch; it
              does not say the bytes are the ones that release was published with, and the party
              answering &ldquo;which version&rdquo; is the party serving the tarball:
            </p>
            <Block>{`npm pack --pack-destination "$RUNNER_TEMP" @profullstack/threatcrush@0.11.2
got="sha512-$(openssl dgst -sha512 -binary "$RUNNER_TEMP/$name" | openssl base64 -A)"
[ "$got" = "$EXPECTED" ] || exit 1
npm install -g --ignore-scripts "$RUNNER_TEMP/$name"`}</Block>
            <p className="mt-3 text-tc-text-dim">
              ThreatCrush declares no install hook of its own, and <Code>scan</Code> is verified to
              run from an <Code>--ignore-scripts</Code> install — so a security gate never opens a
              shell for its own dependency tree. Published integrity hashes are on npm under{" "}
              <Code>dist.integrity</Code>.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">7. False positives are a bug</h2>
            <p className="mt-2 text-tc-text-dim">
              A report nobody finishes reading is not a gate. We measure the false-positive rate on
              real repositories before claiming anything, and rule changes are checked in both
              directions — a fix has to silence the noise <em>and</em> leave detection unchanged on
              the{" "}
              <a
                className={linkClass}
                href="https://github.com/profullstack/malware-test-prs"
                rel="noopener noreferrer"
              >
                public testbed
              </a>
              . If ThreatCrush flags something that is not a defect, that is a bug worth an issue.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">8. Reporting a vulnerability</h2>
            <p className="mt-2 text-tc-text-dim">
              Report security issues in ThreatCrush itself privately through{" "}
              <a
                className={linkClass}
                href="https://github.com/profullstack/threatcrush/security/advisories/new"
                rel="noopener noreferrer"
              >
                GitHub Security Advisories
              </a>
              . The source is MIT and public at{" "}
              <a
                className={linkClass}
                href="https://github.com/profullstack/threatcrush"
                rel="noopener noreferrer"
              >
                profullstack/threatcrush
              </a>{" "}
              — every claim on this page is checkable against it.
            </p>
          </section>
        </div>
      </div>
    </main>
  );
}
