import Link from "next/link";

export const metadata = {
  title: "GitHub App Installed — ThreatCrush",
  description:
    "Confirmation that the ThreatCrush GitHub App is installed on your account or organisation, and what to do next.",
  robots: { index: false, follow: false },
};

const linkClass = "text-tc-green underline underline-offset-4 hover:opacity-80";

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="rounded bg-black/40 px-1.5 py-0.5 font-mono text-[0.9em] text-tc-green">
      {children}
    </code>
  );
}

/**
 * `setup_action=request` means a non-admin asked an organisation owner to
 * approve the install — nothing is installed yet, and saying otherwise would be
 * the one claim on this page that is not true.
 */
const HEADINGS = {
  install: { kicker: "// installed", title: "GitHub App", accent: "Installed" },
  update: { kicker: "// updated", title: "Installation", accent: "Updated" },
  request: { kicker: "// pending approval", title: "Approval", accent: "Requested" },
} as const;

type SetupAction = keyof typeof HEADINGS;

function asSetupAction(value: string | string[] | undefined): SetupAction {
  const first = Array.isArray(value) ? value[0] : value;
  return first === "update" || first === "request" ? first : "install";
}

export default async function GitHubInstalledPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const action = asSetupAction(params.setup_action);
  const rawId = Array.isArray(params.installation_id)
    ? params.installation_id[0]
    : params.installation_id;
  const installationId = rawId && /^\d{1,20}$/.test(rawId) ? rawId : null;
  const heading = HEADINGS[action];

  return (
    <main className="min-h-screen bg-tc-darker matrix-bg pt-24">
      <div className="mx-auto max-w-2xl px-6 py-16">
        <header className="mb-10">
          <p className="font-mono-green text-sm uppercase tracking-widest">{heading.kicker}</p>
          <h1 className="mt-3 text-4xl font-bold text-tc-text">
            {heading.title} <span className="text-tc-green glow-green">{heading.accent}</span>
          </h1>
          {action === "request" ? (
            <p className="mt-4 text-tc-text-dim">
              Your request to install ThreatCrush has gone to the owners of that organisation.
              Nothing is installed until one of them approves it, and GitHub will email you when
              they do.
            </p>
          ) : (
            <p className="mt-4 text-tc-text-dim">
              ThreatCrush now has access to the repositories you selected. You can change that
              selection, or remove the app entirely, from your GitHub settings at any time.
            </p>
          )}
          {installationId && (
            <p className="mt-4 text-sm text-tc-text-dim">
              Installation ID: <Code>{installationId}</Code>
            </p>
          )}
        </header>

        <div className="space-y-8 text-tc-text">
          <section>
            <h2 className="text-xl font-semibold text-tc-green">Next</h2>
            <ul className="mt-3 space-y-3 text-tc-text-dim">
              <li>
                <Link href="/auth/login" className={linkClass}>
                  Sign in to ThreatCrush
                </Link>{" "}
                — or{" "}
                <Link href="/auth/signup" className={linkClass}>
                  create an account
                </Link>{" "}
                if you do not have one yet.
              </li>
              <li>
                Scan locally in the meantime: <Code>npm i -g @profullstack/threatcrush</Code> then{" "}
                <Code>threatcrush scan .</Code> — it opens no sockets, as the{" "}
                <Link href="/security" className={linkClass}>
                  security page
                </Link>{" "}
                sets out.
              </li>
              <li>
                <Link href="/docs" className={linkClass}>
                  Read the docs
                </Link>{" "}
                for what the scanner looks for and how to wire it into CI.
              </li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">Something wrong?</h2>
            <p className="mt-2 text-tc-text-dim">
              If this page is not what you expected, tell us from{" "}
              <Link href="/about" className={linkClass}>
                the about page
              </Link>{" "}
              and quote the installation ID above.
            </p>
          </section>
        </div>
      </div>
    </main>
  );
}
