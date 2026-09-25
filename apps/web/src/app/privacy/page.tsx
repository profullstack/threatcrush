export const metadata = {
  title: "Privacy Policy — ThreatCrush",
  description: "Privacy policy for ThreatCrush.",
};

const h2 = "text-xl font-semibold text-tc-green";
const p = "mt-2 text-tc-text-dim";
const ul = "mt-2 list-disc space-y-2 pl-6 text-tc-text-dim";
const code = "rounded bg-black/40 px-1.5 py-0.5 font-mono text-sm text-tc-green";

export default function PrivacyPage() {
  return (
    <main className="min-h-screen bg-tc-darker matrix-bg pt-24">
      <div className="mx-auto max-w-3xl px-6 py-16">
        <header className="mb-10">
          <p className="font-mono-green text-sm uppercase tracking-widest">// legal</p>
          <h1 className="mt-3 text-4xl font-bold text-tc-text">
            Privacy <span className="text-tc-green glow-green">Policy</span>
          </h1>
          <p className="mt-2 text-sm text-tc-text-dim">Last updated: September 25, 2026</p>
        </header>

        <div className="space-y-8 text-tc-text">
          <section>
            <h2 className={h2}>1. Scope</h2>
            <p className={p}>
              This policy covers threatcrush.com, the ThreatCrush cloud dashboard and API, and the
              data the ThreatCrush CLI, daemon, desktop app, mobile app and browser extension send
              to us. The CLI and daemon run on your own machines; what they do locally stays there
              unless this policy says otherwise.
            </p>
          </section>

          <section>
            <h2 className={h2}>2. Information We Collect</h2>
            <ul className={ul}>
              <li>
                <span className="text-tc-text">Account.</span> Email address, password (handled by
                our sign-in service; we never see it in plain text), display name, phone number and
                its verification status, and your GitHub identity if you sign in with GitHub. If you
                use the referral program: your referral code and the crypto wallet addresses you add
                for payouts. Notification preferences you set in Account settings.
              </li>
              <li>
                <span className="text-tc-text">Organizations.</span> Organizations and their
                members, the targets you add (URLs, APIs, domains, IP addresses, repositories), scan
                and pentest results, allowlists, and alert destinations — including the Slack,
                Discord or webhook URLs, email addresses and PagerDuty keys you enter.
              </li>
              <li>
                <span className="text-tc-text">Linked servers.</span> Only when you are signed in
                and have run <code className={code}>threatcrush servers link</code> on a server, its
                daemon sends us: the server&apos;s hostname and daemon version, a heartbeat; each
                detection, including the source IP address, the username involved (for example in a
                failed SSH login), the rule, severity, and log or request details (up to 16 KB per
                detection); hardening check results; and the IP bans and unbans it carries out. An
                unlinked daemon sends none of this. The CLI keeps your sign-in tokens on the machine
                in <code className={code}>~/.threatcrush/config.json</code>.
              </li>
              <li>
                <span className="text-tc-text">GitHub App.</span> If you install the ThreatCrush
                GitHub App, we read the file list and file contents of the repositories you grant it
                through the GitHub API and scan them in memory; we do not clone them. We store the
                installation (account login, repository names, whether each is private) and the
                findings (file path, line number, rule, and the matched line of code).
              </li>
              <li>
                <span className="text-tc-text">Payments.</span> Payments go through CoinPayPortal;
                card payments are processed by Stripe through CoinPayPortal. We store the payment
                ID, amount, currency, status and your email address. We never see your card number.
                For contributions on /investors we store the name and email you enter (both
                optional), the amount and the transaction hash.
              </li>
              <li>
                <span className="text-tc-text">Forms.</span> Waitlist: your email. Contact and
                /hire form: name, email, company and your message. Guide and whitepaper downloads:
                name, email, company, role, team size, your marketing-email choice, campaign (UTM)
                parameters, and your IP address and browser user agent.
              </li>
              <li>
                <span className="text-tc-text">Push notifications.</span> If you enable them, your
                browser&apos;s push subscription (endpoint and keys) or your mobile app&apos;s Expo
                push token, tied to your account and organization.
              </li>
              <li>
                <span className="text-tc-text">Browser extension.</span> Page checks run entirely
                in your browser and send nothing to us. When you are signed in, the extension calls
                our API with your session (for example to show new detections for your
                organization). If you ask it to scan a URL, that URL is sent to our API.
              </li>
            </ul>
          </section>

          <section>
            <h2 className={h2}>3. How We Use Information</h2>
            <ul className={ul}>
              <li>To provide the Service: show your data in the dashboard and apps, run scans, and carry out the bans you ask for</li>
              <li>To send the alerts you configure, and transactional email and SMS (verification codes)</li>
              <li>To process payments, contributions and referral payouts</li>
              <li>To detect and prevent fraud or abuse</li>
              <li>To comply with legal obligations</li>
            </ul>
          </section>

          <section>
            <h2 className={h2}>4. Service Providers and Other Recipients</h2>
            <p className={p}>
              We do not sell your personal information. Our database and sign-in run on Supabase
              software that we host ourselves. We share data with these providers only as needed to
              run the Service:
            </p>
            <ul className={ul}>
              <li><span className="text-tc-text">CoinPayPortal and Stripe</span> — payments (amount, currency, your email, card details you enter on their checkout).</li>
              <li><span className="text-tc-text">Telnyx</span> — sends phone verification codes (your phone number and the code).</li>
              <li><span className="text-tc-text">Resend</span> — delivers the email we send, such as contact-form notifications and guide downloads.</li>
              <li><span className="text-tc-text">GitHub</span> — sign-in with GitHub and the GitHub App.</li>
              <li><span className="text-tc-text">Expo, Apple and Google</span> — deliver mobile push notifications; your browser vendor&apos;s push service delivers web push notifications. Notifications contain the alert text.</li>
              <li><span className="text-tc-text">Sentry</span> — if error reporting is enabled: server-side errors from the website (the error, request method and path), and errors from the CLI or daemon (stack trace, environment, software version, host name).</li>
              <li><span className="text-tc-text">Your alert destinations</span> — detection details (title, severity, server, source IP) go to the Slack, Discord, PagerDuty, email or webhook destinations you configure; their own policies apply.</li>
              <li><span className="text-tc-text">OSV.dev</span> — <code className={code}>threatcrush scan --deps</code> sends the package names and versions from your lockfiles to OSV.dev directly from your machine.</li>
            </ul>
          </section>

          <section>
            <h2 className={h2}>5. Website Analytics and Third-Party Scripts</h2>
            <p className={p}>Pages on threatcrush.com load:</p>
            <ul className={ul}>
              <li><span className="text-tc-text">DataFast</span> (datafa.st) — website analytics.</li>
              <li><span className="text-tc-text">Robauto</span> (robauto.ai) — a pixel script, and a beacon that sends the page path, URL and referrer to Robauto&apos;s tracking endpoint.</li>
              <li><span className="text-tc-text">Crawlproof</span> (crawlproof.com) — a statistics script.</li>
              <li><span className="text-tc-text">Profullstack Feedback</span> (feedback.profullstack.com) — the feedback widget; feedback you submit goes to that service.</li>
              <li><span className="text-tc-text">Google Fonts</span> (fonts.googleapis.com) — web fonts; your browser requests them from Google.</li>
            </ul>
            <p className={p}>
              These providers receive your IP address and browser details when your browser loads
              them, and may set their own cookies or identifiers.
            </p>
          </section>

          <section>
            <h2 className={h2}>6. What Is Public</h2>
            <ul className={ul}>
              <li>
                <span className="text-tc-text">GitHub App findings.</span> Findings in the{" "}
                <em>public</em> repositories of an installation are published on{" "}
                <a href="/discovery" className="text-tc-green hover:underline">/discovery</a> and at{" "}
                <code className={code}>/.well-known/openthreat.json</code>. This is on by default;
                the person who installed the app can turn it off per installation in Account
                settings. Private repositories, organizations, servers, targets and detections are
                never published.
              </li>
              <li>
                <span className="text-tc-text">Contributions.</span> For confirmed contributions,
                the name you entered and the amount are shown under &ldquo;Recent backers&rdquo; on
                /investors.
              </li>
              <li>
                <span className="text-tc-text">Module Store.</span> Modules you publish, with their
                author name, and reviews you post (with your email address partly masked) are
                public.
              </li>
            </ul>
          </section>

          <section>
            <h2 className={h2}>7. Data Retention and Deletion</h2>
            <p className={p}>
              Phone verification codes expire after 10 minutes. Everything else is kept until you
              delete it or your account. Deleting a server or organization deletes its detections,
              hardening findings, bans and alert settings.
            </p>
            <p className={p}>
              You can delete your account yourself from Account settings. This deletes your
              sign-in, profile, organization memberships, push subscriptions, payment and referral
              records tied to your account, and every organization where you are the only member,
              with its servers and their data. Organizations you share with others stay, as does
              data you created in them. Waitlist, contact-form, guide-download and /investors
              records, and Module Store reviews, are not tied to your account; email us to have
              them removed.
            </p>
          </section>

          <section>
            <h2 className={h2}>8. Security</h2>
            <p className={p}>
              Data travels to us over TLS, and access to stored data is restricted to your
              account and the members of your organizations. No system is perfectly secure; we
              cannot guarantee absolute security.
            </p>
          </section>

          <section>
            <h2 className={h2}>9. Cookies and Local Storage</h2>
            <p className={p}>
              Your sign-in session is kept in your browser&apos;s local storage. We do not use
              advertising cookies. The analytics and third-party scripts listed in section 5 may
              set their own cookies or identifiers.
            </p>
          </section>

          <section>
            <h2 className={h2}>10. Your Rights</h2>
            <p className={p}>
              Depending on your jurisdiction, you may have the right to access, correct, delete,
              or export your personal data. Contact us to exercise these rights.
            </p>
          </section>

          <section>
            <h2 className={h2}>11. Children</h2>
            <p className={p}>
              ThreatCrush is not directed at children under 13, and we do not knowingly collect
              personal information from them.
            </p>
          </section>

          <section>
            <h2 className={h2}>12. Changes</h2>
            <p className={p}>
              We may update this policy from time to time. Material changes will be announced on
              this page.
            </p>
          </section>

          <section>
            <h2 className={h2}>13. Contact</h2>
            <p className={p}>
              Privacy questions? Email{" "}
              <a href="mailto:privacy@threatcrush.com" className="text-tc-green hover:underline">
                privacy@threatcrush.com
              </a>
              .
            </p>
          </section>
        </div>
      </div>
    </main>
  );
}
