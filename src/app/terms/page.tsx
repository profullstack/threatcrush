export const metadata = {
  title: "Terms of Service — ThreatCrush",
  description: "Terms of service for ThreatCrush.",
};

export default function TermsPage() {
  return (
    <main className="min-h-screen bg-tc-darker matrix-bg pt-24">
      <div className="mx-auto max-w-3xl px-6 py-16">
        <header className="mb-10">
          <p className="font-mono-green text-sm uppercase tracking-widest">// legal</p>
          <h1 className="mt-3 text-4xl font-bold text-tc-text">
            Terms of <span className="text-tc-green glow-green">Service</span>
          </h1>
          <p className="mt-2 text-sm text-tc-text-dim">Last updated: April 7, 2026</p>
        </header>

        <div className="space-y-8 text-tc-text">
          <section>
            <h2 className="text-xl font-semibold text-tc-green">1. Acceptance of Terms</h2>
            <p className="mt-2 text-tc-text-dim">
              By accessing or using ThreatCrush (the &ldquo;Service&rdquo;), you agree to be bound
              by these Terms of Service. If you do not agree, do not use the Service.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">2. Use of the Service</h2>
            <p className="mt-2 text-tc-text-dim">
              ThreatCrush provides threat intelligence, vulnerability scanning, and active defense
              tooling. You agree to use the Service only against systems you own or have explicit
              written authorization to test. Any unauthorized use against third-party
              infrastructure is strictly prohibited.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">3. Accounts</h2>
            <p className="mt-2 text-tc-text-dim">
              You are responsible for safeguarding your account credentials and for all activity
              that occurs under your account. Notify us immediately of any unauthorized use.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">4. Payments and Refunds</h2>
            <p className="mt-2 text-tc-text-dim">
              Lifetime licenses are payable via credit card or cryptocurrency through our payment
              processors. Refunds are available within 30 days of purchase if you are not
              satisfied. Investor contributions made via /investors are non-refundable except
              where required by law.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">5. Intellectual Property</h2>
            <p className="mt-2 text-tc-text-dim">
              All content, code, and trademarks associated with ThreatCrush are the property of
              Profullstack, Inc. or its licensors. Open-source components are governed by their
              respective licenses.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">6. Disclaimer of Warranties</h2>
            <p className="mt-2 text-tc-text-dim">
              The Service is provided &ldquo;as is&rdquo; without warranties of any kind. We do
              not guarantee that the Service will be uninterrupted, secure, or error-free.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">7. Limitation of Liability</h2>
            <p className="mt-2 text-tc-text-dim">
              To the maximum extent permitted by law, Profullstack, Inc. shall not be liable for
              any indirect, incidental, special, consequential, or punitive damages arising out of
              your use of the Service.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">8. Changes to Terms</h2>
            <p className="mt-2 text-tc-text-dim">
              We may update these Terms from time to time. Continued use of the Service after
              changes constitutes acceptance of the revised Terms.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">9. Contact</h2>
            <p className="mt-2 text-tc-text-dim">
              Questions about these Terms? Email{" "}
              <a href="mailto:legal@threatcrush.com" className="text-tc-green hover:underline">
                legal@threatcrush.com
              </a>
              .
            </p>
          </section>
        </div>
      </div>
    </main>
  );
}
