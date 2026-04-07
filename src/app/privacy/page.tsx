export const metadata = {
  title: "Privacy Policy — ThreatCrush",
  description: "Privacy policy for ThreatCrush.",
};

export default function PrivacyPage() {
  return (
    <main className="min-h-screen bg-tc-darker matrix-bg pt-24">
      <div className="mx-auto max-w-3xl px-6 py-16">
        <header className="mb-10">
          <p className="font-mono-green text-sm uppercase tracking-widest">// legal</p>
          <h1 className="mt-3 text-4xl font-bold text-tc-text">
            Privacy <span className="text-tc-green glow-green">Policy</span>
          </h1>
          <p className="mt-2 text-sm text-tc-text-dim">Last updated: April 7, 2026</p>
        </header>

        <div className="space-y-8 text-tc-text">
          <section>
            <h2 className="text-xl font-semibold text-tc-green">1. Information We Collect</h2>
            <p className="mt-2 text-tc-text-dim">
              We collect information you provide directly — including email, name, phone number,
              and payment details — when you sign up, join the waitlist, or contribute via the
              /investors page. We also collect basic telemetry (IP address, user agent) for
              security and abuse prevention.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">2. How We Use Information</h2>
            <ul className="mt-2 list-disc space-y-1 pl-6 text-tc-text-dim">
              <li>To provide, maintain, and improve the Service</li>
              <li>To process payments and contributions</li>
              <li>To send transactional and security notifications</li>
              <li>To detect and prevent fraud or abuse</li>
              <li>To comply with legal obligations</li>
            </ul>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">3. Sharing</h2>
            <p className="mt-2 text-tc-text-dim">
              We do not sell your personal information. We share data only with the service
              providers required to operate ThreatCrush — including Supabase (database), CoinPay
              (payments), Stripe (card processing via CoinPay), and Telnyx (SMS) — and only as
              needed to deliver the Service.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">4. Data Retention</h2>
            <p className="mt-2 text-tc-text-dim">
              We retain your information for as long as your account is active or as needed to
              comply with legal obligations and resolve disputes. You may request deletion at any
              time.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">5. Security</h2>
            <p className="mt-2 text-tc-text-dim">
              We use industry-standard safeguards including TLS encryption in transit, encrypted
              storage at rest, and least-privilege access controls. No system is perfectly secure;
              we cannot guarantee absolute security.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">6. Cookies</h2>
            <p className="mt-2 text-tc-text-dim">
              We use essential cookies for authentication and session management. We do not use
              third-party advertising cookies.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">7. Your Rights</h2>
            <p className="mt-2 text-tc-text-dim">
              Depending on your jurisdiction, you may have the right to access, correct, delete,
              or export your personal data. Contact us to exercise these rights.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">8. Children</h2>
            <p className="mt-2 text-tc-text-dim">
              ThreatCrush is not directed at children under 13, and we do not knowingly collect
              personal information from them.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">9. Changes</h2>
            <p className="mt-2 text-tc-text-dim">
              We may update this policy from time to time. Material changes will be announced on
              this page.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-tc-green">10. Contact</h2>
            <p className="mt-2 text-tc-text-dim">
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
