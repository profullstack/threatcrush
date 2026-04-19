import { FundingClient } from '@/components/funding/FundingClient';
import { FundingProgress } from '@/components/funding/FundingProgress';
import { TopContributors } from '@/components/funding/TopContributors';
import { PaymentStatus } from '@/components/funding/PaymentStatus';
import { FUNDING_GOAL_USD } from '@/lib/funding';

export const metadata = {
  title: 'Invest in threatcrush',
  description:
    'Back threatcrush — open-source threat intelligence tooling. Contribute via credit card or crypto.',
};

export default function InvestorsPage() {
  return (
    <main className="min-h-screen bg-tc-darker matrix-bg">
      <div className="mx-auto max-w-5xl px-6 py-16 sm:py-24">
        <header className="mb-12 text-center">
          <p className="font-mono-green text-sm uppercase tracking-widest">// invest</p>
          <h1 className="mt-3 text-4xl font-bold text-tc-text sm:text-5xl">
            Invest in <span className="text-tc-green glow-green">threatcrush</span>
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-tc-text-dim">
            Back the team building open-source threat intelligence tooling. Contribute with a
            credit card or crypto — both rails are processed by CoinPay.
          </p>
        </header>

        <div className="space-y-6">
          <PaymentStatus />
          <FundingProgress goal={FUNDING_GOAL_USD} />
          <FundingClient />
        </div>

        <section className="mt-16">
          <h2 className="mb-4 text-xl font-semibold text-tc-text">Recent backers</h2>
          <TopContributors />
        </section>

        <section className="mt-16 rounded-2xl border border-tc-border bg-tc-card p-6">
          <h2 className="text-xl font-semibold text-tc-text">Prefer to talk first?</h2>
          <p className="mt-2 text-sm text-tc-text-dim">
            For larger contributions or strategic partnerships, reach out at{' '}
            <a
              href="mailto:invest@threatcrush.com"
              className="text-tc-green underline hover:glow-green"
            >
              invest@threatcrush.com
            </a>
            .
          </p>
        </section>
      </div>
    </main>
  );
}
