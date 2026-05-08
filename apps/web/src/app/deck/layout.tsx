import type { ReactNode } from 'react';
import { JetBrains_Mono, Inter_Tight, Instrument_Serif } from 'next/font/google';

const mono = JetBrains_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '700'],
  variable: '--font-deck-mono',
  display: 'swap',
});

const body = Inter_Tight({
  subsets: ['latin'],
  weight: ['400', '500', '600'],
  variable: '--font-deck-body',
  display: 'swap',
});

const serif = Instrument_Serif({
  subsets: ['latin'],
  weight: ['400'],
  style: ['italic', 'normal'],
  variable: '--font-deck-serif',
  display: 'swap',
});

export const metadata = {
  title: 'ThreatCrush — Investor Deck',
  description:
    'ThreatCrush — one agent, two layers. CTEM to find and reduce exposures, SIEM/EDR/SOC to detect and respond. Seed round, 2026.',
};

export default function DeckLayout({ children }: { children: ReactNode }) {
  return (
    <div className={`${mono.variable} ${body.variable} ${serif.variable}`}>
      {children}
    </div>
  );
}
