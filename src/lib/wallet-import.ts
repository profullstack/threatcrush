/**
 * Wallet address paste parser for referral payout wallet import.
 * Compatible with CoinPayPortal's web wallet "Copy All Addresses" format.
 *
 * Format:
 *   BTC: bc1qexample
 *   USDC_SOL: FX8QhU1TPUHGs2X8PibbHikd4YvdQMPfVuFd6mqk9qJw
 *   USDC_POL (Label): 0xEf993488b444b75585A5CCe171e65F4dD9D99add
 */

export const SUPPORTED_PAYOUT_COINS = [
  "BTC",
  "ETH",
  "SOL",
  "USDT",
  "USDC",
  "USDC_ETH",
  "USDC_SOL",
  "USDC_POL",
  "USDT_ETH",
  "USDT_SOL",
  "USDT_POL",
  "BNB",
  "XRP",
  "ADA",
  "DOGE",
  "POL",
  "BCH",
] as const;

export type PayoutCoin = (typeof SUPPORTED_PAYOUT_COINS)[number];

const supportedSet = new Set(SUPPORTED_PAYOUT_COINS);

export interface ParsedWalletLine {
  coin: string;
  address: string;
  label?: string;
  rawLine: string;
}

export interface WalletImportResult {
  wallets: ParsedWalletLine[];
  invalidLines: string[];
  unsupportedCoins: string[];
  duplicateCoins: string[];
}

/**
 * Parse wallet addresses from clipboard text in CoinPay format.
 * Handles lines like:
 *   "BTC: address"
 *   "USDC_POL (Treasury): address"
 */
export function parseWalletPaste(text: string): WalletImportResult {
  const invalidLines: string[] = [];
  const unsupportedCoins: string[] = [];
  const duplicateCoins: string[] = [];
  const seen = new Set<string>();
  const wallets: ParsedWalletLine[] = [];

  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const colonIdx = line.indexOf(":");
    if (colonIdx <= 0 || colonIdx === line.length - 1) {
      invalidLines.push(line);
      continue;
    }

    let coinPart = line.slice(0, colonIdx).trim().toUpperCase();
    const address = line.slice(colonIdx + 1).trim();

    // Strip label if present: "USDC_POL (Label)" -> "USDC_POL"
    let label: string | undefined;
    const labelMatch = coinPart.match(/^([A-Z_]+)\s*\(([^)]+)\)$/);
    if (labelMatch) {
      coinPart = labelMatch[1];
      label = labelMatch[2];
    }

    if (!supportedSet.has(coinPart as PayoutCoin)) {
      unsupportedCoins.push(coinPart);
      continue;
    }

    if (!address || address.length < 10) {
      invalidLines.push(line);
      continue;
    }

    if (seen.has(coinPart)) {
      duplicateCoins.push(coinPart);
    }

    seen.add(coinPart);
    wallets.push({ coin: coinPart, address, label, rawLine: line });
  }

  return {
    wallets,
    invalidLines,
    unsupportedCoins: [...new Set(unsupportedCoins)],
    duplicateCoins: [...new Set(duplicateCoins)],
  };
}

/**
 * Format wallet addresses for clipboard copy (CoinPay-compatible).
 */
export function formatWalletCopyText(
  wallets: Array<{ coin: string; address: string; label?: string }>
): string {
  return wallets
    .map((w) => {
      const label = w.label ? ` (${w.label})` : "";
      return `${w.coin}${label}: ${w.address}`;
    })
    .join("\n");
}
