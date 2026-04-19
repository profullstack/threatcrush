import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { parseWalletPaste, formatWalletCopyText, SUPPORTED_PAYOUT_COINS } from '@/lib/wallet-import';

describe('lib/wallet-import', () => {
  describe('SUPPORTED_PAYOUT_COINS', () => {
    it('includes all major cryptocurrencies', () => {
      expect(SUPPORTED_PAYOUT_COINS).toContain('BTC');
      expect(SUPPORTED_PAYOUT_COINS).toContain('ETH');
      expect(SUPPORTED_PAYOUT_COINS).toContain('SOL');
      expect(SUPPORTED_PAYOUT_COINS).toContain('USDC');
      expect(SUPPORTED_PAYOUT_COINS).toContain('USDT');
    });

    it('includes CoinPay-specific variants', () => {
      expect(SUPPORTED_PAYOUT_COINS).toContain('USDC_SOL');
      expect(SUPPORTED_PAYOUT_COINS).toContain('USDC_ETH');
      expect(SUPPORTED_PAYOUT_COINS).toContain('USDC_POL');
      expect(SUPPORTED_PAYOUT_COINS).toContain('USDT_SOL');
    });
  });

  describe('parseWalletPaste', () => {
    it('parses standard CoinPay format', () => {
      const input = `BTC: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh
USDC_SOL: FX8QhU1TPUHGs2X8PibbHikd4YvdQMPfVuFd6mqk9qJw
ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb`;

      const result = parseWalletPaste(input);
      expect(result.wallets).toHaveLength(3);
      expect(result.wallets[0]).toEqual({
        coin: 'BTC',
        address: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
        label: undefined,
        rawLine: 'BTC: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
      });
      expect(result.invalidLines).toHaveLength(0);
      expect(result.unsupportedCoins).toHaveLength(0);
    });

    it('parses format with labels', () => {
      const input = `USDC_POL (Treasury): 0xEf993488b444b75585A5CCe171e65F4dD9D99add
BTC (Cold Storage): bc1qexample`;

      const result = parseWalletPaste(input);
      expect(result.wallets).toHaveLength(2);
      expect(result.wallets[0].label).toBe('Treasury');
      expect(result.wallets[1].label).toBe('Cold Storage');
    });

    it('ignores empty lines and comments', () => {
      const input = `# My wallets
BTC: bc1qexample

ETH: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb
`;
      const result = parseWalletPaste(input);
      expect(result.wallets).toHaveLength(2);
      expect(result.invalidLines).toHaveLength(0);
    });

    it('detects invalid lines', () => {
      const input = `BTC: bc1qexample
INVALID_LINE_NO_COLON
: missing_coin
XRP: `;
      const result = parseWalletPaste(input);
      expect(result.wallets).toHaveLength(1);
      expect(result.invalidLines.length).toBeGreaterThanOrEqual(2);
    });

    it('detects unsupported coins', () => {
      const input = `FAKECOIN: address123
BTC: bc1qexample`;
      const result = parseWalletPaste(input);
      expect(result.wallets).toHaveLength(1);
      expect(result.unsupportedCoins).toContain('FAKECOIN');
    });

    it('deduplicates by coin (last wins)', () => {
      const input = `BTC: bc1qfirst12345
BTC: bc1qsecond67890`;
      const result = parseWalletPaste(input);
      expect(result.wallets).toHaveLength(1);
      expect(result.wallets[0].address).toBe('bc1qsecond67890');
      expect(result.duplicateCoins).toContain('BTC');
    });

    it('returns empty result for empty input', () => {
      const result = parseWalletPaste('');
      expect(result.wallets).toHaveLength(0);
    });

    it('handles single wallet line', () => {
      const result = parseWalletPaste('SOL: 7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU');
      expect(result.wallets).toHaveLength(1);
      expect(result.wallets[0].coin).toBe('SOL');
    });
  });

  describe('formatWalletCopyText', () => {
    it('formats wallets for clipboard copy', () => {
      const wallets = [
        { coin: 'BTC', address: 'bc1qexample' },
        { coin: 'USDC_SOL', address: 'FX8QhU1', label: 'Main' },
      ];
      const result = formatWalletCopyText(wallets);
      expect(result).toBe(`BTC: bc1qexample
USDC_SOL (Main): FX8QhU1`);
    });

    it('returns empty string for empty array', () => {
      expect(formatWalletCopyText([])).toBe('');
    });
  });
});
