import { describe, expect, it, vi } from 'vitest';
import { callingCodeOf, groupMessages, TwilioProvider, type TwilioMessage } from '../providers/twilio.js';

/**
 * Payloads below are the real shape returned by
 * `GET /2010-04-01/Accounts/{sid}/Messages.json` on the attacked account,
 * including Twilio's negative price strings and its RFC-2822 date format.
 */
const REAL_MESSAGES: TwilioMessage[] = [
  // Legitimate US verification, captured 2026-07-28.
  { to: '+14086562473', date_sent: 'Tue, 28 Jul 2026 07:28:42 +0000', price: '-0.00830', status: 'delivered' },
  // Fraud, 2026-07-27 — note the 10x and 55x prices.
  { to: '+358465317194', date_sent: 'Mon, 27 Jul 2026 10:45:19 +0000', price: '-0.08610', status: 'delivered' },
  { to: '+996709961117', date_sent: 'Mon, 27 Jul 2026 10:45:02 +0000', price: '-0.45880', status: 'delivered' },
];

describe('callingCodeOf', () => {
  it('extracts codes from real incident numbers', () => {
    expect(callingCodeOf('+14086562473')).toBe('1');
    expect(callingCodeOf('+996556175367')).toBe('996');
    expect(callingCodeOf('+358465317194')).toBe('358');
    expect(callingCodeOf('+380501234567')).toBe('380');
  });

  it('resolves Myanmar to +95, not the dialled 959 prefix', () => {
    // The audit log shows 959…; the country code is +95 and the 9 is the
    // mobile prefix. Getting this wrong makes the destination list impossible
    // to reconcile with a provider's country picker.
    expect(callingCodeOf('+959651017644')).toBe('95');
  });

  it('separates Kazakhstan from Russia inside +7', () => {
    expect(callingCodeOf('+77012345678')).toBe('77');
    expect(callingCodeOf('+76012345678')).toBe('76');
    expect(callingCodeOf('+79521234567')).toBe('7');
  });

  it('degrades gracefully on junk', () => {
    expect(callingCodeOf(null)).toBe('unknown');
    expect(callingCodeOf('')).toBe('unknown');
    expect(callingCodeOf('not-a-number')).toBe('unknown');
  });
});

describe('groupMessages', () => {
  it('buckets by day and destination, treating negative prices as spend', () => {
    const samples = groupMessages(REAL_MESSAGES);

    expect(samples).toHaveLength(3);

    const kg = samples.find((s) => s.destination === '996');
    expect(kg?.date).toBe('2026-07-27');
    expect(kg?.count).toBe(1);
    expect(kg?.cost).toBeCloseTo(0.4588, 4);

    const us = samples.find((s) => s.destination === '1');
    expect(us?.cost).toBeCloseTo(0.0083, 4);
  });

  it('aggregates repeats into one bucket', () => {
    const samples = groupMessages([
      { to: '+996556175367', date_sent: 'Mon, 29 Jun 2026 08:00:00 +0000', price: '-0.45880' },
      { to: '+996556295567', date_sent: 'Mon, 29 Jun 2026 09:00:00 +0000', price: '-0.45880' },
      { to: '+996552133649', date_sent: 'Mon, 29 Jun 2026 10:00:00 +0000', price: '-0.45880' },
    ]);

    expect(samples).toHaveLength(1);
    expect(samples[0]).toMatchObject({ date: '2026-06-29', destination: '996', count: 3 });
    expect(samples[0].cost).toBeCloseTo(1.3764, 4);
  });

  it('counts unpriced messages as volume without cost', () => {
    const samples = groupMessages([
      { to: '+14086562473', date_created: 'Tue, 28 Jul 2026 07:00:00 +0000', price: null, status: 'queued' },
    ]);

    expect(samples[0].count).toBe(1);
    expect(samples[0].cost).toBe(0);
  });

  it('skips undated and unparseable rows rather than throwing', () => {
    expect(groupMessages([{ to: '+1408', price: '-0.01' }])).toHaveLength(0);
    expect(groupMessages([{ to: '+1408', date_sent: 'never', price: '-0.01' }])).toHaveLength(0);
  });
});

describe('TwilioProvider', () => {
  const creds = { accountSid: 'AC0000000000000000000000000000dead', authToken: 'token' };

  it('reads the balance', async () => {
    const fakeFetch = vi.fn(async () =>
      new Response(JSON.stringify({ balance: '17.9294', currency: 'USD' }), { status: 200 }),
    );

    const snapshot = await new TwilioProvider(creds, fakeFetch as unknown as typeof fetch).fetchBalance();

    expect(snapshot?.balance).toBeCloseTo(17.9294, 4);
    expect(snapshot?.currency).toBe('USD');
    // Twilio has no public auto-recharge endpoint — must be asserted in config.
    expect(snapshot?.autoRechargeEnabled).toBeNull();
  });

  it('surfaces a 401 with the 20003 hint instead of a bare status', async () => {
    const fakeFetch = vi.fn(async () => new Response('{}', { status: 401 }));
    const provider = new TwilioProvider(creds, fakeFetch as unknown as typeof fetch);

    await expect(provider.fetchBalance()).rejects.toThrow(/20003/);
  });

  it('follows pagination and honours the message cap', async () => {
    const page = (next: string | null) =>
      new Response(
        JSON.stringify({
          messages: [
            { to: '+996556175367', date_sent: 'Mon, 29 Jun 2026 08:00:00 +0000', price: '-0.45880' },
          ],
          next_page_uri: next,
        }),
        { status: 200 },
      );

    const fakeFetch = vi
      .fn()
      .mockResolvedValueOnce(page('/2010-04-01/Accounts/x/Messages.json?Page=1'))
      .mockResolvedValueOnce(page(null));

    const provider = new TwilioProvider(creds, fakeFetch as unknown as typeof fetch, 10);
    const samples = await provider.fetchUsage('2026-06-01');

    expect(fakeFetch).toHaveBeenCalledTimes(2);
    expect(samples).toHaveLength(1);
    expect(samples[0].count).toBe(2);
  });

  it('stops paging once the cap is reached', async () => {
    const fakeFetch = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            messages: [
              { to: '+996556175367', date_sent: 'Mon, 29 Jun 2026 08:00:00 +0000', price: '-0.45880' },
            ],
            next_page_uri: '/2010-04-01/Accounts/x/Messages.json?Page=next',
          }),
          { status: 200 },
        ),
    );

    const provider = new TwilioProvider(creds, fakeFetch as unknown as typeof fetch, 1);
    await provider.fetchUsage('2026-06-01');

    // Cap is 1, so exactly one page is pulled despite next_page_uri always set.
    expect(fakeFetch).toHaveBeenCalledTimes(1);
  });
});
