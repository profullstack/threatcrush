/**
 * Twilio connector — the reference implementation.
 *
 * Chosen first because it is where the motivating incident happened, and
 * because SMS is the most commonly pumped resource. Usage is read from the
 * Messages resource rather than Usage Records: the daily rollup gives totals
 * but no destination, and destination is what separates a pumping run from a
 * genuine international market.
 */

import type { UsageSample } from '../detectors.js';
import { ProviderError, type BalanceSnapshot, type SpendProvider } from './types.js';

const API_ROOT = 'https://api.twilio.com/2010-04-01';

/** Subset of Twilio's Message resource that we rely on. */
export interface TwilioMessage {
  to?: string | null;
  date_sent?: string | null;
  date_created?: string | null;
  /** Twilio reports outbound price as a negative string, e.g. "-0.00830". */
  price?: string | null;
  status?: string | null;
}

/**
 * Longest-match country calling codes.
 *
 * Only codes we need to tell apart are listed; anything else falls back to a
 * coarse prefix. Note '7' is deliberately split — Kazakhstan (+7 6xx/7xx) is a
 * frequent pumping destination while Russia (+7 9xx) is a normal user base, so
 * collapsing them into one bucket would make the destination signal useless.
 */
const CALLING_CODES = [
  '996', '998', '995', '994', '993', '992', '977', '976', '975', '974', '973',
  '972', '971', '968', '967', '966', '965', '964', '963', '962', '961', '960',
  '880', '856', '855', '853', '852', '850', '692', '691', '690', '689', '688',
  '687', '686', '685', '684', '683', '682', '681', '680', '679', '678', '677',
  '676', '675', '674', '673', '672', '670', '599', '598', '597', '596', '595',
  '594', '593', '592', '591', '590', '509', '508', '507', '506', '505', '504',
  '503', '502', '501', '500', '423', '421', '420', '389', '387', '386', '385',
  '381', '380', '378', '377', '376', '375', '374', '373', '372', '371', '370',
  '359', '358', '357', '356', '355', '354', '353', '352', '351', '350', '299',
  '298', '297', '291', '290', '269', '268', '267', '266', '265', '264', '263',
  '262', '261', '260', '258', '257', '256', '255', '254', '253', '252', '251',
  '250', '249', '248', '247', '246', '245', '244', '243', '242', '241', '240',
  '239', '238', '237', '236', '235', '234', '233', '232', '231', '230', '229',
  '228', '227', '226', '225', '224', '223', '222', '221', '220', '218', '216',
  '213', '212', '211', '98', '95', '94', '93', '92', '91', '90', '86', '84',
  '82', '81', '77', '76', '66', '65', '64', '63', '62', '61', '60', '58', '57',
  '56', '55', '54', '53', '52', '51', '49', '48', '47', '46', '45', '44', '43',
  '41', '40', '39', '36', '34', '33', '32', '31', '30', '27', '20', '7', '1',
].sort((a, b) => b.length - a.length);

/** Extract the ITU country calling code from an E.164 number. */
export function callingCodeOf(e164: string | null | undefined): string {
  if (!e164) return 'unknown';
  const digits = e164.replace(/\D/g, '');
  if (!digits) return 'unknown';
  return CALLING_CODES.find((code) => digits.startsWith(code)) ?? digits.slice(0, 3);
}

/**
 * Collapse raw messages into per-day, per-destination usage samples.
 *
 * Pure so it can be tested against captured API payloads without network access.
 */
export function groupMessages(messages: TwilioMessage[]): UsageSample[] {
  const buckets = new Map<string, UsageSample>();

  for (const msg of messages) {
    const stamp = msg.date_sent || msg.date_created;
    if (!stamp) continue;

    const parsed = new Date(stamp);
    if (Number.isNaN(parsed.getTime())) continue;

    const date = parsed.toISOString().slice(0, 10);
    const destination = callingCodeOf(msg.to);
    const key = `${date}|${destination}`;

    // Twilio prices outbound traffic negatively; unpriced messages (queued,
    // failed before submission) contribute volume but no cost.
    const cost = Math.abs(Number.parseFloat(msg.price ?? '0') || 0);

    const existing = buckets.get(key);
    if (existing) {
      existing.count += 1;
      existing.cost += cost;
    } else {
      buckets.set(key, { date, destination, count: 1, cost });
    }
  }

  return [...buckets.values()].sort((a, b) => a.date.localeCompare(b.date));
}

export interface TwilioCredentials {
  accountSid: string;
  authToken: string;
}

export class TwilioProvider implements SpendProvider {
  readonly name = 'twilio';

  constructor(
    private readonly creds: TwilioCredentials,
    private readonly fetchImpl: typeof fetch = fetch,
    /** Hard cap on messages pulled per poll, to bound memory and API cost. */
    private readonly maxMessages = 1000,
  ) {}

  private authHeader(): string {
    const raw = `${this.creds.accountSid}:${this.creds.authToken}`;
    return `Basic ${Buffer.from(raw).toString('base64')}`;
  }

  private async get<T>(path: string): Promise<T> {
    const res = await this.fetchImpl(`${API_ROOT}${path}`, {
      headers: { Authorization: this.authHeader(), Accept: 'application/json' },
    });

    if (!res.ok) {
      // 20003 is Twilio's authentication failure. Surfacing it distinctly
      // matters: during the reference incident it was mistaken for the attack
      // stopping, when in fact the credentials had been rotated.
      const hint = res.status === 401 ? ' (check credentials — Twilio error 20003)' : '';
      throw new ProviderError(`Twilio ${path} returned HTTP ${res.status}${hint}`, this.name, res.status);
    }

    return (await res.json()) as T;
  }

  async fetchUsage(sinceIsoDate: string): Promise<UsageSample[]> {
    const collected: TwilioMessage[] = [];
    let page: string | null =
      `/Accounts/${this.creds.accountSid}/Messages.json?PageSize=1000&DateSent%3E=${sinceIsoDate}`;

    while (page && collected.length < this.maxMessages) {
      const body: { messages?: TwilioMessage[]; next_page_uri?: string | null } =
        await this.get(page);

      collected.push(...(body.messages ?? []));
      page = body.next_page_uri ? body.next_page_uri.replace('/2010-04-01', '') : null;
    }

    return groupMessages(collected.slice(0, this.maxMessages));
  }

  async fetchBalance(): Promise<BalanceSnapshot | null> {
    const body: { balance?: string; currency?: string } = await this.get(
      `/Accounts/${this.creds.accountSid}/Balance.json`,
    );

    return {
      balance: Number.parseFloat(body.balance ?? '0') || 0,
      currency: body.currency ?? 'USD',
      // Twilio does not expose auto-recharge state over the public API, so the
      // operator asserts it in config instead.
      autoRechargeEnabled: null,
    };
  }
}
