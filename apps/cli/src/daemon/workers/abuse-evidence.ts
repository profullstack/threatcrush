import { isIP } from 'node:net';
import type { ThreatEvent } from '../../types/events.js';
import { DEFAULT_PROTECTED, isProtected } from '../firewall/protected.js';

/**
 * The evidence bar from PRD 0015 — the whole point of the abuse-reporter.
 *
 * Reporting a source is a public accusation about someone else's machine, and
 * the usual attack source is a *victim*: a hacked VPS, an infected router, a
 * CGNAT gateway shared by thousands, or a spoofed address chosen to weaponize
 * us into a reputation attack. So this module's job is to make a false report
 * structurally hard to produce, even at the cost of under-reporting real abuse.
 *
 * Everything here is pure so it can be asserted by test: the success metric is
 * *zero* reports for spoofable, private, protected or carrier-range sources.
 */

/**
 * R3: addresses that are never reportable, on top of the operator's own
 * `never_report` list and the firewall's protected set.
 *
 * CGNAT/carrier (RFC 6598 100.64/10) and shared ranges attribute one attack to
 * many innocent users; documentation and benchmark ranges should never appear
 * in real traffic and are a sign of a misconfiguration or a spoof. The
 * link-local metadata address 169.254.169.254 is already inside the
 * 169.254.0.0/16 that DEFAULT_PROTECTED carries.
 */
export const NEVER_REPORT_RANGES: string[] = [
  ...DEFAULT_PROTECTED,
  '100.64.0.0/10', // RFC 6598 carrier-grade NAT
  '192.0.2.0/24', // TEST-NET-1 (documentation)
  '198.51.100.0/24', // TEST-NET-2
  '203.0.113.0/24', // TEST-NET-3
  '192.0.0.0/24', // IETF protocol assignments
  '198.18.0.0/15', // benchmarking
  '224.0.0.0/4', // multicast
  '240.0.0.0/4', // reserved
  '::/128', // unspecified
  '2001:db8::/32', // documentation
  '100::/64', // discard-only
];

/**
 * Event categories that imply a *completed* TCP handshake (R2). An attacker
 * cannot forge these from a spoofed address: to send an HTTP request, fail an
 * SSH password or trip a honeypot you must first finish the handshake, which
 * reveals your real address. Pure L3/L4 signals — a SYN flood, a UDP port scan
 * — are trivially spoofable and are never, on their own, enough to report.
 */
const CONNECTION_VERIFIED_CATEGORIES = new Set(['auth', 'web', 'pentest']);

/** Module-name fragments that are themselves connection-verified evidence. */
const CONNECTION_VERIFIED_MODULES = ['honeypot', 'honey-pot', 'webhoneypot'];

export interface AbuseEvidence {
  /** Distinct detectors (modules) that observed this source. */
  signals: number;
  /** True when at least one signal required a completed handshake (R2). */
  connectionVerified: boolean;
  /** Earliest observation, epoch ms — drives the cooling-off window (R5). */
  firstSeen: number;
  /** Latest observation, epoch ms. */
  lastSeen: number;
  /** Total events on record for the source. */
  total: number;
  /** The distinct event categories seen, for category mapping and the comment. */
  categories: string[];
  /** Rule ids that matched, de-duplicated. */
  ruleIds: string[];
}

/**
 * Collapse the raw ledger for one IP into the facts the bar needs. The block
 * event itself (module `firewall-rules`) is not evidence of anything — it is
 * our own action — so it never counts as a corroborating signal.
 */
export function summarizeEvidence(events: ThreatEvent[]): AbuseEvidence {
  const modules = new Set<string>();
  const categories = new Set<string>();
  const ruleIds = new Set<string>();
  let connectionVerified = false;
  let firstSeen = Infinity;
  let lastSeen = 0;
  let total = 0;

  for (const event of events) {
    if (event.module === 'firewall-rules') continue;
    total++;
    modules.add(event.module);
    categories.add(event.category);
    const ruleId = event.details?.rule_id;
    if (typeof ruleId === 'string') ruleIds.add(ruleId);
    const t = event.timestamp.getTime();
    if (t < firstSeen) firstSeen = t;
    if (t > lastSeen) lastSeen = t;
    if (
      CONNECTION_VERIFIED_CATEGORIES.has(event.category) ||
      CONNECTION_VERIFIED_MODULES.some((m) => event.module.includes(m))
    ) {
      connectionVerified = true;
    }
  }

  return {
    signals: modules.size,
    connectionVerified,
    firstSeen: firstSeen === Infinity ? 0 : firstSeen,
    lastSeen,
    total,
    categories: [...categories],
    ruleIds: [...ruleIds],
  };
}

export interface ReportabilityConfig {
  minCorroboratingSignals: number;
  coolingOffSeconds: number;
  /** Operator `never_report` plus the built-in unsafe ranges. */
  neverReport: string[];
}

export interface ReportDecision {
  reportable: boolean;
  /** Why not, when `reportable` is false — logged, never sent anywhere. */
  reason?: string;
  /** How much longer the cooling-off window has to run, seconds (R5). */
  waitSeconds?: number;
}

/**
 * The gate. Order matters: the disqualifying checks (never-report ranges,
 * spoofability) come before the "not yet" checks, so a protected address is
 * reported as protected rather than as merely cooling off.
 */
export function isReportable(
  ip: string,
  evidence: AbuseEvidence,
  config: ReportabilityConfig,
  now: number = Date.now(),
): ReportDecision {
  if (isIP(ip) === 0) return { reportable: false, reason: 'not an IP address' };

  // R3 — never attribute an attack to a shared, reserved or operator-excluded
  // address. This is the check that protects third parties, so it is first.
  if (isProtected(ip, config.neverReport)) {
    return { reportable: false, reason: 'address is in a never-report range (private/CGNAT/reserved/allowlisted)' };
  }

  // R2 — spoofable sources are unreportable. Without a completed handshake we
  // cannot stand behind the accusation, and an attacker could otherwise make
  // us report a competitor.
  if (!evidence.connectionVerified) {
    return { reportable: false, reason: 'no connection-verified (L7) signal — spoofable, not reportable' };
  }

  // R1 — a single ambiguous hit is never enough.
  if (evidence.signals < config.minCorroboratingSignals) {
    return {
      reportable: false,
      reason: `only ${evidence.signals} corroborating signal(s), need ${config.minCorroboratingSignals}`,
    };
  }

  // R5 — hold a freshly-seen source so one burst does not become a public
  // record before we have watched it for a while.
  const age = (now - evidence.firstSeen) / 1000;
  if (evidence.firstSeen > 0 && age < config.coolingOffSeconds) {
    return { reportable: false, reason: 'within cooling-off window', waitSeconds: Math.ceil(config.coolingOffSeconds - age) };
  }

  return { reportable: true };
}

/**
 * AbuseIPDB category codes (https://www.abuseipdb.com/categories) mapped from
 * what our detectors saw. Conservative: when nothing specific matches we fall
 * back to 15 (Hacking) rather than inventing a precise accusation.
 */
export function abuseipdbCategories(evidence: AbuseEvidence): number[] {
  const cats = new Set<number>();
  const rules = evidence.ruleIds.join(' ').toLowerCase();

  for (const category of evidence.categories) {
    switch (category) {
      case 'auth':
        cats.add(18); // Brute-Force
        cats.add(22); // SSH
        break;
      case 'web':
        cats.add(21); // Web App Attack
        break;
      case 'scan':
      case 'network':
        cats.add(14); // Port Scan
        break;
      case 'pentest':
        cats.add(15); // Hacking
        break;
      default:
        break;
    }
  }

  if (rules.includes('sql')) cats.add(16); // SQL Injection
  if (rules.includes('xss') || rules.includes('rce') || rules.includes('lfi') || rules.includes('rfi')) cats.add(15);
  if (rules.includes('bot') || rules.includes('scrape') || rules.includes('paywall')) cats.add(19); // Bad Web Bot

  if (cats.size === 0) cats.add(15); // Hacking — a safe generic
  return [...cats].sort((a, b) => a - b);
}
