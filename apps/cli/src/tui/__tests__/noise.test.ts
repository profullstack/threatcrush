import { describe, expect, it } from 'vitest';
import { isNoise } from '../state.js';
import type { ThreatEvent, EventSeverity } from '../../types/events.js';

function ev(message: string, severity: EventSeverity = 'info'): ThreatEvent {
  return { timestamp: new Date(), module: 'user-journal', category: 'system', severity, message };
}

describe('feed noise', () => {
  it('shows cron CMD lines by default, hides them only when muteCron is on', () => {
    const cron = ev('[CRON] (root) CMD (curl -fsS -m 55 -o /dev/null https://coinpayportal.com/api/cron/monitor-payments)');
    // Default (muteCron off): a keepalive cron is visible.
    expect(isNoise(cron)).toBe(false);
    // With the `c` toggle on, it is noise and drops out of the feed.
    expect(isNoise(cron, true)).toBe(true);
    expect(isNoise(ev('[CRON] (anthony) CMD (/usr/bin/node /home/anthony/job.js)'), true)).toBe(true);
    // A real attack line stays visible even with cron muting on.
    expect(isNoise(ev('Attack [RCE]: GET /x', 'high'), true)).toBe(false);
  });

  it('hides routine 4xx and container veth churn', () => {
    expect(isNoise(ev('Client error 404: GET /x'))).toBe(true);
    expect(isNoise(ev('[kernel] veth69e02ee: entered promiscuous mode'))).toBe(true);
    expect(isNoise(ev('[kernel] veth69e02ee: entered allmulticast mode'))).toBe(true);
    expect(isNoise(ev('[kernel] vethe7d4cc3 (unregistering): left promiscuous mode'))).toBe(true);
    expect(isNoise(ev('[kernel] docker0: entered promiscuous mode'))).toBe(true);
  });

  it('never hides a real NIC going promiscuous, or any real attack', () => {
    // A physical NIC line is not noise even at info; and the rule engine raises
    // it to medium anyway.
    expect(isNoise(ev('[kernel] enp11s0: entered promiscuous mode'))).toBe(false);
    expect(isNoise(ev('Attack [RCE]: GET /x', 'high'))).toBe(false);
    expect(isNoise(ev('[DETECTION] Network Interface Entered Promiscuous Mode', 'medium'))).toBe(false);
  });
});
