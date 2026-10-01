import { describe, expect, it } from 'vitest';
import { isNoise } from '../state.js';
import type { ThreatEvent, EventSeverity } from '../../types/events.js';

function ev(message: string, severity: EventSeverity = 'info'): ThreatEvent {
  return { timestamp: new Date(), module: 'user-journal', category: 'system', severity, message };
}

describe('feed noise', () => {
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
