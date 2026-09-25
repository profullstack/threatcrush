import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The outage this file exists for.
 *
 * `network-monitor` read the **local** port of every socket and called it "the
 * port this peer probed". For an outbound connection the local port is an
 * ephemeral one chosen per connection, so ten connections to the same upstream
 * inside thirty seconds looked like a ten-port scan. Observed on dev1:
 *
 *   69.46.46.87 → local ports 42202 42214 49484 49500 49506 59050 59136
 *   "Port scan detected: 69.46.46.87 probed 10 ports in 0s"  (HIGH → banned)
 *
 * With auto-defence enforcing by default, that banned our own upstreams and
 * any host we had ssh'd out to.
 */
const SOURCE = readFileSync(
  join(__dirname, '..', '..', 'modules', 'network-monitor', 'index.ts'),
  'utf-8',
);
const PROTECTED = readFileSync(join(__dirname, '..', 'firewall', 'protected.ts'), 'utf-8');
const REMEDIATION = readFileSync(join(__dirname, '..', 'firewall', 'remediation.ts'), 'utf-8');

describe('port-scan detection counts inbound traffic only', () => {
  it('asks the kernel which ports we actually listen on', () => {
    expect(SOURCE).toMatch(/listeningPorts\(\)/);
    expect(SOURCE).toMatch(/'-ltnH'/);
  });

  it('records nothing when the listener list is unavailable', () => {
    // A missed detection is recoverable; a banned upstream is an outage.
    expect(SOURCE).toMatch(/if \(listening\.size === 0\) return records;/);
  });

  it('filters both the conntrack and the ss path', () => {
    expect(SOURCE).toMatch(/if \(!listening\.has\(port\)\) continue;/);
    expect(SOURCE).toMatch(/listening\.has\(destPort\)/);
  });
});

describe('anti-lockout protection works under systemd', () => {
  it('reads live SSH peers from the kernel, not from SSH_CLIENT', () => {
    // systemd sets no SSH_CLIENT, so the guard was inert in exactly the case
    // where the daemon is root and can actually write firewall rules.
    expect(PROTECTED).toMatch(/export function establishedSshPeers/);
    expect(PROTECTED).toMatch(/users:\\\(\\\("sshd/);
  });

  it('matches on the sshd process rather than assuming port 22', () => {
    expect(PROTECTED).toMatch(/sshd is frequently moved/);
  });

  it('refreshes the protected set on every sweep, not only at startup', () => {
    // A session opened after startup is just as much a lockout risk.
    expect(REMEDIATION).toMatch(/refreshSshProtection\(\);/);
    const sweep = REMEDIATION.slice(REMEDIATION.indexOf('private async processExpiries'));
    expect(sweep.slice(0, 400)).toMatch(/refreshSshProtection\(\)/);
  });
});
