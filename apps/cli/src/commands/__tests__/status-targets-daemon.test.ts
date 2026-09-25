import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Both reported from the dev2 recovery.
 *
 * `threatcrush status` printed "NOT RUNNING / No modules discovered" against a
 * live root daemon while `blocklist` over the very same socket answered fine.
 * It gated the IPC call on `findRunningDaemon()`, which reads only *this
 * mode's* pid file — so a non-root caller never even tried to connect, and
 * THREATCRUSH_SOCKET was ignored because nothing used it.
 *
 * `threatcrush allowlist add` told the operator to edit
 * ~/.threatcrush/threatcrushd.conf — a file the root daemon never reads.
 */
const STATUS = readFileSync(join(__dirname, '..', 'status.ts'), 'utf-8');
const FIREWALL = readFileSync(join(__dirname, '..', 'firewall.ts'), 'utf-8');

describe('status asks the socket, not the local pid file', () => {
  it('connects unconditionally rather than gating on findRunningDaemon', () => {
    const body = STATUS.slice(STATUS.indexOf('export async function statusCommand'));
    const connectAt = body.indexOf('await client.connect()');
    expect(connectAt).toBeGreaterThan(-1);
    // The connect must not sit inside an `if (pid)` guard.
    const beforeConnect = body.slice(0, connectAt);
    expect(beforeConnect).not.toMatch(/if \(pid\) \{[\s\S]*$/);
  });

  it('keeps the pid file only as a fallback for what to say', () => {
    expect(STATUS).toMatch(/findRunningDaemon\(\)/);
    expect(STATUS).toMatch(/RUNNING \(IPC unreachable\)/);
  });
});

describe('allowlist names the config the daemon actually reads', () => {
  it('takes the path from the daemon status reply', () => {
    expect(FIREWALL).toMatch(/status\.paths\.config/);
  });

  it('tells a system daemon to be restarted through systemctl', () => {
    // `threatcrush restart` run as a user does not restart a root service.
    expect(FIREWALL).toMatch(/sudo systemctl restart threatcrushd/);
  });
});
