import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * `install-service` used to stop at the first thing it could not do itself:
 * it printed "Must run as root (try `sudo threatcrush install-service`)" and
 * enabled the unit without starting it, leaving the operator with two manual
 * steps and a service that would first run at the next reboot.
 *
 * These assert the source does the job instead. They read the file rather than
 * executing it because the command's whole surface is root-only side effects on
 * /etc and systemd, which a unit test must not perform.
 */
const SOURCE = readFileSync(join(__dirname, '..', 'service.js').replace(/\.js$/, '.ts'), 'utf-8');
const INDEX = readFileSync(join(__dirname, '..', '..', 'index.ts'), 'utf-8');

describe('install-service does the whole job', () => {
  it('re-runs itself under sudo rather than telling the operator to', () => {
    expect(SOURCE).toMatch(/reexecWithSudo\(\['install-service'\]\)/);
    expect(SOURCE).not.toMatch(/Must run as root \(try/);
  });

  it('starts the service, not just enables it for the next boot', () => {
    expect(SOURCE).toMatch(/systemctl enable --now/);
  });

  it('stops the user-mode daemon it is replacing', () => {
    // Two daemons would otherwise run at once, and the client prefers the
    // user's socket — so the dashboard would keep talking to the unprivileged
    // one that cannot ban.
    expect(SOURCE).toMatch(/stopUserModeDaemon\(\)/);
  });

  it('checks the unit actually came up before claiming success', () => {
    expect(SOURCE).toMatch(/unitIsActive\(\)/);
  });
});

describe('update does the whole job', () => {
  it('restarts a systemd-managed daemon itself', () => {
    expect(INDEX).toMatch(/restartSystemdDaemon\(\)/);
  });

  it('repairs an unprivileged daemon instead of only reporting it', () => {
    expect(INDEX).toMatch(/promoteUnprivilegedDaemon\(\)/);
  });
});
