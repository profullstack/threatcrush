import { describe, expect, it } from 'vitest';
import type { ThreatEvent } from '../../types/events.js';
import type { SnapshotIO } from '../../core/privileges/index.js';
import { keyFingerprint } from '../../core/privileges/index.js';
import { KeyDirectory, enrichLoginEvent } from '../key-directory.js';
import { evidenceOf } from '../rules/engine.js';

const DEPLOY_BLOB = 'AAAAC3NzaC1lZDI1NTE5AAAAIMi1GfQ77aPFF13xUgNd4Xpg1lVuEG3LvIa3VpmbJAok';
const PERSON_BLOB = 'AAAAC3NzaC1lZDI1NTE5AAAAIO2VNuRjG4NTbj+Jn3PHDjdV1TgTC7rkielAsjB+qgbB';
const DEPLOY_FP = keyFingerprint(DEPLOY_BLOB)!;
const PERSON_FP = keyFingerprint(PERSON_BLOB)!;

function io(files: Record<string, string>): SnapshotIO {
  return {
    readFile: (p) => files[p] ?? null,
    readDir: () => null,
    exists: (p) => p in files,
  };
}

const files = {
  '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\nanthony:x:1001:1001::/home/anthony:/bin/zsh\n',
  '/home/anthony/.ssh/authorized_keys': [
    `restrict,command="/usr/local/bin/deploy" ssh-ed25519 ${DEPLOY_BLOB} github-actions-deploy@profullstack/watchnews.now-2026-10-28`,
    `ssh-ed25519 ${PERSON_BLOB} anthony@profullstack-2026-10-28`,
  ].join('\n'),
};

const login = (fingerprint: string): ThreatEvent => ({
  timestamp: new Date('2026-11-02T17:59:14Z'),
  module: 'ssh-guard',
  category: 'auth',
  severity: 'info',
  message: 'SSH login accepted for anthony',
  source_ip: '172.182.202.193',
  details: { user: 'anthony', ssh_user: 'anthony', fingerprint, key_type: 'ED25519' },
});

describe('enrichLoginEvent (GitHub Actions deploys vs people)', () => {
  const keys = new KeyDirectory(io(files));

  it('marks a CI deploy key as automation and carries it into the evidence', () => {
    const event = login(DEPLOY_FP);
    enrichLoginEvent(event, keys);
    expect(event.details).toMatchObject({
      key_kind: 'automation',
      key_account: 'anthony',
      key_comment: 'github-actions-deploy@profullstack/watchnews.now-2026-10-28',
    });
    expect(evidenceOf(event)).toMatchObject({ key_kind: 'automation', key_comment: 'github-actions-deploy@profullstack/watchnews.now-2026-10-28' });
  });

  it("marks a person's key as a person", () => {
    const event = login(PERSON_FP);
    enrichLoginEvent(event, keys);
    expect(event.details?.key_kind).toBe('person');
  });

  it('never guesses automation for a key it cannot find', () => {
    const event = login('SHA256:notinanyfile');
    enrichLoginEvent(event, keys);
    expect(event.details?.key_kind).toBe('unknown');
    expect(event.details?.key_comment).toBeUndefined();
  });

  it('leaves other modules alone', () => {
    const event = { ...login(DEPLOY_FP), module: 'network-monitor' };
    enrichLoginEvent(event, keys);
    expect(event.details?.key_kind).toBeUndefined();
  });
});
