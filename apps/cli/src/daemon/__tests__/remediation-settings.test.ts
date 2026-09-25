import { describe, it, expect } from 'vitest';
import { remediationSettings } from '../firewall/settings.js';

describe('remediationSettings', () => {
  it('leaves the defaults alone when there is no config', () => {
    expect(remediationSettings(undefined)).toEqual({});
  });

  it('reads mode = dry_run', () => {
    expect(remediationSettings({ mode: 'dry_run' }).dry_run).toBe(true);
    expect(remediationSettings({ mode: 'enforce' }).dry_run).toBe(false);
  });

  it('still honours the older dry_run boolean', () => {
    expect(remediationSettings({ dry_run: true }).dry_run).toBe(true);
  });

  it('lets mode win over the older boolean', () => {
    expect(remediationSettings({ mode: 'enforce', dry_run: true }).dry_run).toBe(false);
  });

  it('parses the duration spellings', () => {
    const settings = remediationSettings({ max_ban: '6h', strike_memory: '2d' });
    expect(settings.max_ban_seconds).toBe(21600);
    expect(settings.strike_memory_seconds).toBe(172800);
  });

  it('ignores a duration it cannot read rather than banning for NaN', () => {
    expect(remediationSettings({ max_ban: 'a while' }).max_ban_seconds).toBeUndefined();
  });

  it('merges both spellings of the never-block list', () => {
    const settings = remediationSettings({
      protected: ['203.0.113.7'],
      allowlist: ['198.51.100.0/24'],
    });
    expect(settings.allowlist).toEqual(['203.0.113.7', '198.51.100.0/24']);
  });
});
