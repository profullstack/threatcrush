import { describe, expect, it } from 'vitest';
import { REDACTED, redactConfig } from '../save.js';

describe('redactConfig', () => {
  it('uploads remediation settings but never alert secrets', () => {
    expect(redactConfig({
      remediation: { max_ban: '7d', strike_memory: '30d', protected: ['203.0.113.7/32'] },
      alerts: { smtp: { host: 'mail', password: 'p', enabled: true }, discord: { webhook_url: 'https://x' } },
    })).toEqual({
      remediation: { max_ban: '7d', strike_memory: '30d', protected: ['203.0.113.7/32'] },
      alerts: { smtp: { host: 'mail', password: REDACTED, enabled: true }, discord: { webhook_url: REDACTED } },
    });
  });
});
