import { describe, expect, it } from 'vitest';
import { ControlAudit, SECURITY_CONTROLS } from '../controls';

const auditOf = (files: Record<string, string>): ControlAudit => {
  const audit = new ControlAudit();
  for (const [path, text] of Object.entries(files)) audit.observe(path, text);
  return audit;
};

const missingIds = (files: Record<string, string>): string[] =>
  auditOf(files).missing().map((control) => control.id);

describe('applicability', () => {
  it('says nothing about a tree that serves no HTTP', () => {
    // The most important test here. "This library has no CSRF token" is a
    // category error, and reporting it is the fastest way to teach an operator
    // that these findings are noise.
    expect(missingIds({ 'sum.js': 'export const add = (a, b) => a + b;' })).toEqual([]);
  });

  it('reports nothing to anchor to when no server was found', () => {
    expect(auditOf({ 'sum.js': 'export const add = (a, b) => a + b;' }).findings()).toEqual([]);
  });

  it('engages once a server is constructed', () => {
    const missing = missingIds({ 'server.js': 'const app = express();\napp.listen(3000);' });
    expect(missing).toHaveLength(SECURITY_CONTROLS.length);
  });
});

describe('evidence', () => {
  it('accepts a control installed in a different file from the server', () => {
    // The whole reason this is a walk-wide accumulator rather than a per-file
    // rule: the limiter in `app.js` protects the route in `routes/admin.js`.
    const missing = missingIds({
      'server.js': 'const app = express();',
      'middleware/security.js': "const helmet = require('helmet');\napp.use(helmet());",
    });
    expect(missing).not.toContain('control-security-headers-absent');
  });

  it('accepts a SameSite cookie as anti-CSRF', () => {
    // A cookie the browser refuses to send cross-site is not reachable by the
    // attack the control exists to stop.
    const missing = missingIds({
      'server.js': "const app = express();\napp.use(session({ cookie: { sameSite: 'strict' } }));",
    });
    expect(missing).not.toContain('control-anti-csrf-absent');
  });

  it('accepts a rate limiter', () => {
    const missing = missingIds({
      'server.js': "const app = express();\nconst rateLimit = require('express-rate-limit');",
    });
    expect(missing).not.toContain('control-rate-limiting-absent');
  });

  it('accepts a body size limit', () => {
    const missing = missingIds({
      'server.js': "const app = express();\napp.use(express.json({ limit: '100kb' }));",
    });
    expect(missing).not.toContain('control-body-size-limit-absent');
  });

  it('reports the ones with no evidence anywhere', () => {
    const missing = missingIds({
      'server.js': "const app = express();\napp.use(helmet());",
    });
    expect(missing).not.toContain('control-security-headers-absent');
    expect(missing).toContain('control-anti-csrf-absent');
    expect(missing).toContain('control-rate-limiting-absent');
  });
});

describe('findings', () => {
  it('anchors to the file that builds the server', () => {
    const findings = auditOf({
      'lib/util.js': 'export const noop = () => {};',
      'src/server.js': 'const app = express();',
    }).findings();
    expect(findings.every((finding) => finding.file === 'src/server.js')).toBe(true);
    expect(findings.every((finding) => finding.line === 1)).toBe(true);
  });

  it('never claims more than `pattern` confidence', () => {
    // An absence is not evidence. The confidence value is what caps the
    // severity, and it is what the report shows the operator.
    const findings = auditOf({ 'server.js': 'const app = express();' }).findings();
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.every((finding) => finding.confidence === 'pattern')).toBe(true);
    expect(findings.every((finding) => finding.severity === 'medium')).toBe(true);
  });
});
