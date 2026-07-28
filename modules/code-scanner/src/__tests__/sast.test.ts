import { describe, expect, it } from 'vitest';
import { SAST_RULES, isVendored, scanSource, severityFor } from '../sast/index.js';

const rule = (id: string) => SAST_RULES.find((r) => r.id === id)!;

/**
 * THE OVERCLAIMING TEST (PRD 0004 R13).
 *
 * A regex is not data-flow analysis. The failure mode that would discredit this
 * subsystem — and the accurate findings standing next to it — is presenting a
 * bare pattern match with the confidence of a proven vulnerability. The cap is
 * enforced in `severityFor` rather than per-rule, so no future rule can opt out
 * of it by accident, and this test is what keeps that true.
 */
describe('confidence caps severity', () => {
  it('never lets a pattern-only match exceed medium', () => {
    for (const r of SAST_RULES) {
      const capped = severityFor(r, 'pattern');
      expect(['low', 'medium'], `${r.id} escalated on a bare pattern`).toContain(capped);
    }
  });

  it('allows the rule severity once there is context', () => {
    expect(severityFor(rule('js-eval-call'), 'contextual')).toBe('critical');
    expect(severityFor(rule('js-eval-call'), 'pattern')).toBe('medium');
  });

  it('holds for every finding a real scan produces', () => {
    const source = [
      'eval(userInput);',
      'exec(`convert ${req.body.file} out.png`);',
      'const x = 1;',
    ].join('\n');

    for (const finding of scanSource(source).findings) {
      if (finding.confidence === 'pattern') {
        expect(['low', 'medium'], `${finding.ruleId} overclaimed`).toContain(finding.severity);
      }
    }
  });
});

describe('rule detection', () => {
  it('finds dynamic code execution', () => {
    expect(scanSource('eval(payload);').findings.map((f) => f.ruleId)).toContain('js-eval-call');
    expect(scanSource('const f = new Function("return 1");').findings.map((f) => f.ruleId)).toContain(
      'js-eval-call',
    );
  });

  it('finds shell execution only when the command is interpolated', () => {
    const interpolated = scanSource('exec(`rm -rf ${dir}`);');
    expect(interpolated.findings.map((f) => f.ruleId)).toContain('js-exec-interpolation');

    // A fixed command string is not a finding; flagging it is how a scanner
    // earns its reputation for noise.
    const literal = scanSource("exec('ls -la');");
    expect(literal.findings.map((f) => f.ruleId)).not.toContain('js-exec-interpolation');
  });

  it('finds SQL built by interpolation', () => {
    const found = scanSource('db.query(`SELECT * FROM users WHERE id = ${id}`);');
    expect(found.findings.map((f) => f.ruleId)).toContain('js-sql-concatenation');
  });

  it('finds disabled TLS verification', () => {
    expect(scanSource('const a = { rejectUnauthorized: false };').findings.map((f) => f.ruleId)).toContain(
      'js-tls-verification-disabled',
    );
  });

  it('finds Math.random used for a security value', () => {
    const found = scanSource('const token = Math.random().toString(36);');
    expect(found.findings.map((f) => f.ruleId)).toContain('js-insecure-randomness');

    // Ordinary randomness is not a security bug.
    expect(scanSource('const jitter = Math.random() * 100;').findings).toHaveLength(0);
  });

  it('finds unsafe HTML rendering', () => {
    expect(
      scanSource('el.innerHTML = userProvided;').findings.map((f) => f.ruleId),
    ).toContain('js-unsafe-html');
  });

  it('finds prototype pollution shapes', () => {
    expect(scanSource('target["__proto__"] = source;').findings.map((f) => f.ruleId)).toContain(
      'js-prototype-pollution',
    );
  });

  it('every rule carries a CWE and a consequence, not just a name', () => {
    for (const r of SAST_RULES) {
      expect(r.cwe, r.id).toMatch(/^CWE-\d+$/);
      expect(r.consequence.length, r.id).toBeGreaterThan(20);
    }
  });
});

describe('context gating', () => {
  it('escalates when untrusted input is on the same line', () => {
    const found = scanSource('exec(`convert ${req.body.file} out.png`);');
    expect(found.findings[0]?.confidence).toBe('contextual');
    expect(found.findings[0]?.severity).toBe('critical');
  });

  it('stays at pattern confidence without an untrusted source', () => {
    const found = scanSource('exec(`convert ${localFile} out.png`);');
    expect(found.findings[0]?.confidence).toBe('pattern');
    expect(found.findings[0]?.severity).toBe('medium');
  });

  it('suppresses needsContext rules entirely when there is no context', () => {
    // Reading a file from a computed path is just software.
    expect(scanSource('readFile(`${dir}/config.json`, cb);').findings).toHaveLength(0);
    // With a request field it becomes a traversal candidate.
    expect(
      scanSource('readFile(`${req.query.path}/config.json`, cb);').findings.map((f) => f.ruleId),
    ).toContain('js-path-traversal');
  });
});

describe('noise control', () => {
  it('reports nothing on ordinary application code', () => {
    const ordinary = [
      'import express from "express";',
      'const app = express();',
      'app.get("/health", (req, res) => res.json({ ok: true }));',
      'const total = items.reduce((a, b) => a + b.price, 0);',
      'export default app;',
    ].join('\n');
    expect(scanSource(ordinary).findings).toHaveLength(0);
  });

  it('ignores comments, including rule documentation', () => {
    // Without this the subsystem reports findings about its own rule file.
    const commented = ['// eval(payload) is dangerous', ' * exec(`${x}`) runs a shell'].join('\n');
    expect(scanSource(commented).findings).toHaveLength(0);
  });
});

describe('suppressions', () => {
  it('honours an inline disable for the named rule only', () => {
    const source = [
      '// threatcrush-disable-next-line js-eval-call sandboxed by design',
      'eval(sandboxedExpression);',
    ].join('\n');
    const result = scanSource(source);
    expect(result.findings).toHaveLength(0);
    expect(result.suppressions[0]).toMatchObject({
      ruleId: 'js-eval-call',
      reason: 'sandboxed by design',
    });
  });

  it('does not suppress a different rule on the same line', () => {
    const source = [
      '// threatcrush-disable-next-line js-sql-concatenation',
      'eval(payload);',
    ].join('\n');
    expect(scanSource(source).findings.map((f) => f.ruleId)).toContain('js-eval-call');
  });

  it('records a placeholder when no reason is given', () => {
    const source = ['// threatcrush-disable-next-line js-eval-call', 'eval(x);'].join('\n');
    // Counted and reported: a quiet scan full of suppressions is not clean.
    expect(scanSource(source).suppressions[0]?.reason).toBe('(no reason given)');
  });
});

describe('vendored classification', () => {
  it('recognises third-party and generated locations', () => {
    expect(isVendored('/srv/app/vendor/lib.js')).toBe(true);
    expect(isVendored('/srv/app/dist/bundle.js')).toBe(true);
    expect(isVendored('/srv/app/static/app.min.js')).toBe(true);
    expect(isVendored('/srv/app/src/routes/admin.ts')).toBe(false);
  });
});
