import { describe, expect, it } from 'vitest';
import { scanText } from '../text';

/**
 * `secret-private-key` keys on the PEM banner, which code that *handles* keys
 * writes all the time without ever holding one. The rule now needs the body.
 *
 * Banners and bodies are assembled at runtime: a literal key-shaped block in
 * this file would fail the other scanners in this repository's CI.
 */
const BEGIN = (kind = '') => `-----BEGIN ${kind}PRIVATE KEY` + '-----';
const END = (kind = '') => `-----END ${kind}PRIVATE KEY` + '-----';
const BODY = 'MIGH' + 'AgEA'.repeat(15);

const hits = (path: string, source: string) =>
  scanText(path, source).filter((one) => one.ruleId === 'secret-private-key');

describe('a PEM banner with no key under it', () => {
  it('skips a regex that extracts a key from openssl output', () => {
    const source = [
      'const { stdout } = await run("openssl", ["req", "-new", "-keyout", "-"]);',
      `const key = stdout.match(/${BEGIN()}[\\s\\S]+?${END()}\\n?/)?.[0];`,
      'const csr = stdout.match(/-----BEGIN CERTIFICATE REQUEST-----[\\s\\S]+?/)?.[0];',
      'if (!key || !csr) throw new Error("openssl did not produce a key and a request");',
    ].join('\n');
    expect(hits('lib/c0mpute-edge.ts', source)).toEqual([]);
  });

  it('skips a replace() that strips the banner', () => {
    const source = `const der = pem.replace('${BEGIN()}', '').replace('${END()}', '');`;
    expect(hits('src/keys.ts', source)).toEqual([]);
  });

  it('skips a banner in a startsWith check followed by ordinary code', () => {
    const source = [
      `if (!input.startsWith('${BEGIN('RSA ')}')) {`,
      '  throw new InvalidKeyFormatErrorWithAVeryLongDescriptiveName(input);',
      '}',
    ].join('\n');
    expect(hits('src/import.ts', source)).toEqual([]);
  });
});

describe('a PEM banner with key material', () => {
  it('reports a multi-line PEM block', () => {
    const source = [BEGIN(), BODY, BODY, 'AgEA==', END()].join('\n');
    const found = hits('deploy/server.key', source);
    expect(found).toHaveLength(1);
    expect(found[0].severity).toBe('critical');
  });

  it('reports a key inside a JSON string with escaped newlines', () => {
    const source = `{"private_key": "${BEGIN()}\\n${BODY}\\n${BODY}\\n${END()}\\n"}`;
    expect(hits('service-account.json', source)).toHaveLength(1);
  });

  it('reports a key in a template literal', () => {
    const source = ['const key = `' + BEGIN(), BODY, END() + '`;'].join('\n');
    expect(hits('src/fixtures.ts', source)).toHaveLength(1);
  });

  it('reports a key concatenated line by line', () => {
    const source = [`const key = "${BEGIN('EC ')}\\n" +`, `  "${BODY}\\n" +`, `  "${END('EC ')}";`].join('\n');
    expect(hits('src/sign.js', source)).toHaveLength(1);
  });

  it('reports a legacy encrypted key past its Proc-Type headers', () => {
    const source = [
      BEGIN('RSA '),
      'Proc-Type: 4,ENCRYPTED',
      'DEK-Info: AES-128-CBC,0123456789ABCDEF0123456789ABCDEF',
      '',
      BODY,
      END('RSA '),
    ].join('\n');
    expect(hits('certs/legacy.pem', source)).toHaveLength(1);
  });

  it('reports an indented key in a YAML block scalar', () => {
    const source = ['tls:', '  key: |', `    ${BEGIN()}`, `    ${BODY}`, `    ${END()}`].join('\n');
    expect(hits('k8s/secret.yaml', source)).toHaveLength(1);
  });
});
