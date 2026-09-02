/**
 * Cause 4: a language whose tests live inside the file they test.
 *
 * The first three structural causes were all about *where a file sits* —
 * `_test.go`, `testutils/`, `docs/`. Rust does not work that way. `cargo test`
 * compiles unit tests from a `#[cfg(test)] mod tests` block at the bottom of
 * the very file they cover, so the path is `core/src/domain/…/services.rs` for
 * the production code and the fixtures alike, and no path rule can separate
 * them.
 *
 * Every Rust line below is copied from ferriskey/ferriskey, an IAM server of
 * 689 stars that scored 135 findings and zero true positives at 0.11.8. Twenty
 * two of those are this cause.
 *
 * The stakes on the other side are why this is done with a brace-matched block
 * rather than "everything after the first `#[cfg(test)]`": in `services.rs` the
 * test module opens at line 2137 of 4042, so a to-end-of-file rule would soften
 * production code on almost half a file, and a real hardcoded credential below
 * a test module would be reported at `low` for no reason anybody could see.
 */
import { describe, expect, it } from 'vitest';
import { inlineTestLines, scanText } from '../text';

const severityOf = (path: string, source: string, ruleId: string): string | undefined =>
  scanText(path, source).find((one) => one.ruleId === ruleId)?.severity;

/**
 * Assembled rather than written out, like every other credential fixture here.
 *
 * The repository's own `gitleaks` job scans all refs, not the diff, so a
 * password-shaped literal sitting on this branch reddens pull requests that
 * never touched it — see the entries in `.gitleaksignore` for the ones that
 * already did. Nothing about the test needs the literal to exist in the tree;
 * the scanner reads the string it is handed.
 */
const FIXTURE_PASSWORD = ['Str0ng!', 'P@ssword', '#2024'].join('');

/**
 * The shape of `services.rs`: production code, then the test module.
 *
 * `services.rs:2719` is the sharpest of the twenty two — it reported at `high`,
 * not at `low`, because the value is strong enough that none of the existing
 * value-side softeners recognise it as a fixture. Being a good fake password is
 * what made it look like a real one. Only the block it sits in says otherwise.
 */
const SERVICE = [
  'pub async fn reset_password(&self, user: &User, new_password: String) -> Result<(), Error> {',
  '    self.repository.update_credential(user.id, hash(&new_password)?).await',
  '}',
  '',
  '#[cfg(test)]',
  'mod tests {',
  '    use super::*;',
  '',
  '    #[tokio::test]',
  '    async fn resets_a_password() {',
  '        let input = ResetPasswordInput {',
  `            new_password: "${FIXTURE_PASSWORD}".to_string(),`,
  '        };',
  '        assert!(service.reset_password(&user, input.new_password).await.is_ok());',
  '    }',
  '}',
].join('\n');

const SERVICE_PATH = 'core/src/domain/trident/services.rs';

describe('cause 4 — a fixture inside an inline test block', () => {
  it('softens a test password in a #[cfg(test)] module', () => {
    expect(severityOf(SERVICE_PATH, SERVICE, 'secret-generic-credential')).toBe('low');
  });

  it('leaves the same line at full severity in the production half of the file', () => {
    const production = SERVICE.replace('#[cfg(test)]\nmod tests {', 'mod helpers {').replace('#[tokio::test]\n', '');
    expect(severityOf(SERVICE_PATH, production, 'secret-generic-credential')).toBe('high');
  });

  it('says in the message that the block is what softened it', () => {
    const finding = scanText(SERVICE_PATH, SERVICE).find((one) => one.ruleId === 'secret-generic-credential');
    expect(finding?.message).toContain('in a test-only block');
  });

  // The softening is a claim about severity and nothing else — the same line
  // `context-severity.test.ts` draws for the path-based rules.
  it('keeps the finding in the report rather than dropping it', () => {
    const findings = scanText(SERVICE_PATH, SERVICE);
    expect(findings.filter((one) => one.ruleId === 'secret-generic-credential')).toHaveLength(1);
  });
});

describe('where an inline test block starts and stops', () => {
  const linesOf = (source: string): number[] => [...inlineTestLines('a.rs', source.split('\n'))].sort((x, y) => x - y);

  it('claims the module and nothing after it', () => {
    const source = [
      'fn before() {}',        // 0
      '#[cfg(test)]',          // 1
      'mod tests {',           // 2
      '    #[test]',           // 3
      '    fn t() {}',         // 4
      '}',                     // 5
      'fn after() {}',         // 6
    ].join('\n');
    expect(linesOf(source)).toEqual([1, 2, 3, 4, 5]);
  });

  // The reason the block needs a lexer at all. `format!("{}")` is a brace in a
  // string on a line that is otherwise ordinary; counted, it closes the module
  // early and every fixture below it goes back to reporting at full severity.
  it('does not count braces inside strings', () => {
    const source = [
      '#[cfg(test)]',
      'mod tests {',
      '    fn t() {',
      '        let s = format!("{} {{}}", x);',
      '        let n = 1;',
      '    }',
      '}',
      'fn after() {}',
    ].join('\n');
    expect(linesOf(source)).toEqual([0, 1, 2, 3, 4, 5, 6]);
  });

  it('does not count braces inside raw strings or comments', () => {
    const source = [
      '#[cfg(test)]',
      'mod tests {',
      '    // }',
      '    /* } /* nested */ } */',
      '    let q = r#"a "quoted" } brace"#;',
      '}',
      'fn after() {}',
    ].join('\n');
    expect(linesOf(source)).toEqual([0, 1, 2, 3, 4, 5]);
  });

  it('reads a lifetime as a lifetime, not as a char literal opening a string', () => {
    const source = [
      '#[cfg(test)]',
      'mod tests {',
      "    fn t<'a>(s: &'a str) { let c = '}'; }",
      '}',
      'fn after() {}',
    ].join('\n');
    expect(linesOf(source)).toEqual([0, 1, 2, 3]);
  });

  it('claims a bare #[test] fn outside any module', () => {
    const source = ['fn before() {}', '#[test]', 'fn t() {}', 'fn after() {}'].join('\n');
    expect(linesOf(source)).toEqual([1, 2]);
  });

  it('claims the async and parameterised test attributes too', () => {
    for (const attribute of ['#[tokio::test]', '#[rstest]', '#[actix_web::test]']) {
      expect(linesOf([attribute, 'fn t() {}', 'fn after() {}'].join('\n'))).toEqual([0, 1]);
    }
  });

  it('claims a declaration that has no block', () => {
    expect(linesOf(['#[cfg(test)]', 'mod tests;', 'fn after() {}'].join('\n'))).toEqual([0, 1]);
  });

  it('claims a gate written with all() or any()', () => {
    expect(linesOf(['#[cfg(all(test, unix))]', 'mod tests {', '}', 'fn a() {}'].join('\n'))).toEqual([0, 1, 2]);
  });
});

describe('what an inline test block is not', () => {
  // `not(test)` is the exact inverse: code compiled when tests are *off*. It is
  // production code by definition, and softening it would be backwards.
  it('does not claim #[cfg(not(test))]', () => {
    const source = ['#[cfg(not(test))]', 'mod real {', `    let p = "${FIXTURE_PASSWORD}";`, '}'].join('\n');
    expect(inlineTestLines('a.rs', source.split('\n')).size).toBe(0);
  });

  // A feature flag whose name merely contains "test". The string blanking is
  // what keeps this from reading as a gate.
  it('does not claim a feature flag named for testing', () => {
    const source = ['#[cfg(feature = "test-util")]', 'mod util {', '}'].join('\n');
    expect(inlineTestLines('a.rs', source.split('\n')).size).toBe(0);
  });

  it('does nothing to a language whose tests live in their own files', () => {
    const go = ['// #[cfg(test)]', 'func main() {', `    password := "${FIXTURE_PASSWORD}"`, '}'].join('\n');
    expect(inlineTestLines('main.go', go.split('\n')).size).toBe(0);
    expect(severityOf('main.go', go, 'secret-generic-credential')).not.toBe('low');
  });

  // An unbalanced file means the stripper lost its place. Claiming the rest of
  // it on a parse that already went wrong is how a scanner goes quiet on real
  // findings, so an unclosed block claims only the line it started on.
  it('claims only the attribute line when the braces never balance', () => {
    const source = ['fn a() {}', '#[cfg(test)]', 'mod tests {', '    fn t() {'].join('\n');
    expect([...inlineTestLines('a.rs', source.split('\n'))]).toEqual([1]);
  });
});
