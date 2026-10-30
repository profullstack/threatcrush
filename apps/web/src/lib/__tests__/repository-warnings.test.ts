import { describe, expect, it } from "vitest";
import { classifyRepositoryFindings, examplePath, parseRepositoryFindings } from "../repository-warnings";

const finding = (file: string, severity = "high") => ({ file, severity, ruleId: "secret-private-key", line: 1, fingerprint: "a".repeat(32) });
describe("repository warning policy", () => {
  it.each([".env.example", "config/.env.sample", "config/example.env", "docs/API.md", "packages/sdk/test/cli.test.js", "src/example.spec.ts", "README.md"])("recognizes %s", (file) => expect(examplePath(file)).toBe(true));
  it("does not soften ordinary production paths by substring", () => {
    expect(examplePath("src/latest.ts")).toBe(false);
    expect(examplePath("src/testing-service.ts")).toBe(false);
    expect(examplePath(".env.production")).toBe(false);
  });
  it("preserves critical findings in examples when both silence settings are enabled", () => {
    const findings = parseRepositoryFindings([finding(".env.example", "critical"), finding("test/a.ts"), finding("src/app.ts")]);
    expect(classifyRepositoryFindings(findings, { silence_examples: true, silence_warnings: true })).toMatchObject({ visible: [0], counts: { critical: 1, warnings: 0, silenced: 2 } });
  });
  it("silences examples only while keeping production warnings", () => {
    const findings = parseRepositoryFindings([finding("test/a.ts"), finding("src/app.ts")]);
    expect(classifyRepositoryFindings(findings, { silence_examples: true, silence_warnings: false }).visible).toEqual([1]);
  });
  it("retains warnings by default and strips untrusted snippets", () => {
    const findings = parseRepositoryFindings([{ ...finding(".env.example"), excerpt: "never store me", message: "never store me" }]);
    expect(findings[0]).not.toHaveProperty("excerpt");
    expect(findings[0]).not.toHaveProperty("message");
    expect(classifyRepositoryFindings(findings, { silence_examples: false, silence_warnings: false }).counts.warnings).toBe(1);
  });
  it.each([null, [{}], [finding("src/a", "unknown")], [{ ...finding("a"), line: 0 }]])("rejects malformed metadata", (raw) => expect(() => parseRepositoryFindings(raw)).toThrow());
});
