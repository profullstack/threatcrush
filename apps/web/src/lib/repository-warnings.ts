import { isTestPath, type Severity } from "@threatcrush/scan";

export type RepositoryFinding = { ruleId: string; file: string; line: number; severity: Severity; example: boolean; fingerprint: string };
export type WarningPolicy = { silence_warnings: boolean; silence_examples: boolean };
const severities = new Set(["critical", "high", "medium", "low", "info"]);

export function examplePath(file: string): boolean {
  return isTestPath(file) || /(?:^|\/)(?:docs?|examples?|samples?|demo)(?:\/|$)/i.test(file)
    || /(?:^|\/)\.env\.(?:example|sample|template)(?:\.|$)/i.test(file)
    || /(?:^|\/)(?:example|sample)\.env$/i.test(file)
    || /(?:^|\/)readme(?:\.[^/]*)?$/i.test(file);
}

/** Read metadata only. Source snippets and credential-bearing messages never leave CI. */
export function parseRepositoryFindings(raw: unknown): RepositoryFinding[] {
  if (!Array.isArray(raw) || raw.length > 10000) throw new Error("findings must be an array of at most 10000 results");
  return raw.map((f) => {
    if (!f || typeof f !== "object" || typeof f.ruleId !== "string" || !/^[\w.-]{1,120}$/.test(f.ruleId)
      || typeof f.file !== "string" || !f.file || f.file.length > 1000 || /[\x00-\x1f|`]/.test(f.file)
      || !Number.isInteger(f.line) || f.line < 1 || !severities.has(f.severity)
      || typeof f.fingerprint !== "string" || !/^[a-f0-9]{32,64}$/.test(f.fingerprint)) throw new Error("Invalid finding metadata");
    return { ruleId: f.ruleId, file: f.file, line: f.line, severity: f.severity, fingerprint: f.fingerprint, example: examplePath(f.file) };
  });
}

/** Critical findings always stay visible, including in tests and examples. */
export function classifyRepositoryFindings(findings: RepositoryFinding[], policy: WarningPolicy) {
  const critical = findings.filter((f) => f.severity === "critical");
  const visible = findings.map((f, index) => ({ f, index })).filter(({ f }) =>
    f.severity === "critical" || (!policy.silence_warnings && !(policy.silence_examples && f.example)));
  return {
    critical,
    visible: visible.map(({ index }) => index),
    counts: { critical: critical.length, warnings: visible.length - critical.length, silenced: findings.length - visible.length },
  };
}
