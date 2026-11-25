import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { ScanFinding } from "@threatcrush/scan";
import type { TextProvider, TextRequest } from "@profullstack/ai-providers";
import {
  buildPrompt,
  contextFor,
  describeTarget,
  looksSecret,
  maskSecrets,
  ModelChain,
  parseVerdict,
  verifyFindings,
} from "../index.js";

function finding(over: Partial<ScanFinding> = {}): ScanFinding {
  return {
    ruleId: "js-command-injection",
    title: "Shell command built from input",
    file: "src/run.js",
    line: 3,
    severity: "high",
    confidence: "contextual",
    message: "exec() receives a string built from a variable",
    excerpt: "exec(`ls ${dir}`)",
    category: "code",
    ...over,
  };
}

function fakeProvider(answer: (req: TextRequest) => string | Error): TextProvider & { calls: TextRequest[] } {
  const calls: TextRequest[] = [];
  return {
    name: "fake",
    calls,
    async generate(req) {
      calls.push(req);
      const out = answer(req);
      if (out instanceof Error) throw out;
      return { text: out, model: "fake-7b", usage: { inputTokens: 0, outputTokens: 0, estimated: true } };
    },
  };
}

describe("secret masking", () => {
  // Built at runtime so the test file itself never holds a key-shaped literal.
  const key = ["AKIA", "Z3x9Qp", "L0vR8tYw", "2mNb7Kc4"].join("");

  it("masks a high-entropy literal but keeps identifiers and prose", () => {
    const out = maskSecrets(`const awsKey = "${key}";\nconst flag = "pull-secret-name-for-k8s";`);
    expect(out).not.toContain(key);
    expect(out).toContain(`<masked ${key.length}-char high-entropy string>`);
    expect(out).toContain('"pull-secret-name-for-k8s"');
  });

  it("masks env-style assignments and PEM blocks", () => {
    const pem = ["-----BEGIN ", "PRIVATE KEY-----\nMIIEv", "QIBADANBgkq\n-----END ", "PRIVATE KEY-----"].join("");
    const out = maskSecrets(`API_TOKEN=${key}x9\n${pem}`);
    expect(out).not.toContain(key);
    expect(out).toContain("<masked PEM block>");
  });

  it("does not treat paths, URLs or dotted names as secrets", () => {
    expect(looksSecret("/usr/local/lib/node_modules")).toBe(false);
    expect(looksSecret("https://example.com/some/long/path")).toBe(false);
    expect(looksSecret("com.example.service.handler")).toBe(false);
    expect(looksSecret(key)).toBe(true);
  });
});

describe("parseVerdict", () => {
  it("reads strict JSON, normalising percentages", () => {
    expect(parseVerdict('{"verdict":"false_positive","confidence":92,"reason":"test fixture"}')).toEqual({
      verdict: "false_positive",
      confidence: 0.92,
      reason: "test fixture",
    });
  });

  it("reads JSON wrapped in prose or fences", () => {
    const v = parseVerdict('Sure!\n```json\n{"verdict":"True Positive","confidence":0.8,"reason":"x"}\n```');
    expect(v.verdict).toBe("true_positive");
  });

  it("falls back to words but never with dismiss-level confidence", () => {
    const v = parseVerdict("This is clearly a false positive because it is a test.");
    expect(v.verdict).toBe("false_positive");
    expect(v.confidence).toBeLessThan(0.7);
  });

  it("throws on an answer it cannot read", () => {
    expect(() => parseVerdict("I cannot help with that.")).toThrow(/unparseable/);
  });
});

describe("context", () => {
  it("marks the flagged line and masks secrets in the window", () => {
    const root = mkdtempSync(join(tmpdir(), "tc-verify-"));
    const key = ["sk_live_", "9fK2mQx", "7LpZ0vRt", "Yw3nB8cD"].join("");
    writeFileSync(join(root, "a.js"), `const a = 1;\nconst k = "${key}";\nexec(cmd);\n`);
    const ctx = contextFor(root, finding({ file: "a.js", line: 3 }), 5);
    expect(ctx).toMatch(/>>\s+3 \| exec\(cmd\);/);
    expect(ctx).not.toContain(key);
    expect(buildPrompt(finding(), ctx)).toContain("Rule: js-command-injection");
  });
});

describe("verifyFindings", () => {
  const root = mkdtempSync(join(tmpdir(), "tc-verify-"));

  it("dismisses only confident false positives and keeps the rest annotated", async () => {
    const provider = fakeProvider((req) =>
      req.user?.includes("test/a.js")
        ? '{"verdict":"false_positive","confidence":0.9,"reason":"test file"}'
        : req.user?.includes("low.js")
          ? '{"verdict":"false_positive","confidence":0.4,"reason":"maybe"}'
          : '{"match_is_code":true,"attacker_source":"dir","verdict":"true_positive","confidence":0.85,"reason":"user input reaches exec"}',
    );
    const report = await verifyFindings(
      root,
      [finding({ file: "test/a.js" }), finding({ file: "low.js" }), finding({ file: "src/real.js" })],
      { provider },
    );
    expect(report.dismissed.map((f) => f.file)).toEqual(["test/a.js"]);
    expect(report.kept.map((f) => [f.file, f.verification.verdict])).toEqual([
      ["low.js", "false_positive"],
      ["src/real.js", "true_positive"],
    ]);
    expect(report.checked).toBe(3);
  });

  it("downgrades a true_positive that cites no source visible in the excerpt", async () => {
    const provider = fakeProvider(() =>
      '{"match_is_code":true,"attacker_source":"req.body.cmd","verdict":"true_positive","confidence":0.95,"reason":"could be attacker-controlled"}',
    );
    const report = await verifyFindings(root, [finding({ file: "nope.js" })], { provider });
    expect(report.kept[0].verification.verdict).toBe("uncertain");
    expect(report.kept[0].verification.confidence).toBeLessThanOrEqual(0.5);
    expect(report.kept[0].verification.reason).toMatch(/cited no attacker source/);
  });

  it("downgrades a true_positive whose reason argues the opposite", async () => {
    const provider = fakeProvider(() =>
      '{"match_is_code":true,"attacker_source":"dir","verdict":"true_positive","confidence":0.9,"reason":"The redirect target comes from the app\'s own API response, not from the user."}',
    );
    const report = await verifyFindings(root, [finding({ file: "contra.js" })], { provider });
    expect(report.kept[0].verification.verdict).toBe("uncertain");
    expect(report.kept[0].verification.reason).toMatch(/contradicts its own reasoning/);
  });

  it("never sends dependency advisories and respects --verify-max by severity", async () => {
    const provider = fakeProvider(() => '{"verdict":"uncertain","confidence":0.5,"reason":"?"}');
    const report = await verifyFindings(
      root,
      [
        finding({ file: "dep", category: "dependency" }),
        finding({ file: "low.js", severity: "low" }),
        finding({ file: "crit.js", severity: "critical" }),
      ],
      { provider, max: 1 },
    );
    expect(provider.calls).toHaveLength(1);
    expect(provider.calls[0].user).toContain("crit.js");
    const byFile = Object.fromEntries(report.kept.map((f) => [f.file, f.verification.verdict]));
    expect(byFile).toEqual({ dep: "unverified", "low.js": "unverified", "crit.js": "uncertain" });
  });

  it("stops after a rate-limit error and keeps every finding", async () => {
    const provider = fakeProvider(() => new Error("c0mpute 429: free daily limit reached"));
    const report = await verifyFindings(root, Array.from({ length: 10 }, (_, i) => finding({ file: `f${i}.js` })), {
      provider,
      concurrency: 1,
    });
    expect(provider.calls).toHaveLength(1);
    expect(report.kept).toHaveLength(10);
    expect(report.dismissed).toHaveLength(0);
    expect(report.firstError).toMatch(/429/);
  });

  it("walks past paid-only models to the free fallback and remembers it", async () => {
    const paid = fakeProvider(() => new Error('c0mpute: "qwen2.5-coder:7b" runs on a GPU and is paid only.'));
    const free = fakeProvider(() => '{"verdict":"uncertain","confidence":0.5,"reason":"ok"}');
    const chain = new ModelChain([paid, free], ["7b", "4b"]);
    await chain.generate({ user: "a" });
    await chain.generate({ user: "b" });
    expect(paid.calls).toHaveLength(1);
    expect(free.calls).toHaveLength(2);
  });

  it("does not skip a model on an ordinary call failure", async () => {
    const flaky = fakeProvider(() => new Error("This operation was aborted"));
    const chain = new ModelChain([flaky, fakeProvider(() => "{}")], ["a", "b"]);
    await expect(chain.generate({ user: "a" })).rejects.toThrow(/aborted/);
  });

  it("describes where code goes", () => {
    expect(describeTarget({ env: {} }).local).toBe(false);
    expect(describeTarget({ env: { THREATCRUSH_AI_URL: "http://localhost:11434/v1" } })).toEqual({
      local: true,
      label: "http://localhost:11434/v1",
    });
  });
});
