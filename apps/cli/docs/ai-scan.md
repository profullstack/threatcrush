# AI Red-Team Scan

Red-team an AI/LLM endpoint **you own or are authorized to test** for OWASP LLM
Top 10 guardrail gaps. It is a scanner scaffold in the shape of 0DIN / garak /
PyRIT: the built-in probes are **benign canary checks**, not weaponized
jailbreaks. Each probe asks the model to surface a harmless per-run token through
a channel it should refuse; if the token comes back, the boundary leaked. Nothing
harmful is ever requested or produced. Bring your own probe pack for coverage
beyond the capability checks.

## Quick start

```bash
# Default request shape is {"input":"<prompt>"} and the reply is auto-detected
threatcrush ai-scan https://your-app.example/api/chat

# Custom request/response shape + auth
threatcrush ai-scan https://your-app.example/v1/chat \
  --template '{"messages":[{"role":"user","content":"{{PROMPT}}"}]}' \
  --header 'authorization: Bearer $TOKEN' \
  --response-path 'choices.0.message.content'

# Only some categories, JSON output for CI
threatcrush ai-scan https://your-app.example/chat \
  --categories prompt-injection,system-prompt-leak --json
```

Categories: `prompt-injection` (LLM01), `sensitive-disclosure` (LLM02),
`output-handling` (LLM05), `excessive-agency` (LLM06), `system-prompt-leak`
(LLM07).

## Scripting with `.mosh`

Drive the scanner from a moshscript file — plain JavaScript with the scanner
vocabulary injected as globals, so a script can threshold, branch and fail a
pipeline on the result.

```js
#!/usr/bin/env threatcrush-mosh
// probe.mosh — fail CI if prompt injection is reachable
const r = await aiScan(argv[0], {
  categories: ["prompt-injection"],
  template: '{"messages":[{"role":"user","content":"{{PROMPT}}"}]}',
  responsePath: "choices.0.message.content",
});
for (const f of r.findings) say(`${f.severity}  ${f.message}`);
if (r.severity_summary.high > 0) fail("prompt injection reachable");
```

```bash
threatcrush ai-scan-run probe.mosh https://your-app.example/chat
```

Vocabulary: `aiScan(url, opts)`, `probes([categories])`, `say(...)`,
`fail(reason)`, plus `argv` and `env`.

## Exit codes

`ai-scan-run` exits non-zero when the script calls `fail()`, so it drops into CI
as a gate. `ai-scan` always reports; wrap it in a script (or `--json` + `jq`) to
gate on severity.
