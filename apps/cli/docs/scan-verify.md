# `threatcrush scan --verify`: AI-verified findings

The rule engine behind `threatcrush scan` is pattern matching. It is fast and
it does not miss the constructs it knows, but on mature codebases most of what
it flags is obvious noise to a person who reads ten lines around the match: a
test fixture, a constant argument, a flag name that looks like a secret, a
pattern sitting inside a regex literal. `--verify` automates that read.

It is our take on the find-then-verify pipeline Anthropic describes for its
[OSS Scanner](https://red.anthropic.com/oss-scanner/), sized for open models
you can run yourself or on the [c0mpute](https://c0mpute.com) network.

## What it does

For every finding (highest severity first, up to `--verify-max`):

1. Reads the flagged line plus 20 lines of surrounding code on each side.
2. Masks anything that could be key material: high-entropy string literals,
   `KEY=value` assignments, PEM blocks and long base64/hex runs. A secret the
   scan found is described to the model ("a 40-char high-entropy string"), never
   sent to it.
3. Asks the model for a JSON verdict: is the match real code, what exact
   expression carries attacker data, `true_positive` / `false_positive` /
   `uncertain`, a confidence and one sentence of reasoning.
4. Holds the model to its evidence: a `true_positive` on a code finding whose
   quoted attacker source is missing, or does not appear in the code it was
   shown, is downgraded to `uncertain`. Small models otherwise "confirm"
   everything with "could be attacker-controlled".

Then:

- `false_positive` at or above `--verify-threshold` (default 0.7): dismissed.
  Not printed (unless `--show-dismissed`), not counted by `--fail-on`, not in
  SARIF. JSON output keeps them under `dismissed`.
- everything else is kept with its `verification` attached.
- dependency advisories (OSV) are facts, not pattern matches, and are never sent.

## Where the code goes

| Setting | Endpoint | Leaves the machine? |
|---|---|---|
| default | c0mpute peer network (`infernetprotocol.com`) | Yes: masked excerpts, end-to-end encrypted to the one worker that runs the job, which reads them in plaintext |
| `--ai-url http://localhost:11434/v1` | your Ollama / llama.cpp / vLLM | No |
| `--ai-url https://...` | any OpenAI-compatible API | To that API |

The CLI prints which one it is using before sending anything.

## Models

Default chain on c0mpute, tried in order; a model your key cannot use
(GPU models are paid) is skipped for the rest of the run:

1. `qwen2.5-coder:7b`: reading code is the job.
2. `eriktonon/qwen3.8-uncensored:9b`, `huihui_ai/qwen3.5-abliterated:9b`:
   uncensored fallbacks, because stock models sometimes refuse to discuss
   whether an injection is exploitable at all.
3. `huihui_ai/qwen3.5-abliterated:4b`: free without a key, CPU-served, about
   two and a half minutes per finding.

Without a key c0mpute allows 10 free calls a day. Set `C0MPUTE_API_KEY`
(an `ik_live_` account key) for real runs, or use `--ai-url`.

## Flags

| Flag | Env | Default |
|---|---|---|
| `--verify` | | off |
| `--ai-url <url>` | `THREATCRUSH_AI_URL` | c0mpute |
| `--ai-model <a,b>` | `THREATCRUSH_AI_MODEL` | chain above (first entry only with `--ai-url`) |
| | `THREATCRUSH_AI_KEY` | bearer for `--ai-url` |
| | `C0MPUTE_API_KEY` | keyless free tier |
| `--verify-max <n>` | | 50 |
| `--verify-threshold <0-1>` | | 0.7 |
| `--show-dismissed` | | off |

## JSON output

```json
{
  "findings": [{ "ruleId": "...", "file": "...", "line": 12,
    "verification": { "verdict": "uncertain", "confidence": 0.5,
      "reason": "...", "model": "qwen2.5-coder:7b", "provider": "c0mpute" } }],
  "verification": { "provider": "c0mpute", "models": ["..."], "checked": 25, "errors": 0 },
  "dismissed": [{ "ruleId": "...", "verification": { "verdict": "false_positive", "confidence": 0.9 } }]
}
```

## Limits

- It is a second opinion from a small model, not proof. A dismissed finding can
  be real; check `dismissed` before deleting a rule from CI.
- It only sees the window around the match, so cross-file taint is out of
  reach; such findings usually come back `uncertain` and stay in the report.
