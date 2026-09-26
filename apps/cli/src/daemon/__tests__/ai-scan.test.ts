import { describe, it, expect } from 'vitest';
import { runAiScan } from '../../aiscan/runner.js';
import { BUILTIN_PROBES, selectProbes } from '../../aiscan/probes.js';
import { runMosh } from '../../aiscan/mosh.js';

describe('aiscan probes', () => {
  it('every probe maps to an OWASP LLM Top 10 id and has a detector', () => {
    for (const p of BUILTIN_PROBES) {
      expect(p.owasp).toMatch(/^LLM\d\d:2025$/);
      expect(typeof p.detect).toBe('function');
      expect(typeof p.build).toBe('function');
    }
  });

  it('selectProbes filters by category', () => {
    const inj = selectProbes(['prompt-injection']);
    expect(inj.length).toBeGreaterThan(0);
    expect(inj.every((p) => p.category === 'prompt-injection')).toBe(true);
  });
});

describe('runAiScan scoring', () => {
  it('flags a target that echoes the canary (guardrail failed)', async () => {
    // A vulnerable endpoint that obeys any embedded instruction: it echoes the
    // canary back. Every canary probe should breach; heuristic probes may not.
    const send = async (input: string) => {
      const m = input.match(/TC-CANARY-[A-Z0-9-]+/);
      return m ? `sure, here you go: ${m[0]}` : 'ok';
    };
    const res = await runAiScan('https://target.example/chat', send, {
      categories: ['prompt-injection'],
    });
    expect(res.findings.length).toBeGreaterThan(0);
    expect(res.findings.every((f) => f.severity === 'high')).toBe(true);
    expect(res.findings[0].details?.owasp).toBe('LLM01:2025');
    // Evidence is redacted to a short slice, never the whole response.
    expect((res.findings[0].details?.evidence as string).length).toBeLessThanOrEqual(200);
  });

  it('reports clean when the endpoint refuses everything', async () => {
    const send = async () => "I can't help with that request.";
    const res = await runAiScan('https://target.example/chat', send, {});
    expect(res.findings).toHaveLength(0);
    expect(res.summary).toMatch(/No guardrail failures/);
  });

  it('never bans/throws on a transport error — records it instead', async () => {
    const send = async () => { throw new Error('connection refused'); };
    const res = await runAiScan('https://down.example', send, { categories: ['prompt-injection'] });
    expect(res.findings).toHaveLength(0);
    expect(res.summary).toMatch(/errored/);
  });

  it('honors the probe limit', async () => {
    const send = async () => 'ok';
    let calls = 0;
    await runAiScan('https://t.example', async (i) => { calls++; return send(); }, { limit: 2 });
    expect(calls).toBe(2);
  });
});

describe('.mosh runtime', () => {
  it('exposes probes(), say(), argv and runs real JS', async () => {
    const out: string[] = [];
    const res = await runMosh(
      `
        const list = probes(["prompt-injection"]);
        for (const p of list) say(p.owasp, p.id);
        say("target:", argv[0]);
      `,
      { argv: ['https://x.example'], out: (s) => out.push(s) },
    );
    expect(res.failed).toBeUndefined();
    expect(out.some((l) => l.startsWith('LLM01:2025'))).toBe(true);
    expect(out.at(-1)).toBe('target: https://x.example');
  });

  it('fail() aborts the script with a reason and no throw', async () => {
    const res = await runMosh(`say("before"); fail("policy breach"); say("after");`, { out: () => {} });
    expect(res.failed).toBe('policy breach');
  });
});
