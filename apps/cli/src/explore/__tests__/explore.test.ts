import { mkdtempSync, writeFileSync, mkdirSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { TextProvider, TextRequest } from '@profullstack/ai-providers';
import { Board, GOAL, ORIGIN } from '../graph.js';
import { Workspace } from '../tools.js';
import { parseBootstrap, parseExplore, parseReason, parseToolCall, stripThinking } from '../tasks.js';
import { runBootstrap } from '../worker.js';
import { runEngine } from '../engine.js';
import { runExploreEngine } from '../index.js';

let tick = 0;
const clock = () => `2026-01-01T00:00:${String(tick++).padStart(2, '0')}.000Z`;

/** A provider that replays queued responses; records the requests it saw. */
function scripted(responses: string[]): TextProvider & { seen: TextRequest[] } {
  let i = 0;
  const seen: TextRequest[] = [];
  return {
    name: 'mock',
    seen,
    async generate(req) {
      seen.push(req);
      const text = responses[Math.min(i++, responses.length - 1)];
      return { text, model: 'mock', usage: { inputTokens: 0, outputTokens: 0, estimated: true } };
    },
  };
}

function tmpRepo(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), 'tc-explore-'));
  for (const [rel, content] of Object.entries(files)) {
    const abs = join(root, rel);
    mkdirSync(join(abs, '..'), { recursive: true });
    writeFileSync(abs, content);
  }
  return root;
}

describe('Board', () => {
  it('is append-only and tracks derived facts', () => {
    const b = new Board({ origin: 'repo', goal: 'find bug', clock });
    expect(b.facts.map((f) => f.id)).toEqual([ORIGIN, GOAL]);
    const i = b.declareIntent([ORIGIN], 'look at auth', 'w1', 'w1');
    expect(i.worker).toBe('w1');
    const { fact } = b.concludeIntent(i.id, 'w1', 'auth check missing in login.ts:10');
    expect(fact.id).toBe('f001');
    expect(b.derivedFacts().map((f) => f.id)).toEqual(['f001']);
    expect(i.to).toBe('f001');
    expect(() => b.concludeIntent(i.id, 'w1', 'x')).toThrow(/already concluded/);
  });

  it('supports hyperedge intents and refuses unknown sources', () => {
    const b = new Board({ origin: 'repo', goal: 'g', clock });
    const i1 = b.declareIntent([ORIGIN], 'a', 'w');
    b.concludeIntent(i1.id, 'w', 'fact one');
    const hyper = b.declareIntent([ORIGIN, 'f001'], 'combine', 'w');
    expect(hyper.from).toEqual([ORIGIN, 'f001']);
    expect(() => b.declareIntent(['nope'], 'x', 'w')).toThrow(/unknown source/);
  });

  it('claims are exclusive; release frees them', () => {
    const b = new Board({ origin: 'r', goal: 'g', clock });
    const i = b.declareIntent([ORIGIN], 'x', 'creator');
    b.claimIntent(i.id, 'w1');
    expect(() => b.claimIntent(i.id, 'w2')).toThrow(/held by w1/);
    b.releaseIntent(i.id, 'w1');
    expect(b.claimIntent(i.id, 'w2').worker).toBe('w2');
  });

  it('complete sets a goal edge; reopen undoes it and records a correction', () => {
    const b = new Board({ origin: 'r', goal: 'g', clock });
    const i = b.declareIntent([ORIGIN], 'x', 'w');
    b.concludeIntent(i.id, 'w', 'the proof');
    b.complete(['f001'], 'w');
    expect(b.status).toBe('completed');
    expect(b.intents.some((x) => x.to === GOAL)).toBe(true);
    const corr = b.reopen('the flag was wrong', 'human');
    expect(b.status).toBe('active');
    expect(b.intents.some((x) => x.to === GOAL)).toBe(false);
    expect(b.fact(corr.id)?.description).toBe('the flag was wrong');
  });

  it('stopped clears open-intent workers', () => {
    const b = new Board({ origin: 'r', goal: 'g', clock });
    const i = b.declareIntent([ORIGIN], 'x', 'w', 'w');
    b.setStatus('stopped');
    expect(i.worker).toBe(null);
    expect(() => b.declareIntent([ORIGIN], 'y', 'w')).toThrow(/not active/);
  });
});

describe('Workspace tools', () => {
  it('lists, reads windows, and greps; confines to the root', () => {
    const root = tmpRepo({ 'a.js': 'const x=1;\neval(userInput);\n', 'sub/b.txt': 'hello\nworld\n' });
    const ws = new Workspace(root);
    expect(ws.list('.')).toEqual(expect.arrayContaining(['a.js', 'sub/', 'sub/b.txt']));
    expect(ws.read('a.js', 2, 2)).toContain('2| eval(userInput);');
    expect(ws.grep('eval(')).toEqual([expect.stringContaining('a.js:2:')]);
    expect(() => ws.read('../../../etc/passwd')).toThrow(/escapes workspace/);
  });

  it('refuses a symlink that points outside the root', () => {
    const root = tmpRepo({ 'keep.txt': 'ok' });
    try {
      symlinkSync('/etc/passwd', join(root, 'evil'));
    } catch {
      return; // no symlink perms in this sandbox: skip
    }
    expect(() => new Workspace(root).read('evil')).toThrow(/escapes workspace/);
  });
});

describe('parsers', () => {
  it('reads tool calls and final answers, ignoring prose', () => {
    expect(parseToolCall('{"tool":"read","path":"a.js","from":1,"to":9}')?.path).toBe('a.js');
    expect(parseToolCall('{"fact":"done"}')).toBe(null);
    expect(parseBootstrap('sure: {"fact":"SQLi in q.ts:4","complete":false,"finding":{"severity":"high","title":"SQLi","file":"q.ts","line":4}}').finding?.severity).toBe('high');
    expect(parseExplore('{"fact":"dead end, input is constant"}').finding).toBeUndefined();
    const r = parseReason('{"complete":false,"intents":[{"from":["f001"],"description":"trace req.body into exec"}]}');
    expect(r.intents?.[0].description).toContain('exec');
  });
});

describe('thinking-model robustness', () => {
  it('strips closed and unterminated <think> blocks', () => {
    expect(stripThinking('<think>reasoning...</think>{"fact":"x"}')).toBe('{"fact":"x"}');
    // the real failure: budget spent thinking, JSON never emitted
    expect(stripThinking('{"fact":"y"}\n<think>still going when it ran out')).toBe('{"fact":"y"}');
    expect(stripThinking('<think>only thought, no json, hit the cap')).toBe('');
  });

  it('re-asks once for JSON when the first answer is all reasoning', async () => {
    const root = tmpRepo({ 'x.js': 'eval(req.body.code)\n' });
    let n = 0;
    const provider: TextProvider = {
      name: 'thinky',
      async generate() {
        n += 1;
        const text = n === 1
          ? '<think>let me look at this carefully and reason for a very long time'  // no JSON: budget spent
          : '{"fact":"eval of req.body.code at x.js:1","complete":true,"supporting":["f001"],"finding":{"severity":"critical","title":"Code injection","file":"x.js","line":1}}';
        return { text, model: 'thinky', usage: { inputTokens: 0, outputTokens: 0, estimated: true } };
      },
    };
    const board = new Board({ origin: 'repo', goal: 'g', clock });
    const r = await runBootstrap({ provider, workspace: new Workspace(root) }, board.render());
    expect(n).toBe(2); // first all-thinking, retry produced JSON
    expect(r.finding?.severity).toBe('critical');
  });
});

describe('engine', () => {
  const repo = () => tmpRepo({ 'login.ts': 'app.post("/login", (req,res)=>{ db.query("select * from u where id="+req.body.id) })\n' });

  it('bootstraps straight to complete', async () => {
    const provider = scripted([
      '{"fact":"SQL injection in login.ts:1 via req.body.id","complete":true,"supporting":["f001"],"finding":{"severity":"critical","title":"SQL injection","file":"login.ts","line":1,"cwe":"CWE-89"}}',
    ]);
    const board = new Board({ origin: 'repo', goal: 'find bug', clock });
    const out = await runEngine(board, { provider, workspace: new Workspace(repo()) }, { worker: 'w', maxSteps: 5 });
    expect(out.completed).toBe(true);
    expect(out.findings[0].finding.severity).toBe('critical');
    expect(out.steps[0].kind).toBe('bootstrap');
  });

  it('runs bootstrap → explore → reason → complete', async () => {
    const provider = scripted([
      '{"fact":"found a login route","complete":false}',                                   // bootstrap
      '{"complete":false,"intents":[{"from":["f001"],"description":"trace req.body.id into the query"}]}', // reason
      '{"fact":"req.body.id concatenated into SQL at login.ts:1","finding":{"severity":"high","title":"SQLi","file":"login.ts","line":1}}', // explore
      '{"complete":true,"supporting":["f002"]}',                                            // reason
    ]);
    const board = new Board({ origin: 'repo', goal: 'find bug', clock });
    const out = await runEngine(board, { provider, workspace: new Workspace(repo()) }, { worker: 'w', maxSteps: 8 });
    expect(out.steps.map((s) => s.kind)).toEqual(['bootstrap', 'reason', 'explore', 'reason']);
    expect(out.completed).toBe(true);
    expect(out.findings.map((f) => f.finding.title)).toContain('SQLi');
  });

  it('services a worker tool call before the final answer', async () => {
    const provider = scripted([
      '{"tool":"grep","needle":"query("}',                                   // bootstrap gathers first
      '{"fact":"no raw query sinks found","complete":false}',                 // then answers
      '{"complete":false,"intents":[]}',                                      // reason: fixed point
    ]);
    const board = new Board({ origin: 'repo', goal: 'g', clock });
    const out = await runEngine(board, { provider, workspace: new Workspace(repo()) }, { worker: 'w', maxSteps: 5 });
    expect(provider.seen.length).toBe(3);
    expect(out.steps.at(-1)?.outcome).toMatch(/fixed point/);
  });

  it('bails when every worker call fails', async () => {
    const provider: TextProvider = { name: 'bad', async generate() { throw new Error('endpoint down'); } };
    const board = new Board({ origin: 'repo', goal: 'g', clock });
    const out = await runEngine(board, { provider, workspace: new Workspace(repo()) }, { worker: 'w', maxSteps: 10 });
    expect(out.completed).toBe(false);
    expect(out.errors).toBeGreaterThan(0);
    expect(out.steps.length).toBe(0);
  });
});

describe('runExploreEngine', () => {
  it('assembles a RunResult with findings and a graph', async () => {
    const root = tmpRepo({ 'x.ts': 'child_process.exec(req.query.cmd)\n' });
    const provider = scripted([
      '{"fact":"command injection: req.query.cmd reaches exec at x.ts:1","complete":true,"supporting":["f001"],"finding":{"severity":"critical","title":"Command injection","file":"x.ts","line":1,"cwe":"CWE-78","evidence":"child_process.exec(req.query.cmd)"}}',
    ]);
    const { result, engine } = await runExploreEngine(root, { provider, worker: 'w', maxSteps: 4 });
    expect(result.type).toBe('explore');
    expect(result.findings[0].location).toBe('x.ts:1');
    expect(result.severity_summary.critical).toBe(1);
    expect(engine.completed).toBe(true);
    expect(engine.board.render()).toContain('f001');
  });
});
