import { describe, expect, it } from 'vitest';
import { MIN_DAEMON_NODE_MAJOR, daemonNodeProblem, nodeMajor, versionOfNode } from '../node-runtime.js';

describe('nodeMajor', () => {
  it('reads plain and v-prefixed versions', () => {
    expect(nodeMajor('20.20.2')).toBe(20);
    expect(nodeMajor('v24.18.1')).toBe(24);
  });

  it('returns null for something that is not a version', () => {
    expect(nodeMajor('')).toBeNull();
    expect(nodeMajor(null)).toBeNull();
    expect(nodeMajor('bun')).toBeNull();
  });
});

describe('daemonNodeProblem', () => {
  it('refuses Node 20, whose SQLite driver segfaults the daemon', () => {
    expect(daemonNodeProblem('20.20.2')).toMatch(/too old.*SIGSEGV/);
  });

  it('accepts the minimum and newer', () => {
    expect(daemonNodeProblem(`${MIN_DAEMON_NODE_MAJOR}.0.0`)).toBeNull();
    expect(daemonNodeProblem('24.18.1')).toBeNull();
  });

  it('refuses a version it cannot read rather than guessing', () => {
    expect(daemonNodeProblem(null)).toMatch(/cannot tell/);
  });
});

describe('versionOfNode', () => {
  it('answers for the running node without spawning it', () => {
    expect(versionOfNode(process.execPath)).toBe(process.versions.node);
  });

  it('returns null for a path that is not a node', () => {
    expect(versionOfNode('/nonexistent/node')).toBeNull();
  });
});
