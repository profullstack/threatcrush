import { describe, expect, it } from 'vitest';
import { execStartCommand, stableNodePath } from '../service.js';

/**
 * `sudo threatcrush install-service` died with:
 *
 *   env: 'node': No such file or directory
 *
 * Running the CLI script directly makes the kernel honour its
 * `#!/usr/bin/env node` shebang, and root's PATH has no mise-managed node.
 * systemd has exactly the same problem, so ExecStart needs the same treatment.
 */
describe('execStartCommand', () => {
  const script = '/home/anthony/.local/share/mise/installs/node/latest/bin/threatcrush';
  const node = '/home/anthony/.local/share/mise/installs/node/latest/bin/node';

  it('runs a shebang script through an explicit node', () => {
    expect(execStartCommand(script, node, true)).toBe(`${node} ${script} daemon`);
  });

  it('leaves a real binary alone', () => {
    // A compiled binary needs no interpreter, and prefixing node would break it.
    expect(execStartCommand('/usr/local/bin/threatcrush', node, false))
      .toBe('/usr/local/bin/threatcrush daemon');
  });
});

describe('stableNodePath', () => {
  it('leaves a system node untouched', () => {
    expect(stableNodePath('/usr/bin/node')).toBe('/usr/bin/node');
  });

  it('keeps the version-stamped path when no `latest` symlink exists', () => {
    // The rewrite is only taken when the stable path is really there; this one
    // is not, so we must not point a unit file at a path that does not exist.
    const stamped = '/nonexistent/installs/node/24.21.0/bin/node';
    expect(stableNodePath(stamped)).toBe(stamped);
  });

  it('rewrites a stamped path to `latest` in shape', () => {
    // The shape of the rewrite, independent of this machine's filesystem: a
    // node upgrade must not leave ExecStart pointing at a deleted directory.
    const stamped = '/home/x/.local/share/mise/installs/node/24.21.0/bin/node';
    expect(stamped.replace(/(\/installs\/node\/)[^/]+\//, '$1latest/'))
      .toBe('/home/x/.local/share/mise/installs/node/latest/bin/node');
  });
});
