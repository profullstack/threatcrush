import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanText } from '../text';
import { isWorkflowPath } from '../workflow-rules';

const fixture = (name: string): string =>
  readFileSync(join(__dirname, 'fixtures', 'workflows', name), 'utf8');

const scanWorkflow = (source: string, name = 'deploy.yml') =>
  scanText(`.github/workflows/${name}`, source).filter((f) => f.ruleId.startsWith('gha-'));

const ids = (source: string): string[] => scanWorkflow(source).map((f) => f.ruleId);

const lineOf = (source: string, needle: string): number =>
  source.split('\n').findIndex((l) => l.includes(needle)) + 1;

describe('workflow paths', () => {
  it('matches workflows at any depth and nothing else', () => {
    expect(isWorkflowPath('.github/workflows/ci.yml')).toBe(true);
    expect(isWorkflowPath('repos/a/.github/workflows/ci.yaml')).toBe(true);
    expect(isWorkflowPath('.github/dependabot.yml')).toBe(false);
    expect(isWorkflowPath('.forgejo/workflows/ci.yml')).toBe(true);
    expect(isWorkflowPath('workflows/ci.yml')).toBe(false);
  });

  it('recognises a workflow by shape when the path does not say so', () => {
    const src = 'on: workflow_dispatch\njobs:\n  a:\n    steps:\n      - run: echo ${{ inputs.x }}\n';
    expect(scanText('workflows/ci.yml', src).map((f) => f.ruleId)).toContain('gha-expression-injection');
  });

  it('does not run on ordinary YAML', () => {
    const src = 'services:\n  app:\n    command: echo ${{ inputs.x }}\n';
    expect(scanText('config/app.yml', src).filter((f) => f.ruleId.startsWith('gha-'))).toEqual([]);
  });
});

describe('the 2026-11-20 incident workflows', () => {
  it('flags the quoted assignment inside an ssh remote command as critical', () => {
    const src = fixture('unban-remote-injection.yml');
    const findings = scanWorkflow(src);
    const remote = findings.find((f) => f.ruleId === 'gha-input-in-remote-shell');
    expect(remote).toBeDefined();
    expect(remote!.severity).toBe('critical');
    expect(remote!.line).toBe(lineOf(src, `"IPS='$IPS' bash -s"`));
    expect(remote!.message).toContain('$IPS');
    expect(remote!.fix).toBeTruthy();
    // The quoted heredoc body expands nothing locally.
    expect(findings.filter((f) => f.ruleId === 'gha-input-in-remote-shell')).toHaveLength(1);
  });

  it('flags the deploy key as unverifiable, at the line that writes it', () => {
    const src = fixture('unban-remote-injection.yml');
    const key = scanWorkflow(src).find((f) => f.ruleId === 'gha-ssh-key-secret');
    expect(key?.severity).toBe('medium');
    expect(key?.line).toBe(lineOf(src, '> ~/.ssh/id_ed25519'));
    expect(key?.message).toContain('restrict,command=');
  });

  it('does not call writing the key to a file a log leak', () => {
    expect(ids(fixture('unban-remote-injection.yml'))).not.toContain('gha-secrets-to-log');
  });

  it('flags a free-text dispatch input run over ssh as critical remote exec', () => {
    const src = fixture('dispatch-remote-exec.yml');
    const findings = scanWorkflow(src);
    const exec = findings.find((f) => f.ruleId === 'gha-dispatch-remote-exec');
    expect(exec?.severity).toBe('critical');
    expect(exec?.line).toBe(lineOf(src, '<<<"$CMD"'));
    expect(findings.map((f) => f.ruleId)).toContain('gha-ssh-key-secret');
  });

  it('stays silent on the validated, env-passed, local-only version', () => {
    expect(scanWorkflow(fixture('safe-validated-local.yml'))).toEqual([]);
  });
});

const dispatch = (run: string, extra = ''): string => `on:
  workflow_dispatch:
    inputs:
      cmd:
        type: string
      env_name:
        type: choice
        options: [prod, staging]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          CMD: \${{ inputs.cmd }}
          KEY: \${{ secrets.KEY }}${extra}
        run: |
${run.split('\n').map((l) => `          ${l}`).join('\n')}
`;

describe('gha-dispatch-remote-exec', () => {
  it('flags the input as the whole ssh remote command', () => {
    expect(ids(dispatch('ssh deploy@host "$CMD"'))).toContain('gha-dispatch-remote-exec');
  });

  it('flags the expression as the whole ssh remote command', () => {
    expect(ids(dispatch('ssh deploy@host "${{ inputs.cmd }}"'))).toContain('gha-dispatch-remote-exec');
  });

  it('flags the input piped to a remote shell', () => {
    expect(ids(dispatch(`printf '%s\\n' "$CMD" | ssh -i k deploy@host bash -s`))).toContain('gha-dispatch-remote-exec');
  });

  it('flags the input as a line of an unquoted heredoc', () => {
    expect(ids(dispatch('ssh deploy@host <<EOF\n$CMD\nEOF'))).toContain('gha-dispatch-remote-exec');
  });

  it('flags appleboy/ssh-action running the input as its script', () => {
    const src = `on:
  workflow_dispatch:
    inputs:
      cmd: {}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: appleboy/ssh-action@v1
        with:
          host: \${{ secrets.HOST }}
          key: \${{ secrets.KEY }}
          script: |
            cd /srv/app
            \${{ inputs.cmd }}
`;
    const f = scanWorkflow(src).find((x) => x.ruleId === 'gha-dispatch-remote-exec');
    expect(f?.line).toBe(15);
  });

  it('is input-in-remote-shell, not dispatch exec, when the trigger is not a dispatch', () => {
    const src = `on: issue_comment
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          BODY: \${{ github.event.comment.body }}
        run: ssh host "$BODY"
`;
    expect(ids(src)).toEqual(['gha-input-in-remote-shell']);
  });
});

describe('gha-input-in-remote-shell', () => {
  it('flags a variable embedded in the ssh command line', () => {
    expect(ids(dispatch('ssh host "deploy --tag $CMD"'))).toContain('gha-input-in-remote-shell');
  });

  it('flags a remote argument even when quoted locally', () => {
    // ssh joins its arguments into one string for the remote shell.
    expect(ids(dispatch('ssh host deploy "$CMD"'))).toContain('gha-input-in-remote-shell');
  });

  it('flags sh -c and bash -c command strings', () => {
    expect(ids(dispatch('bash -c "echo $CMD"'))).toContain('gha-input-in-remote-shell');
    expect(ids(dispatch('docker exec app sh -c "run $CMD"'))).toContain('gha-input-in-remote-shell');
  });

  it('flags eval', () => {
    expect(ids(dispatch('eval "$CMD"'))).toContain('gha-input-in-remote-shell');
  });

  it('follows an in-script assignment', () => {
    expect(ids(dispatch('X="prefix-$CMD"\nssh host "run $X"'))).toContain('gha-input-in-remote-shell');
  });

  it('follows a $GITHUB_ENV export into a later step', () => {
    const src = `on: workflow_dispatch
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: echo "TAG=\${{ inputs.tag }}" >> "$GITHUB_ENV"
      - run: ssh host "deploy $TAG"
`;
    expect(ids(src)).toContain('gha-input-in-remote-shell');
  });

  it('follows workflow and job level env', () => {
    const src = `on:
  workflow_dispatch:
    inputs:
      tag: {type: string}
env:
  TAG: \${{ inputs.tag }}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: ssh host "deploy $TAG"
`;
    expect(ids(src)).toContain('gha-input-in-remote-shell');
  });

  it('downgrades when the variable is regex-validated in the same step', () => {
    const f = scanWorkflow(dispatch('[[ "$CMD" =~ ^[a-z]+$ ]] || exit 1\nssh host "run $CMD"')).find(
      (x) => x.ruleId === 'gha-input-in-remote-shell',
    );
    expect(f?.severity).toBe('medium');
  });

  it('is silent on single-quoted remote commands, which do not expand locally', () => {
    expect(ids(dispatch("ssh host 'echo $CMD'"))).not.toContain('gha-input-in-remote-shell');
  });

  it('is silent when the input is piped as data to a non-shell remote command', () => {
    const found = ids(dispatch(`printf '%s\\n' "$CMD" | ssh host 'xargs -n1 threatcrush unblock --'`));
    expect(found).not.toContain('gha-input-in-remote-shell');
    expect(found).not.toContain('gha-dispatch-remote-exec');
  });

  it('is silent on positional arguments to bash -c', () => {
    expect(ids(dispatch(`bash -c 'run "$1"' _ "$CMD"`))).not.toContain('gha-input-in-remote-shell');
  });

  it('is silent on choice inputs', () => {
    expect(ids(dispatch('ssh host "deploy ${{ inputs.env_name }}"'))).toEqual([]);
  });

  it('is silent on local use of the env var', () => {
    expect(ids(dispatch('./deploy.sh "$CMD"'))).toEqual([]);
  });
});

describe('gha-expression-injection', () => {
  it('flags inputs and event fields interpolated into run', () => {
    const src = `on: [pull_request, issues, workflow_dispatch]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Title: \${{ github.event.issue.title }}"
          echo "\${{ github.event.pull_request.head.ref }}"
          git checkout \${{ github.head_ref }}
          echo \${{ inputs.anything }}
          echo \${{ github.event.pull_request.number }}
`;
    const findings = scanWorkflow(src).filter((f) => f.ruleId === 'gha-expression-injection');
    expect(findings.map((f) => f.line)).toEqual([7, 8, 9, 10]);
    expect(findings.every((f) => f.severity === 'high')).toBe(true);
  });

  it('flags github-script bodies', () => {
    const src = `on: issue_comment
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: |
            const body = "\${{ github.event.comment.body }}";
`;
    expect(scanWorkflow(src).map((f) => [f.ruleId, f.line])).toEqual([['gha-expression-injection', 9]]);
  });

  it('ignores with: and if: of other actions', () => {
    const src = `on:
  workflow_dispatch:
    inputs:
      ref: {type: string}
jobs:
  a:
    if: \${{ inputs.ref != '' }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        if: github.event.inputs.ref != 'main'
        with:
          ref: \${{ inputs.ref }}
      - uses: actions/setup-node@v4
        with:
          node-version: \${{ inputs.ref }}
`;
    expect(ids(src)).toEqual([]);
  });

  it('skips a branch name in a shell comment but not a PR body', () => {
    const src = `on: pull_request_target
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: |
          # git push origin HEAD:\${{ github.event.pull_request.head.ref }}
          # \${{ github.event.pull_request.body }}
`;
    expect(scanWorkflow(src).map((f) => f.line)).toEqual([8]);
  });

  it('keeps line numbers right in a folded scalar', () => {
    const src = `on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: >-
          echo start &&
          echo \${{ github.event.issue.body }}
`;
    expect(scanWorkflow(src).map((f) => f.line)).toEqual([8]);
  });

  it('honours an inline suppression', () => {
    const src = `on: issues
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: |
          # threatcrush-disable-next-line gha-expression-injection
          echo \${{ github.event.issue.title }}
`;
    expect(ids(src)).toEqual([]);
  });

  it('survives YAML it cannot parse', () => {
    expect(ids('on: [\njobs: {')).toEqual([]);
  });
});

describe('gha-pull-request-target-checkout', () => {
  const prt = (ref: string, on = 'pull_request_target') => `on: ${on}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${ref}
`;

  it('flags checking out the PR head', () => {
    const f = scanWorkflow(prt('${{ github.event.pull_request.head.sha }}'));
    expect(f.map((x) => [x.ruleId, x.severity, x.line])).toEqual([['gha-pull-request-target-checkout', 'high', 8]]);
    expect(ids(prt('${{ github.event.pull_request.head.ref }}'))).toEqual(['gha-pull-request-target-checkout']);
  });

  it('is silent for a base checkout or a plain pull_request trigger', () => {
    expect(ids(prt('${{ github.event.pull_request.base.sha }}'))).toEqual([]);
    expect(ids(prt('${{ github.event.pull_request.head.sha }}', 'pull_request'))).toEqual([]);
  });
});

describe('gha-secrets-to-log', () => {
  const step = (run: string) => `on: push
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - env:
          TOKEN: \${{ secrets.TOKEN }}
        run: |
${run.split('\n').map((l) => `          ${l}`).join('\n')}
`;

  it('flags echo of a secret expression and of a secret env var', () => {
    expect(ids(step('echo "${{ secrets.TOKEN }}"'))).toEqual(['gha-secrets-to-log']);
    expect(ids(step('echo "token is $TOKEN"'))).toEqual(['gha-secrets-to-log']);
    expect(ids(step('echo "$TOKEN" >&2'))).toEqual(['gha-secrets-to-log']);
  });

  it('flags a secret encoded past the log masker', () => {
    expect(ids(step('echo "$TOKEN" | base64'))).toEqual(['gha-secrets-to-log']);
    // The 2026-11-20 exfiltration shape: encrypt, print, read the log back.
    expect(ids(step('echo "$TOKEN" | openssl pkeyutl -encrypt -pubin -inkey k.pem | base64 -w0'))).toEqual(['gha-secrets-to-log']);
  });

  it('flags set -x in a step with secrets', () => {
    expect(ids(step('set -euxo pipefail\n./deploy.sh'))).toEqual(['gha-secrets-to-log']);
  });

  it('is silent when the secret goes to a file or a stdin consumer', () => {
    expect(ids(step('echo "$TOKEN" > token.txt'))).toEqual([]);
    expect(ids(step('echo "$TOKEN" | docker login -u me --password-stdin'))).toEqual([]);
    expect(ids(step('echo "$TOKEN" | base64 -d > key'))).toEqual([]);
    expect(ids(step('echo "$TOKEN" | base64 -d | gpg --batch --import'))).toEqual([]);
    expect(ids(step('echo "deploying"'))).toEqual([]);
    expect(ids(step('echo "::add-mask::$TOKEN"'))).toEqual([]);
    expect(ids(step('{\n  echo "A=1"\n  echo "TOKEN=$TOKEN"\n} >> "$GITHUB_ENV"'))).toEqual([]);
    expect(ids(step(`{ echo '-----BEGIN-----'; printf '%s\\n' "$TOKEN" | fold -w 70; } > ~/.ssh/id_ed25519`))).toEqual([]);
  });

  it('does not treat a command substitution using a secret as the secret', () => {
    expect(ids(step('resp=$(curl -sf -H "Authorization: Bearer $TOKEN" https://api.example.test)\necho "$resp"'))).toEqual([]);
  });
});
