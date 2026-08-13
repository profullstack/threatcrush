#!/usr/bin/env -S npx tsx
/**
 * tcfeed — read the newest posts on a subreddit, find the repositories they
 * link, scan each one, and print a shortlist worth reading.
 *
 * The scan reports, and that is all the scan does. It does not fork anything
 * and it does not open pull requests off its own findings. Four repositories
 * scanned by hand this way produced 166 findings and every one of them was a
 * false positive; a bot that had opened four pull requests off that would have
 * sent four pieces of spam. Read the report, pick the finding that is real,
 * then write that pull request yourself.
 *
 *   npx tsx bin/tcfeed.ts        # the 50 newest posts
 *   npx tsx bin/tcfeed.ts 100    # more of them
 *   npx tsx bin/tcfeed.ts --forget
 *
 * There is one pull request it will open, and it is not a findings pull
 * request. `tcfeed pr` installs the threatcrush-scan action pack into a
 * repository — a workflow file, report-only, no findings quoted, nothing
 * asserted about the code. See the block above openPr() for what that
 * distinction rests on and where the line is.
 *
 *   npx tsx bin/tcfeed.ts pr owner/name --dry-run
 *   npx tsx bin/tcfeed.ts pr owner/name
 *
 * It throttles itself, because reddit throttles the address rather than the
 * account and one impatient afternoon costs everything on this machine the
 * next few minutes. There is a floor between fetches, a Retry-After aware
 * backoff when it is refused anyway, a cap on how many repositories one run
 * clones, and a pause between them.
 *
 *   TCFEED_MIN_GAP  seconds between feed fetches, default 120
 *   TCFEED_MAX      repos cloned per run, default 20
 *   TCFEED_PAUSE    seconds between clones, default 1
 *   TCFEED_SUB      subreddit, default coolgithubprojects
 *   TC_BIN          the scanner, default whatever `threatcrush` resolves to
 *   TCFEED_CACHE    where seen repos and reports live, default ~/.cache/tcfeed
 *
 * and for `pr`:
 *
 *   TCFEED_PACK     the action pack directory, default ../sh1pt/packages/…
 *   TCFEED_PR_MAX   repositories one `pr` run may open against, default 3
 *   TCFEED_NODE     nodeVersion input, default 20
 *   TCFEED_SPEC     threatcrushPackageSpec input, default @latest
 *   TCFEED_FAIL_ON  failOn input, default empty, meaning report-only
 */

import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

const run = promisify(execFile);

const UA = 'Mozilla/5.0 (X11; Linux x86_64) tcfeed/1.0';

/** Kilobytes. A monorepo of a gigabyte is not a lead, it is an afternoon. */
const TOO_BIG_KB = 300_000;

/** Paths under github.com that are the site itself rather than anybody's repo. */
const NOT_A_REPO =
  /^(orgs|sponsors|topics|features|about|pricing|marketplace|collections|events|readme|apps|login|settings|notifications)$/i;

interface Severities {
  critical: number;
  high: number;
  medium: number;
}

interface Row extends Severities {
  repo: string;
  total: number;
  stars: number;
}

const sleep = (seconds: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, seconds * 1000));

const num = (name: string, fallback: number): number => {
  const raw = Number(process.env[name]);
  return Number.isFinite(raw) && raw >= 0 ? raw : fallback;
};

/**
 * Read it if it is there. Asking whether it exists and then reading it is two
 * answers about a file that only had to be true once, and the gap between them
 * is somebody else's to fill.
 */
function readOr(file: string, fallback: string): string {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return fallback;
  }
}

async function usable(command: string, args: string[]): Promise<boolean> {
  try {
    await run(command, args);
    return true;
  } catch {
    return false;
  }
}

/**
 * curl rather than fetch, and not out of habit. Reddit reads more than the
 * User-Agent: asked through node's fetch this returns 403 or 429 on an address
 * curl gets a 200 from in the same second. The one job here is reading a feed,
 * so it goes out the way that is actually answered.
 */
async function ask(url: string): Promise<{ code: string; body: string; retryAfter: number }> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tcfeed-h-'));
  const headers = path.join(dir, 'h');
  try {
    const { stdout } = await run(
      'curl',
      ['-sS', '--max-time', '60', '-D', headers, '-w', '\n%{http_code}', '-H', `User-Agent: ${UA}`, url],
      { maxBuffer: 32 * 1024 * 1024 }
    );

    const cut = stdout.lastIndexOf('\n');
    const told = fs
      .readFileSync(headers, 'utf8')
      .match(/^retry-after:[^\d]*(\d+)/im)?.[1];

    return {
      code: cut === -1 ? '' : stdout.slice(cut + 1).trim(),
      body: cut === -1 ? '' : stdout.slice(0, cut),
      retryAfter: Number(told) || 0,
    };
  } catch {
    return { code: 'network', body: '', retryAfter: 0 };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/**
 * The .json endpoint answers 403 to anything without an OAuth token now, so
 * the RSS feed is the one that works unauthenticated. JSON is tried first
 * anyway: on a machine that can reach it, it carries the post bodies too.
 */
async function readFeed(sub: string, limit: number, cache: string): Promise<string> {
  const stamp = path.join(cache, 'lastfetch');
  const gap = num('TCFEED_MIN_GAP', 120);

  const wroteAt = Number(readOr(stamp, '').trim());
  if (wroteAt > 0) {
    const since = Math.floor(Date.now() / 1000) - wroteAt;
    const waited = gap - since;
    if (waited > 0) {
      console.log(`tcfeed: last fetch was ${since}s ago, waiting ${waited}s for r/${sub}`);
      await sleep(waited);
    }
  }

  const urls = [
    `https://www.reddit.com/r/${sub}/new.json?limit=${limit}`,
    `https://www.reddit.com/r/${sub}/new/.rss?limit=${limit}`,
  ];

  let last = '';
  try {
    for (const url of urls) {
      for (let attempt = 1; attempt <= 3; attempt++) {
        const { code, body, retryAfter } = await ask(url);
        last = code;

        if (code === '429') {
          // Retry-After when it says so, otherwise back off rather than asking
          // again at the same rate that just got refused.
          const backoff = retryAfter > 0 ? retryAfter : attempt * 30;
          if (attempt === 3) break;
          console.log(`tcfeed: throttled, waiting ${backoff}s (try ${attempt} of 3)`);
          await sleep(backoff);
          continue;
        }

        if (code === '200' && body) return body;
        break;
      }
    }
  } finally {
    // Written whatever happened. A refused request still cost the address its
    // place in reddit's budget, so the next run has to wait it out too.
    fs.writeFileSync(stamp, String(Math.floor(Date.now() / 1000)));
  }

  if (last === '429')
    throw new Error(
      `r/${sub} is still throttling this address after three tries. Leave it a few minutes.`
    );
  if (last === '403')
    throw new Error(`r/${sub} refused both endpoints (403). Reddit wants OAuth from this address.`);
  throw new Error(`could not read r/${sub} (HTTP ${last || 'none'})`);
}

/**
 * Matched rather than parsed, so one expression reads both the JSON and the
 * RSS. The whole document is searched on purpose: half these posts link a blog
 * that names the repository further down rather than the repository itself.
 */
function reposIn(body: string): string[] {
  const found = new Set<string>();

  for (const [, owner, rawName] of body.matchAll(
    /github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)/gi
  )) {
    if (NOT_A_REPO.test(owner)) continue;
    // A link at the end of a sentence takes the full stop with it, and a
    // repository name cannot end in one.
    const name = rawName.replace(/\.git$/i, '').replace(/\.+$/, '');
    if (name) found.add(`${owner}/${name}`);
  }

  return [...found].sort();
}

async function metadata(
  repo: string
): Promise<{ archived: boolean; sizeKb: number; stars: number } | null> {
  try {
    const { stdout } = await run('gh', [
      'repo',
      'view',
      repo,
      '--json',
      'isArchived,diskUsage,stargazerCount',
    ]);
    const said = JSON.parse(stdout);
    return {
      archived: said.isArchived === true,
      sizeKb: Number(said.diskUsage) || 0,
      stars: Number(said.stargazerCount) || 0,
    };
  } catch {
    return null;
  }
}

async function scan(
  scanner: string,
  repo: string,
  report: string
): Promise<(Severities & { total: number }) | null> {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tcfeed-'));
  try {
    try {
      await run('git', [
        'clone',
        '--quiet',
        '--depth',
        '1',
        '--single-branch',
        `https://github.com/${repo}.git`,
        path.join(tmp, 'src'),
      ]);
    } catch {
      return null;
    }

    // A scan that finds something exits non-zero, which is the whole point of
    // it, so the report on disk is what says whether it ran.
    await run(scanner, [
      'scan',
      path.join(tmp, 'src'),
      '--format',
      'json',
      '--output',
      report,
    ]).catch(() => undefined);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }

  let parsed: { summary?: Partial<Severities>; findings?: unknown[] };
  try {
    parsed = JSON.parse(fs.readFileSync(report, 'utf8'));
  } catch {
    return null;
  }

  const summary = parsed.summary ?? {};
  return {
    critical: summary.critical ?? 0,
    high: summary.high ?? 0,
    medium: summary.medium ?? 0,
    total: parsed.findings?.length ?? 0,
  };
}

/* ------------------------------------------------------------------ *
 * pr — install the threatcrush-scan action pack into a repository
 * ------------------------------------------------------------------ */

/** The branch, and therefore the identity of the request. One per repository, ever. */
const PR_BRANCH = 'threatcrush-scan';

/**
 * The pack, read from sh1pt rather than copied into this file.
 *
 * A copy would be a second definition of the same workflow, and the second
 * definition is always the one that misses the fix — the whole reason the
 * pack's SARIF handling fails closed is a sequence of bugs that were found
 * once and corrected once. Reading it means a repository gets the corrected
 * pack or the run stops; it never gets a snapshot of the pack as it stood the
 * afternoon this function was written.
 */
function packDir(): string {
  const told = process.env.TCFEED_PACK;
  if (told) {
    if (fs.existsSync(path.join(told, 'workflow.yml'))) return told;
    throw new Error(`TCFEED_PACK is set to ${told}, which has no workflow.yml`);
  }

  // Walked up rather than reached for with a fixed `../sh1pt`, because this
  // runs from a git worktree as often as from the checkout, and from a
  // worktree the sibling is four levels further up than it looks.
  for (let dir = process.cwd(); ; dir = path.dirname(dir)) {
    const guess = path.join(dir, 'sh1pt', 'packages', 'actions', 'threatcrush-scan');
    if (fs.existsSync(path.join(guess, 'workflow.yml'))) return guess;
    if (path.dirname(dir) === dir) break;
  }

  throw new Error(
    'could not find the threatcrush-scan action pack. Clone profullstack/sh1pt\n' +
      '  beside this repository, or set TCFEED_PACK to packages/actions/threatcrush-scan.'
  );
}

/** The pack's inputs, at the defaults its own manifest documents. */
const packInputs = (): Record<string, string> => ({
  scanPath: '.',
  nodeVersion: process.env.TCFEED_NODE || '20',
  threatcrushPackageSpec: process.env.TCFEED_SPEC || '@profullstack/threatcrush@latest',
  // Empty, and this is the one input that must not be "improved" on the way
  // into somebody else's repository. A first install on a codebase with a
  // backlog either reports or blocks, and the one that blocks gets deleted the
  // same day. Report-only is the version that survives long enough to be read.
  failOn: process.env.TCFEED_FAIL_ON ?? '',
  uploadSarif: 'true',
});

/**
 * Substitution, narrow on purpose. `{{name}}` and nothing else: GitHub's own
 * `${{ steps.iface.outputs.native }}` contains braces too, and a looser
 * expression rewrites the workflow's expressions into empty strings. That
 * damage is invisible here and shows up as a broken job in a stranger's repo.
 */
function render(template: string, values: Record<string, string>): string {
  return template.replace(/\{\{([A-Za-z][A-Za-z0-9]*)\}\}/g, (whole, key: string) => {
    const value = values[key];
    // A pack that gained an input this does not know about is a pack this
    // cannot install correctly. Stop; do not ship `{{newInput}}` as a literal.
    if (value === undefined) throw new Error(`the pack has an input tcfeed cannot fill: ${whole}`);
    return value;
  });
}

async function gh(args: string[]): Promise<string> {
  const { stdout } = await run('gh', args, { maxBuffer: 32 * 1024 * 1024 });
  return stdout.trim();
}

/** Everything about the target that decides whether to ask at all. */
async function prTarget(repo: string, me: string): Promise<{ base: string } | string> {
  let about: {
    isArchived: boolean;
    isFork: boolean;
    visibility: string;
    defaultBranchRef: { name: string } | null;
  };
  try {
    about = JSON.parse(
      await gh(['repo', 'view', repo, '--json', 'isArchived,isFork,visibility,defaultBranchRef'])
    );
  } catch {
    return 'gone, renamed or not visible';
  }

  if (about.isArchived) return 'archived — nothing can be merged into it';
  if (about.isFork) return 'a fork; the workflow belongs upstream, not here';
  if (about.visibility !== 'PUBLIC') return 'not public';
  if (!about.defaultBranchRef) return 'has no commits';

  // Asked once. The pull request says "closing it is the right answer and I
  // will not send another", and this is the line that keeps that true — state
  // is `all`, so a closed request counts. Nothing about "no" expires.
  const asked = JSON.parse(
    await gh(['api', `repos/${repo}/pulls?state=all&head=${me}:${PR_BRANCH}&per_page=1`])
  ) as { html_url: string; state: string }[];
  if (asked.length > 0) return `already asked — ${asked[0].state}, ${asked[0].html_url}`;

  // Cheap name check now; the authoritative one greps the tree after cloning.
  // A repository that already scans with threatcrush does not need this.
  try {
    const names = JSON.parse(
      await gh(['api', `repos/${repo}/contents/.github/workflows`])
    ) as { name: string }[];
    if (names.some((entry) => /threatcrush/i.test(entry.name))) return 'already has the workflow';
  } catch {
    // No .github/workflows at all. That is a repository with no CI, which is
    // fine — it is not a reason to skip.
  }

  return { base: about.defaultBranchRef.name };
}

const PR_TITLE = 'ci: scan pull requests for credentials and injection with ThreatCrush';

/**
 * Written to be easy to say no to. It quotes no findings and asserts nothing
 * about the code — a pull request that opens with "your repo has 30 high
 * severity issues" is a claim the sender has not verified, and in this
 * project's own sample every one of those claims was false. This one adds a
 * workflow, discloses who wrote the workflow, and says it will not be sent
 * twice. Everything past that is the maintainer's call.
 */
const prBody = (): string =>
  [
    'Adds a pull-request workflow that scans the diff for hardcoded credentials,',
    'injection, SSRF and unsafe deserialisation. Results go to the Security tab as',
    'SARIF and to a comment on the pull request.',
    '',
    "**It is report-only.** `failOn` is empty, so it annotates and never fails a build.",
    'A repository with pre-existing findings should get a report on its first install,',
    'not a blocked pull request — a gate that fires on everything gets switched off',
    'within a day. Tighten it to `critical,high` in the workflow once any backlog is',
    'triaged.',
    '',
    '- `.github/workflows/threatcrush-scan.yml` — the workflow',
    '- `.github/scripts/threatcrush-to-sarif.py` — a compatibility shim for CLI versions',
    '  older than native SARIF output; unused once the installed CLI can emit it itself',
    '',
    'Permissions are least-privilege (`contents: read`, `pull-requests: write`,',
    '`security-events: write`). It runs on `pull_request`, not `pull_request_target`,',
    'so contributor code never executes with your secrets in scope. The SARIF upload',
    'is `continue-on-error` and degrades quietly where code scanning is unavailable.',
    '',
    'Disclosure: I maintain [ThreatCrush](https://github.com/profullstack/threatcrush).',
    'It is free and MIT, and the workflow installs it from npm — nothing here phones',
    'home. If this is not something you want, closing it is the right answer, and I',
    'will not send another.',
  ].join('\n');

/**
 * Open one. Forks, branches off *upstream's* head rather than the fork's,
 * writes the pack, pushes and asks.
 *
 * Upstream's head matters: a fork left over from a year ago is a year behind,
 * and a pull request built on it arrives carrying a year of reverts.
 */
async function openPr(repo: string, me: string, base: string, dryRun: boolean): Promise<string> {
  const pack = packDir();
  const inputs = packInputs();
  const files = [
    {
      destination: '.github/workflows/threatcrush-scan.yml',
      content: render(fs.readFileSync(path.join(pack, 'workflow.yml'), 'utf8'), inputs),
    },
    {
      destination: '.github/scripts/threatcrush-to-sarif.py',
      content: fs.readFileSync(path.join(pack, 'threatcrush-to-sarif.py'), 'utf8'),
    },
  ];

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tcfeed-pr-'));
  const src = path.join(tmp, 'src');
  const git = (args: string[]) => run('git', ['-C', src, ...args]);

  try {
    await run('git', [
      'clone',
      '--quiet',
      '--depth',
      '1',
      '--branch',
      base,
      `https://github.com/${repo}.git`,
      src,
    ]);

    // The authoritative check. The contents API sees file names; this sees
    // what is in them, including a threatcrush step living inside somebody's
    // ci.yml under a name that says nothing about it.
    const dotGithub = path.join(src, '.github');
    if (fs.existsSync(dotGithub)) {
      const { stdout } = await run('grep', ['-rli', 'threatcrush', dotGithub]).catch(() => ({
        stdout: '',
      }));
      if (stdout.trim()) return `already scans with threatcrush (${stdout.trim().split('\n')[0]})`;
    }

    await git(['checkout', '--quiet', '-b', PR_BRANCH]);
    for (const file of files) {
      const full = path.join(src, file.destination);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, file.content);
    }
    await git(['add', ...files.map((file) => file.destination)]);
    await git(['commit', '--quiet', '-m', 'ci: add the ThreatCrush security scan workflow']);

    if (dryRun) {
      const { stdout } = await git(['show', '--stat', '--oneline', 'HEAD']);
      console.log(`\n--- ${repo} (dry run, nothing pushed) — base ${base}`);
      console.log(stdout.trimEnd());
      console.log(`\n${PR_TITLE}\n\n${prBody()}`);
      return 'dry run';
    }

    // No --remote flag: gh rejects it outright when a repository argument is
    // given ("unsupported when a repository argument is provided") and prints
    // its help instead of forking. The failure is kept rather than discarded,
    // because forking something already forked is a no-op worth ignoring and
    // every other reason to fail is worth reading — swallowing both made a
    // broken invocation surface, three steps later, as "not a fork of".
    const forkFailed = await run('gh', ['repo', 'fork', repo, '--clone=false'])
      .then(() => '')
      .catch((error: Error) => error.message.split('\n')[0]);

    // gh names the fork after the upstream unless that name is taken, in which
    // case it silently picks another and the push below would land somewhere
    // unrelated. Confirm the parent instead of trusting the name.
    const name = repo.split('/')[1];
    const fork = `${me}/${name}`;
    let parent = '';
    for (let attempt = 1; attempt <= 10 && !parent; attempt++) {
      // Forking is asynchronous; the repository exists before it has content.
      if (attempt > 1) await sleep(3);
      // Composed from owner.login and name rather than read off
      // `.parent.nameWithOwner`, which does not exist: gh returns the parent
      // as `{id, name, owner}` only. Asking for the field that is not there
      // yields null, which is never equal to the repo, so every fork looked
      // like somebody else's and nothing was ever pushed.
      parent = await gh([
        'repo',
        'view',
        fork,
        '--json',
        'parent',
        '--jq',
        '.parent | select(.) | .owner.login + "/" + .name',
      ]).catch(() => '');
    }
    if (parent !== repo) {
      if (forkFailed) return `could not fork: ${forkFailed}`;
      return `${fork} is not a fork of ${repo}${parent ? ` (it forks ${parent})` : ''} — fork it by hand`;
    }

    // gh's credential helper applied per command, so this works whether or not
    // `gh auth setup-git` was ever run, and the token stays out of argv.
    await git([
      '-c',
      'credential.helper=',
      '-c',
      'credential.helper=!gh auth git-credential',
      'push',
      '--quiet',
      `https://github.com/${fork}.git`,
      `HEAD:${PR_BRANCH}`,
    ]);

    return await gh([
      'pr',
      'create',
      '--repo',
      repo,
      '--base',
      base,
      '--head',
      `${me}:${PR_BRANCH}`,
      '--title',
      PR_TITLE,
      '--body',
      prBody(),
    ]);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * The subcommand.
 *
 * Repositories are named as arguments and never read from the table. That is
 * the whole design: the scan produces a list, a person reads the list, and a
 * person types the names of the ones worth asking. There is no flag that turns
 * the table into pull requests, because bulk unsolicited pull requests are
 * against GitHub's acceptable use policy regardless of how good the workflow
 * is, and an account that sends them stops being able to send anything.
 */
async function prCommand(argv: string[]): Promise<number> {
  const dryRun = argv.includes('--dry-run') || argv.includes('-n');
  const repos = argv.filter((arg) => !arg.startsWith('-'));

  const wrong = repos.filter((repo) => !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo));
  if (wrong.length > 0) {
    console.error(`tcfeed: not owner/name: ${wrong.join(', ')}`);
    return 1;
  }
  if (repos.length === 0) {
    console.error('usage: tcfeed pr owner/name [owner/name ...] [--dry-run]');
    console.error('  Names are typed, never taken from the table. Read the report first.');
    return 1;
  }

  const max = num('TCFEED_PR_MAX', 3);
  if (repos.length > max) {
    console.error(`tcfeed: ${repos.length} repositories in one run, and the cap is ${max}.`);
    console.error('  This is a typo guard, not a throughput problem. Raise TCFEED_PR_MAX if');
    console.error('  you meant it, but read every report first — that is what the cap is for.');
    return 1;
  }

  for (const tool of ['git', 'gh', 'grep']) {
    if (!(await usable(tool, ['--version']))) {
      console.error(`tcfeed: missing ${tool}`);
      return 1;
    }
  }

  // Pushing a file under .github/workflows/ needs the `workflow` scope, and
  // without it the push fails after the fork already exists — a confusing
  // half-done state. Checked here, where the message can say what to do, and
  // skipped for a dry run, which pushes nothing and should not need it.
  if (!dryRun) {
    const scopes = await run('gh', ['auth', 'status'])
      .then(({ stdout, stderr }) => `${stdout}${stderr}`)
      .catch(() => '');
    if (!/Token scopes:.*\bworkflow\b/.test(scopes)) {
      console.error('tcfeed: this gh token cannot push workflow files.');
      console.error('  gh auth refresh -h github.com -s workflow');
      return 1;
    }
  }

  const me = await gh(['api', 'user', '--jq', '.login']).catch(() => '');
  if (!me) {
    console.error('tcfeed: gh is not logged in');
    return 1;
  }

  // Read once, so a pack that cannot be found or cannot be rendered stops the
  // run before it has forked anything.
  render(fs.readFileSync(path.join(packDir(), 'workflow.yml'), 'utf8'), packInputs());

  let opened = 0;
  for (const repo of repos) {
    const target = await prTarget(repo, me);
    if (typeof target === 'string') {
      console.log(`· ${repo} — skipped: ${target}`);
      continue;
    }

    try {
      const result = await openPr(repo, me, target.base, dryRun);
      console.log(`· ${repo} — ${result}`);
      if (result.startsWith('http')) opened++;
    } catch (error) {
      console.log(`· ${repo} — failed: ${(error as Error).message.split('\n')[0]}`);
    }
  }

  if (!dryRun && opened > 0) {
    console.log('');
    console.log(`${opened} opened. Watch them: a maintainer who says no gets no second request,`);
    console.log('and the closed pull request is what makes that automatic.');
  }
  return 0;
}

function table(rows: Row[]): void {
  const columns = [9, 6, 8, 7, 7];
  const line = (cells: string[]) =>
    cells.map((cell, i) => (i < columns.length ? cell.padEnd(columns[i]) : cell)).join(' ');

  console.log('');
  console.log(line(['CRITICAL', 'HIGH', 'MEDIUM', 'TOTAL', 'STARS', 'REPO']));

  const worst = (row: Row) => row.critical * 1000 + row.high;
  for (const row of [...rows].sort((a, b) => worst(b) - worst(a))) {
    console.log(
      line([
        String(row.critical),
        String(row.high),
        String(row.medium),
        String(row.total),
        String(row.stars),
        `https://github.com/${row.repo}`,
      ])
    );
  }
}

async function main(): Promise<number> {
  const argument = process.argv[2];
  const cache = process.env.TCFEED_CACHE || path.join(os.homedir(), '.cache', 'tcfeed');

  if (argument === '-h' || argument === '--help') {
    console.log('usage: tcfeed [count]                          scan the newest posts');
    console.log('       tcfeed --forget                         make everything look new again');
    console.log('       tcfeed pr owner/name [...] [--dry-run]  install the scan workflow');
    return 0;
  }

  if (argument === 'pr') return prCommand(process.argv.slice(3));

  if (argument === '--forget') {
    fs.rmSync(path.join(cache, 'seen'), { force: true });
    console.log('tcfeed: everything looks new again');
    return 0;
  }

  const limit = Number(argument) > 0 ? Number(argument) : 50;
  const scanner = process.env.TC_BIN || 'threatcrush';
  const sub = process.env.TCFEED_SUB || 'coolgithubprojects';

  for (const tool of ['curl', 'git', 'gh']) {
    if (!(await usable(tool, ['--version']))) {
      console.error(`tcfeed: missing ${tool}`);
      return 1;
    }
  }
  if (!(await usable(scanner, ['--version']))) {
    console.error(`tcfeed: no working scanner at '${scanner}'.`);
    console.error('  npm install -g --ignore-scripts @profullstack/threatcrush');
    console.error('  (--ignore-scripts skips a native build only its daemon needs)');
    return 1;
  }

  fs.mkdirSync(path.join(cache, 'reports'), { recursive: true });
  const seenFile = path.join(cache, 'seen');
  const seen = new Set(readOr(seenFile, '').split('\n').filter(Boolean));
  const remember = (repo: string) => {
    seen.add(repo);
    fs.appendFileSync(seenFile, `${repo}\n`);
  };

  let body: string;
  try {
    body = await readFeed(sub, limit, cache);
  } catch (error) {
    console.error(`tcfeed: ${(error as Error).message}`);
    return 1;
  }

  const repos = reposIn(body);
  if (repos.length === 0) {
    console.log('tcfeed: the feed mentioned no repositories');
    return 0;
  }

  // A run is capped and paced. One invocation that clones ninety repositories
  // back to back is a scraper, and the point of this is a shortlist to read
  // rather than a mirror of the feed.
  const max = num('TCFEED_MAX', 20);
  const pause = num('TCFEED_PAUSE', 1);
  const rows: Row[] = [];
  let scanned = 0;

  for (const repo of repos) {
    if (seen.has(repo)) continue;
    if (scanned >= max) {
      console.log(`· stopping at ${max} this run. Run it again for the rest.`);
      break;
    }
    if (scanned > 0) await sleep(pause);
    scanned++;

    const about = await metadata(repo);
    if (!about) {
      console.log(`· ${repo} (gone)`);
      remember(repo);
      continue;
    }
    if (about.archived) {
      console.log(`· ${repo} (archived)`);
      remember(repo);
      continue;
    }
    if (about.sizeKb > TOO_BIG_KB) {
      console.log(`· ${repo} (too big)`);
      remember(repo);
      continue;
    }

    const report = path.join(cache, 'reports', `${repo.replace(/\//g, '__')}.json`);
    const counted = await scan(scanner, repo, report);
    if (!counted) {
      console.log(`· ${repo} (nothing to read)`);
      remember(repo);
      continue;
    }

    rows.push({ repo, stars: about.stars, ...counted });
    console.log(`· ${repo} ${counted.critical}/${counted.high}/${counted.medium}/${counted.total}`);
    remember(repo);
  }

  if (rows.length === 0) {
    console.log('tcfeed: nothing new since last time');
    return 0;
  }

  table(rows);
  console.log('');
  console.log(`reports: ${path.join(cache, 'reports')}`);
  console.log('Read one before acting on it. Most of these are false positives, and a');
  console.log('pull request about a finding is something you write, not something this sends.');
  console.log('');
  console.log('To install the scan workflow in one of them instead:');
  console.log('  tcfeed pr owner/name --dry-run   # see exactly what would be opened');
  console.log('  tcfeed pr owner/name');
  return 0;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    console.error(`tcfeed: ${(error as Error).message}`);
    process.exitCode = 1;
  });
