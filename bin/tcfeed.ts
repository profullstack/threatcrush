#!/usr/bin/env -S npx tsx
/**
 * tcfeed — read the newest posts on a subreddit, find the repositories they
 * link, scan each one, and print a shortlist worth reading.
 *
 * It reports, and that is all it does. It does not fork anything and it does
 * not open pull requests. Four repositories scanned by hand this way produced
 * 166 findings and every one of them was a false positive; a bot that had
 * opened four pull requests off that would have sent four pieces of spam.
 * Bulk unsolicited pull requests are also against GitHub's acceptable use
 * policy and are the fastest way to get an account flagged. Read the report,
 * pick the finding that is real, then write that pull request yourself.
 *
 *   npx tsx bin/tcfeed.ts        # the 50 newest posts
 *   npx tsx bin/tcfeed.ts 100    # more of them
 *   npx tsx bin/tcfeed.ts --forget
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

  if (fs.existsSync(stamp)) {
    const since = Math.floor(Date.now() / 1000) - Number(fs.readFileSync(stamp, 'utf8').trim());
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
    console.log('usage: tcfeed [count] | tcfeed --forget');
    return 0;
  }

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
  const seen = new Set(
    fs.existsSync(seenFile) ? fs.readFileSync(seenFile, 'utf8').split('\n').filter(Boolean) : []
  );
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
  console.log('Read one before acting on it. Most of these are false positives,');
  console.log('and a pull request is something you write, not something this sends.');
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
