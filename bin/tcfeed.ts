#!/usr/bin/env -S npx tsx
/**
 * tcfeed — find repositories worth a look, scan each one, and print a
 * shortlist worth reading.
 *
 * Three sources, merged and deduplicated: the newest posts on a subreddit,
 * GitHub's own repository search sorted by most recently updated, and any RSS
 * or Atom feeds you have added. Each is allowed to fail on its own — reddit
 * refuses this address often enough that making it fatal meant a whole run
 * produced nothing on an afternoon when the others were answering perfectly.
 *
 *   tcfeed rss add https://leaddev.com/feed
 *   tcfeed rss list
 *   tcfeed rss remove https://leaddev.com/feed
 *
 * The feed list is OPML, at ~/.moshcode/feeds.opml, because every reader
 * imports and exports that format and because moshcode's `/save` copies that
 * directory to your account — so the list arrives on the next machine without
 * this being the only place it lives.
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
 * It is cold outreach, so it goes in the order cold outreach is owed. An
 * issue asks the question, the pull request follows so the diff is there to
 * read rather than imagine, and when everything is open it waits for their
 * checks and fixes what it recognises as its own mess. The first batch of six
 * was closed six times, once with "please open an issue about this first for
 * discussion" and once by a maintainer's own scanner finding a real fault in
 * the workflow — this order is what those two answers cost.
 *
 *   npx tsx bin/tcfeed.ts pr owner/name --dry-run
 *   npx tsx bin/tcfeed.ts pr owner/name
 *   npx tsx bin/tcfeed.ts pr --all              # ask, offer, watch, fix
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
 *   TCFEED_GH       results taken from the search, default 25, 0 turns it off
 *   TCFEED_GH_QUERY the search, default `stars:1000..10000`. Use the `a..b`
 *                   form: `stars:>1000 stars:<10000` does not AND, and
 *                   `starts` is a free-text search for the word. Both return
 *                   results rather than an error — see searchRepos()
 *   TCFEED_OPML     the feed list, default ~/.moshcode/feeds.opml
 *   TCFEED_RSS_PAUSE seconds between feed fetches, default 1
 *   TC_BIN          the scanner, default whatever `threatcrush` resolves to
 *   TCFEED_CACHE    where seen repos and reports live, default ~/.cache/tcfeed
 *
 * and for `pr`:
 *
 *   TCFEED_PACK     the action pack directory, default ../sh1pt/packages/…
 *   TCFEED_PR_MAX   repositories one `pr` run may open against, default 20
 *   TCFEED_PR_PAUSE seconds between requests that open, default 20
 *   TCFEED_PR_STANDING  unanswered requests allowed to stand at once, default 30
 *   TCFEED_PR_PER_DAY   requests opened in a rolling 24 hours, default 20
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

/**
 * Why a command failed, in one line, taking the line that says something.
 *
 * execFile builds `message` as "Command failed: <the entire command>" and puts
 * the actual complaint on the lines after it, so reading the first line of the
 * message reports the command back at you and drops the reason. `gh pr create`
 * failing against a repository that refuses pull requests from this account
 * printed the title, the head ref and the first line of the body, and not one
 * word about permissions; the cause took a manual re-run to find.
 *
 * stderr is where the tools here put their reasons, so it is preferred, and
 * its last meaningful line is the complaint — gh writes progress above it.
 * git's advice is dropped first: it ends with "hint: See the 'Note about
 * fast-forwards'", which is three lines below the "! [rejected]" that says
 * what actually happened, so taking the last line literally reports the
 * footnote instead of the failure.
 */
function why(error: unknown): string {
  const meaningful = (lines: string[]) =>
    lines.filter((line) => line.trim() && !/^(hint:|To https?:|remote:\s*$)/.test(line.trim()));

  const stderr = String((error as { stderr?: string })?.stderr ?? '').trim();
  if (stderr) {
    const said = meaningful(stderr.split('\n'));
    if (said.length > 0) return said[said.length - 1].trim();
  }
  const message = String((error as Error)?.message ?? error ?? 'unknown');
  const lines = message.split('\n').filter((line) => line.trim());
  // Past the "Command failed: …" preamble when there is anything past it.
  const useful = lines.find((line) => !/^Command failed:/.test(line));
  return (useful ?? lines[0] ?? 'unknown').trim();
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

/* ------------------------------------------------------------------ *
 * rss — a list of feeds, kept as OPML
 * ------------------------------------------------------------------ */

/**
 * OPML, and under ~/.moshcode, for one reason each.
 *
 * OPML because a feed list is the one thing in this program somebody already
 * has somewhere else: every reader imports and exports it, so the list can
 * arrive from one and leave for another without this becoming the only place
 * it exists.
 *
 * Under ~/.moshcode because that is the directory moshcode's `/save` copies to
 * the account, and a feed list is exactly the sort of thing that should follow
 * a person to their next machine. The server there validates shape rather than
 * filenames — no `..`, no leading slash, 32 files, 256KB — so it accepts this
 * without anything being deployed; only moshcode's own SYNCED_FILES has to
 * name it. Nothing here depends on moshcode being installed: the file is
 * created on demand, and TCFEED_OPML moves it anywhere.
 */
const opmlPath = (): string =>
  process.env.TCFEED_OPML || path.join(os.homedir(), '.moshcode', 'feeds.opml');

/**
 * The xmlUrl of every outline, in file order.
 *
 * Matched rather than parsed. A feed list is a flat list of attributes and the
 * alternative is an XML dependency for the sake of one of them; what this
 * cannot do is understand nested outlines, which readers use for folders, so
 * they flatten to their feeds and the folder is lost on rewrite. Attribute
 * order and quoting style vary between readers, hence both quote characters.
 */
function feedsIn(opml: string): string[] {
  const found: string[] = [];
  for (const [, url] of opml.matchAll(/xmlUrl\s*=\s*["']([^"']+)["']/gi)) {
    const trimmed = url.trim();
    if (trimmed && !found.includes(trimmed)) found.push(trimmed);
  }
  return found;
}

/** Undo the five entities an attribute value can carry. */
const unescapeXml = (value: string): string =>
  value
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&');

/** And redo them. `&` last on the way out, first on the way in, or it doubles. */
const escapeXml = (value: string): string =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const readFeeds = (): string[] => feedsIn(readOr(opmlPath(), '')).map(unescapeXml);

/**
 * Written whole rather than edited in place, so the file is always something a
 * reader will open even after this has had a turn at it.
 */
function writeFeeds(urls: string[]): void {
  const file = opmlPath();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const outlines = urls
    .map((url) => {
      // The host is a serviceable title when nothing supplied one, and a feed
      // whose URL will not parse is not a feed this is going to fetch either.
      let title = url;
      try {
        title = new URL(url).hostname.replace(/^www\./, '');
      } catch {
        /* keep the URL as the title */
      }
      return `    <outline type="rss" text="${escapeXml(title)}" xmlUrl="${escapeXml(url)}"/>`;
    })
    .join('\n');

  fs.writeFileSync(
    file,
    `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<opml version="2.0">\n` +
      `  <head>\n    <title>tcfeed</title>\n  </head>\n` +
      `  <body>\n${outlines}${outlines ? '\n' : ''}  </body>\n` +
      `</opml>\n`
  );
}

/**
 * `tcfeed rss` — add, list and remove, and that is the whole surface.
 *
 * Nothing validates that a URL is a feed by fetching it. A feed that is down
 * this minute is still a feed, and refusing to record it because of one
 * request is worse than recording it and saying so at the next scan.
 */
async function rssCommand(argv: string[]): Promise<number> {
  const [action, ...rest] = argv.filter((arg) => !arg.startsWith('-'));
  const urls = readFeeds();

  if (!action || action === 'list') {
    if (urls.length === 0) {
      console.log(`no feeds yet — ${opmlPath()}`);
      console.log('  tcfeed rss add https://example.com/feed');
      return 0;
    }
    for (const url of urls) console.log(`· ${url}`);
    console.log('');
    console.log(`${urls.length} feed${urls.length === 1 ? '' : 's'} — ${opmlPath()}`);
    return 0;
  }

  if (action === 'add') {
    if (rest.length === 0) {
      console.error('usage: tcfeed rss add https://example.com/feed');
      return 1;
    }
    const added: string[] = [];
    for (const url of rest) {
      // http(s) only. A feed list is fetched with curl, and `file://` in it
      // would make a shared OPML read this machine's disk.
      if (!/^https?:\/\//i.test(url)) {
        console.error(`tcfeed: not an http(s) URL: ${url}`);
        return 1;
      }
      if (urls.includes(url)) {
        console.log(`· ${url} — already there`);
        continue;
      }
      urls.push(url);
      added.push(url);
    }
    if (added.length > 0) {
      writeFeeds(urls);
      for (const url of added) console.log(`· ${url} — added`);
    }
    return 0;
  }

  if (action === 'remove' || action === 'rm') {
    if (rest.length === 0) {
      console.error('usage: tcfeed rss remove https://example.com/feed');
      return 1;
    }
    const kept = urls.filter((url) => !rest.includes(url));
    if (kept.length === urls.length) {
      console.error(`tcfeed: not in the list: ${rest.join(', ')}`);
      console.error('  tcfeed rss list');
      return 1;
    }
    writeFeeds(kept);
    for (const url of rest) console.log(`· ${url} — removed`);
    return 0;
  }

  console.error(`tcfeed: unknown — rss ${action}`);
  console.error('usage: tcfeed rss [list] | rss add <url> ... | rss remove <url> ...');
  return 1;
}

/**
 * Every feed, fetched and concatenated for reposIn() to read.
 *
 * The bodies are joined rather than parsed. reposIn() already looks for
 * repository links anywhere in a document, which is the only thing wanted from
 * a feed, and it works the same on RSS, Atom and the HTML some of them serve
 * by mistake — none of which a feed parser would agree about.
 *
 * A feed that fails is named and skipped. One dead blog must not be the reason
 * a scan produced nothing.
 */
async function readRss(urls: string[], pause: number): Promise<{ body: string; broke: string[] }> {
  const bodies: string[] = [];
  const broke: string[] = [];

  for (const [index, url] of urls.entries()) {
    if (index > 0 && pause > 0) await sleep(pause);
    const { code, body } = await ask(url);
    if (code === '200' && body) bodies.push(body);
    else broke.push(`${url} (HTTP ${code || 'none'})`);
  }

  return { body: bodies.join('\n'), broke };
}

/**
 * The other source: GitHub's own repository search, newest activity first.
 *
 * This is the API behind
 * https://github.com/search?q=stars:1000..10000&type=repositories&s=updated&o=desc,
 * asked through gh so it uses the token already on this machine — the HTML
 * page is rate-limited hard for anyone not signed in, and parsing it would be
 * a scraper of a page that changes shape without warning.
 *
 * `stars:1000..10000` — a thousand to ten thousand, sorted by most recently
 * pushed. Two traps live in that one string, and both produce a result rather
 * than an error, which is why they are written down here:
 *
 *   `starts:1000..10000`        the qualifier is `stars`. Misspelt, GitHub
 *                               does not reject it — it becomes a free-text
 *                               search for the word and returns repositories
 *                               with no stars at all.
 *
 *   `stars:>1000 stars:<10000`  two range qualifiers on one field do not AND.
 *                               This form returned meilisearch at 58,955
 *                               stars, comfortably outside the bound it
 *                               appears to state. The `a..b` form is the one
 *                               that actually restricts both ends.
 *
 * The upper bound earns its place. Without it the band is dominated by
 * monorepos that the TOO_BIG_KB check throws away after cloning decides they
 * are too large: measured over twenty results, `stars:>1000` yielded twelve
 * scannable repositories against eight discarded, where `stars:1000..10000`
 * yields fourteen against six.
 *
 * Override with TCFEED_GH_QUERY, which takes any GitHub search qualifier.
 *
 * Archived and forked repositories are dropped here rather than left for
 * metadata() to reject one HTTP call later, because the search already knows.
 * Size is not, because the search has no qualifier for it.
 */
async function searchRepos(query: string, limit: number): Promise<string[]> {
  const { stdout } = await run(
    'gh',
    [
      'search',
      'repos',
      query,
      '--sort',
      'updated',
      '--order',
      'desc',
      '--limit',
      String(limit),
      '--json',
      'fullName,isArchived,isFork',
    ],
    { maxBuffer: 32 * 1024 * 1024 }
  );

  const found = JSON.parse(stdout) as {
    fullName: string;
    isArchived: boolean;
    isFork: boolean;
  }[];

  return found
    .filter((entry) => !entry.isArchived && !entry.isFork && entry.fullName)
    .map((entry) => entry.fullName);
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

/**
 * The version the workflow installs, resolved once per run.
 *
 * An exact version rather than `@latest`, because `@latest` in a file
 * committed to somebody else's repository means their security gate installs
 * whatever was published overnight, from a job holding `pull-requests: write`
 * and `security-events: write`. Static analysis says so out loud —
 * SonarQube's githubactions:S8543 failed our own workflow on the one
 * repository that ran it, alongside S6505 for the missing --ignore-scripts.
 *
 * Resolved at ask time rather than hardcoded so each request pins whatever is
 * current that day; from then on the repository moves when it decides to,
 * which is the only thing a pin is for.
 */
let pinned = '';
async function resolveSpec(): Promise<string> {
  const told = process.env.TCFEED_SPEC;
  if (told) return told;
  if (pinned) return pinned;

  const { stdout } = await run('npm', ['view', '@profullstack/threatcrush', 'version']);
  const version = stdout.trim();
  // A pin this could not resolve is the one case where carrying on is worse
  // than stopping: the fallback would be `@latest`, which is the exact string
  // this exists to keep out of other people's repositories.
  if (!/^\d+\.\d+\.\d+/.test(version)) {
    throw new Error(`npm did not name a version to pin (got ${JSON.stringify(version)})`);
  }
  pinned = `@profullstack/threatcrush@${version}`;
  return pinned;
}

/** The pack's inputs, at the defaults its own manifest documents. */
const packInputs = (spec: string): Record<string, string> => ({
  scanPath: '.',
  nodeVersion: process.env.TCFEED_NODE || '20',
  threatcrushPackageSpec: spec,
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
async function prTarget(
  repo: string,
  me: string
): Promise<{ base: string; hasIssues: boolean } | string> {
  let about: {
    isArchived: boolean;
    isFork: boolean;
    visibility: string;
    hasIssuesEnabled: boolean;
    defaultBranchRef: { name: string } | null;
  };
  try {
    about = JSON.parse(
      await gh([
        'repo',
        'view',
        repo,
        '--json',
        'isArchived,isFork,visibility,hasIssuesEnabled,defaultBranchRef',
      ])
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

  // The same promise, on the other channel. Now that the question goes as an
  // issue, a repository that answered the issue and never got a pull request —
  // because it said no, which is the answer the issue is for — has no pull
  // request for the check above to find. Without this, "no" on an issue is
  // followed by the whole thing again on the next run, which is exactly the
  // behaviour asking first was meant to avoid.
  //
  // Searched by title rather than by label or body: nothing here can put a
  // label on somebody else's repository, and the title is the one field this
  // program controls and never varies.
  const raised = JSON.parse(
    await gh([
      'api',
      '-XGET',
      'search/issues',
      '-f',
      `q=repo:${repo} author:${me} type:issue in:title "${ISSUE_TITLE}"`,
      '--jq',
      '{items: [.items[] | {html_url, state}]}',
    ]).catch(() => '{"items":[]}')
  ) as { items: { html_url: string; state: string }[] };
  if (raised.items.length > 0) {
    return `already asked — issue ${raised.items[0].state}, ${raised.items[0].html_url}`;
  }

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

  return { base: about.defaultBranchRef.name, hasIssues: about.hasIssuesEnabled };
}

const PR_TITLE = 'ci: scan pull requests for credentials and injection with ThreatCrush';

/**
 * The CodeQL answer, because "we already get this from GitHub" is the reason
 * maintainers actually give, and saying nothing about it reads as not having
 * an answer.
 *
 * It says *different*, never *better*, and the restraint is deliberate. It is
 * not better at what CodeQL does: CodeQL is semantic dataflow analysis and
 * most of this is pattern matching, which our own output admits every time it
 * prints `confidence: pattern` next to a finding. Told "we'll likely try
 * CodeQL first" by somebody who has read both, an overclaim here is checkable
 * on the spot and loses the rest of the paragraph with it.
 *
 * So: two differences that are true, dated, and verifiable by the reader
 * without taking our word for anything, and then the offer to be closed.
 */
const alongsideCodeql = [
  '**This is not a CodeQL replacement, and it is worth saying where it differs.**',
  'CodeQL does semantic dataflow analysis and is better at it than this is — a',
  'repository already running it is not missing much by closing this. Two gaps it',
  'does fill:',
  '',
  '- Code scanning and secret scanning are free on public repositories, but need',
  '  paid GitHub Code Security / Secret Protection on private ones. This is MIT and',
  '  free on both, so the same gate can run across a mixed set of repositories.',
  '- CodeQL analyses a fixed set of languages, and among compiled ones it analyses',
  "  only the language with the most source files unless it's explicitly configured",
  '  otherwise. In a polyglot repository the rest goes unscanned by default; this',
  '  reads every file it is pointed at.',
  '',
  'It is additive and report-only, so running both costs a few CI minutes and',
  'changes nothing else.',
];

/**
 * Written to be easy to say no to. It quotes no findings and asserts nothing
 * about the code — a pull request that opens with "your repo has 30 high
 * severity issues" is a claim the sender has not verified, and in this
 * project's own sample every one of those claims was false. This one adds a
 * workflow, discloses who wrote the workflow, and says it will not be sent
 * twice. Everything past that is the maintainer's call.
 */
const prBody = (spec: string, issue: string): string =>
  [
    'Adds a pull-request workflow that scans the diff for hardcoded credentials,',
    'injection, SSRF and unsafe deserialisation. Results go to the Security tab as',
    'SARIF and to a comment on the pull request.',
    '',
    // The diff exists so the question in the issue can be answered by reading
    // it rather than imagining it. Which of the two gets closed is the
    // maintainer's choice, and saying so costs nothing.
    ...(issue
      ? [
          'Opened alongside the question in',
          `${issue}, which is the place to say no or ask for`,
          'changes. This is only the diff, so it is there to read rather than imagine —',
          'closing either one is a fine answer.',
          '',
        ]
      : []),
    ...alongsideCodeql,
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
    `The CLI is pinned to \`${spec}\` and installed with`,
    '`--ignore-scripts`, and checkout runs with `persist-credentials: false`. A',
    "scanner that installs a floating version, runs its dependencies' lifecycle",
    'scripts and leaves a token in `.git/config` is asking you to trust more than it',
    'is worth, and none of that is needed to read a diff. Bump the pin whenever you',
    'like — nothing here updates itself.',
    '',
    'Disclosure: I maintain [ThreatCrush](https://github.com/profullstack/threatcrush).',
    'It is free and MIT, and the workflow installs it from npm — nothing here phones',
    'home. If this is not something you want, closing it is the right answer, and I',
    'will not send another.',
  ].join('\n');

/**
 * How many requests may be opened right now, and why not more.
 *
 * TCFEED_PR_MAX bounds a run. Nothing bounded the account, and on the first
 * day that mattered: 33 unsolicited pull requests went out in a single day
 * across 33 strangers' repositories, 25 of them still unanswered days later.
 * Each run was individually within its cap and the total was nowhere near
 * defensible, which is the difference between a per-run cap and a budget.
 *
 * prCommand's own docstring already said what this costs — bulk unsolicited
 * pull requests are against GitHub's acceptable use policy however good the
 * workflow is, and an account that sends them stops being able to send
 * anything — so this is that paragraph made executable rather than advisory.
 *
 * Two numbers, because they fail differently:
 *
 *   standing  unanswered requests sitting in other people's repositories. The
 *             footprint. 33 open requests is what "bulk" looks like to a
 *             human reading the account, whenever they were sent.
 *   perDay    requests opened in a rolling 24 hours. The velocity. 33 in one
 *             afternoon reads as automation even if the total is modest.
 *
 * Counted with search/issues total_count rather than by listing, because
 * listing caps at 100 and a budget that silently undercounts once the number
 * gets interesting is worse than no budget at all.
 */
async function budget(me: string): Promise<{ allowed: number; note: string }> {
  const standingCap = num('TCFEED_PR_STANDING', 30);
  // 20, matching TCFEED_PR_MAX: one full --all run is a day's sending. A
  // number below the run cap would mean the headline command could never
  // complete in one go, which reads as a bug rather than as a budget.
  const dailyCap = num('TCFEED_PR_PER_DAY', 20);

  const count = async (extra: string): Promise<number> => {
    const said = await gh([
      'api',
      '-XGET',
      'search/issues',
      '-f',
      `q=type:pr author:${me} in:title "${PR_TITLE}" ${extra}`,
      '--jq',
      '.total_count',
    ]);
    const total = Number(said.trim());
    // A budget that cannot count is not a budget. Refusing here costs one run;
    // guessing zero would open the floodgates on exactly the failure this is
    // meant to catch.
    if (!Number.isFinite(total)) throw new Error(`could not count requests (got ${said.trim()})`);
    return total;
  };

  const standing = await count('state:open');
  // A rolling day, not "since midnight": the point is velocity, and midnight
  // resets it to zero for an account that sent thirty at 23:00.
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString().slice(0, 19) + 'Z';
  const today = await count(`created:>=${since}`);

  const room = Math.min(standingCap - standing, dailyCap - today);
  const note =
    `${standing} unanswered of ${standingCap}, ${today} opened in the last day of ${dailyCap}`;
  return { allowed: Math.max(0, room), note };
}

const ISSUE_TITLE = 'Would you take a pull-request security scan workflow?';

/**
 * The question that goes first.
 *
 * capstone's maintainer closed the pull request with "please open an issue
 * about this first for discussion", and that is the standard courtesy for an
 * unsolicited CI change: a pull request arrives as a decision already made and
 * a diff to review, an issue arrives as a question. Two of the other closes
 * were project-direction answers — "not planned for now", "not intending to
 * integrate" — that an issue would have got without anyone reading a diff.
 *
 * So it describes, links, and asks. It quotes no findings and names no
 * severity, for the same reason the pull request body does not: a claim about
 * somebody's code that the sender has not verified is the fastest way to be
 * ignored, and in this project's own sample every such claim was false.
 */
const issueBody = (spec: string): string =>
  [
    'Hello — would a pull-request security scan be useful here, or is this',
    'already covered?',
    '',
    'The offer is one workflow that scans each pull request diff for hardcoded',
    'credentials, injection, SSRF and unsafe deserialisation, and writes results to',
    'the Security tab as SARIF plus a comment on the pull request. It is report-only',
    "(`failOn` empty), so it annotates and never fails a build — a first install on a",
    'repository with a backlog should produce a report, not a blocked pull request.',
    '',
    ...alongsideCodeql,
    '',
    'How it is wired, since this is the part worth objecting to:',
    '',
    '- runs on `pull_request`, not `pull_request_target`, so contributor code never',
    '  executes with your secrets in scope',
    `- installs a pinned \`${spec}\` with \`--ignore-scripts\``,
    '- `contents: read`, `pull-requests: write`, `security-events: write`, and',
    '  `persist-credentials: false` on checkout',
    '- two files, both under `.github/`; nothing else in the tree is touched',
    '',
    'Disclosure: I maintain [ThreatCrush](https://github.com/profullstack/threatcrush).',
    'It is free and MIT, and the workflow installs it from npm — nothing here phones',
    'home. I am opening a pull request alongside this so the diff is there to read if',
    'you want it, and it can be closed and this discussed instead.',
    '',
    'If this is not something you want, saying so is the right answer and I will not',
    'ask again.',
  ].join('\n');

/**
 * Ask. Cheap next to openPr — no fork, no clone, no push — which is most of
 * why it goes first.
 */
async function openIssue(repo: string, spec: string, dryRun: boolean): Promise<string> {
  if (dryRun) {
    console.log(`\n--- ${repo} (dry run, nothing opened)`);
    console.log(`\n${ISSUE_TITLE}\n\n${issueBody(spec)}`);
    return 'dry run';
  }

  return await gh([
    'issue',
    'create',
    '--repo',
    repo,
    '--title',
    ISSUE_TITLE,
    '--body',
    issueBody(spec),
  ]);
}

/**
 * Open one. Forks, branches off *upstream's* head rather than the fork's,
 * writes the pack, pushes and asks.
 *
 * Upstream's head matters: a fork left over from a year ago is a year behind,
 * and a pull request built on it arrives carrying a year of reverts.
 */
async function openPr(
  repo: string,
  me: string,
  base: string,
  issue: string,
  dryRun: boolean
): Promise<string> {
  const pack = packDir();
  const spec = await resolveSpec();
  const inputs = packInputs(spec);
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
      console.log(`\n${PR_TITLE}\n\n${prBody(spec, issue)}`);
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
      .catch((error: unknown) => why(error));

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
    //
    // Forced, and only this far into the function. Getting here means prTarget
    // found no request on this repository in any state, so a branch already
    // sitting on the fork is debris from a run that pushed and then failed to
    // ask — the earlier attempt against a repository that refuses pull
    // requests from this account left exactly that. Unforced, the leftover is
    // permanent: the new branch is built from a fresh clone of upstream and is
    // no descendant of it, so every later attempt is rejected as a
    // non-fast-forward and the repository can never be asked at all.
    //
    // What is overwritten is a branch on our own fork, named by this program,
    // with no pull request pointing at it. The lease is pinned to the SHA the
    // fork actually has rather than left bare: bare --force-with-lease needs a
    // remote-tracking ref to compare against, and pushing to a URL never
    // creates one, so it refuses every time with "failed to push some refs"
    // and reads exactly like the rejection it was meant to replace.
    const standing = await gh([
      'api',
      `repos/${fork}/branches/${PR_BRANCH}`,
      '--jq',
      '.commit.sha',
    ]).catch(() => '');

    await git([
      '-c',
      'credential.helper=',
      '-c',
      'credential.helper=!gh auth git-credential',
      'push',
      '--quiet',
      // Nothing there is the ordinary case, and a plain push is right for it.
      ...(standing ? [`--force-with-lease=${PR_BRANCH}:${standing}`] : []),
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
      prBody(spec, issue),
    ]);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * The subcommand.
 *
 * Repositories are named as arguments, or taken from the last scan with
 * --all — worst first, so a cap takes the top of the table rather than an
 * arbitrary slice of it.
 *
 * --all used to be the one flag this deliberately did not have, and the rails
 * around it are now the point. Bulk unsolicited pull requests are against
 * GitHub's acceptable use policy however good the workflow is, and an account
 * that sends them stops being able to send anything. So: TCFEED_PR_MAX still
 * bounds a run and says out loud how many it left behind, TCFEED_PR_PAUSE
 * spaces the ones it does open, a repository already asked is never asked
 * twice whatever its answer was, and --all means the run whose table is still
 * on the screen rather than every repository the cache has ever seen.
 *
 * All of which bounded the run and none of which bounded the account, so 33
 * went out in one day and 25 were still unanswered days later. budget() is the
 * rail that was missing: standing footprint and rolling velocity, checked
 * before anything opens.
 *
 * None of which makes the pull requests wanted. Seven maintainers have answered
 * so far and all seven closed it.
 */
async function prCommand(argv: string[], cache: string): Promise<number> {
  const dryRun = argv.includes('--dry-run') || argv.includes('-n');
  const all = argv.includes('--all');
  // Both default on, and both are escapes rather than opt-ins: asking first
  // and cleaning up after are the courtesies, so they should be what happens
  // when nobody types anything.
  const noIssue = argv.includes('--no-issue');
  const noFollow = argv.includes('--no-follow');
  const named = argv.filter((arg) => !arg.startsWith('-'));

  if (all && named.length > 0) {
    console.error('tcfeed: --all takes the last run, so naming repositories with it is');
    console.error('  ambiguous. Use one or the other.');
    return 1;
  }

  // --all is the table from the run whose output is still on the screen, worst
  // first — not every repository ever scanned. The cache holds months of them
  // and none of that was being looked at when --all was typed.
  let repos = named;
  if (all) {
    repos = readOr(path.join(cache, 'lastrun'), '').split('\n').filter(Boolean);
    if (repos.length === 0) {
      console.error('tcfeed: no last run to take. Run a scan first — --all is the table');
      console.error('  it prints, and there has not been one since this cache was made.');
      return 1;
    }
  }

  const wrong = repos.filter((repo) => !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo));
  if (wrong.length > 0) {
    console.error(`tcfeed: not owner/name: ${wrong.join(', ')}`);
    return 1;
  }
  if (repos.length === 0) {
    console.error('usage: tcfeed pr owner/name [owner/name ...] [--dry-run]');
    console.error('       tcfeed pr --all [--dry-run]');
    console.error('  --all is the last scan, worst first. Read the reports first.');
    console.error('');
    console.error('  Each repository gets an issue asking the question, then the pull');
    console.error('  request so the diff is there to read. When every one is open it');
    console.error('  waits for their checks and fixes what it recognises as its own.');
    console.error('    --no-issue   the diff alone, no question first');
    console.error('    --no-follow  open them and stop; `tcfeed check --fix` does the rest');
    return 1;
  }

  // 20, matching TCFEED_MAX: a scan takes twenty repositories at a time, so a
  // cap below that guaranteed every --all run left something behind and had to
  // be run again to finish what it started.
  const max = num('TCFEED_PR_MAX', 20);
  if (!all && repos.length > max) {
    console.error(`tcfeed: ${repos.length} repositories in one run, and the cap is ${max}.`);
    console.error('  This is a typo guard, not a throughput problem. Raise TCFEED_PR_MAX if');
    console.error('  you meant it, but read every report first — that is what the cap is for.');
    return 1;
  }

  // Named repositories were typed and refusing them is right; --all was one
  // word and refusing it is only annoying, so the cap throttles instead. What
  // it must not do is throttle silently: a run that quietly did some of the
  // table reads exactly like a run that did all of it.
  if (all && repos.length > max) {
    console.log(`tcfeed: ${repos.length} in the last run, taking the worst ${max}.`);
    console.log(`  ${repos.slice(max).length} left for a later run, or raise TCFEED_PR_MAX.`);
    repos = repos.slice(0, max);
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
  // run before it has forked anything. Resolving the pin here too means a
  // registry that will not name a version stops the run at the same point,
  // rather than after the first fork.
  const spec = await resolveSpec();
  render(fs.readFileSync(path.join(packDir(), 'workflow.yml'), 'utf8'), packInputs(spec));

  // The account's budget, after the run's own cap and before anything is
  // opened. A dry run is exempt because it opens nothing; it still prints the
  // standing, which is the number worth seeing before deciding to send.
  const { allowed, note } = await budget(me);
  console.log(`standing: ${note}`);
  if (!dryRun) {
    if (allowed === 0) {
      console.error('');
      console.error('tcfeed: no room to send. Nothing was opened.');
      console.error('  `tcfeed check` shows where the open ones stand; the budget frees up as');
      console.error('  they are answered, and the rolling day frees up on its own.');
      console.error('  TCFEED_PR_STANDING and TCFEED_PR_PER_DAY raise it if you mean to.');
      return 1;
    }
    if (repos.length > allowed) {
      // Said out loud, for the same reason the --all cap says it: a run that
      // quietly did four of twenty reads exactly like a run that did twenty.
      console.log(`  room for ${allowed} this run; ${repos.length - allowed} left for later.`);
      repos = repos.slice(0, allowed);
    }
  }

  // Paced, and only between requests that actually opened. Forking, pushing
  // and opening in a tight loop is the shape GitHub's abuse detection watches
  // for, and being throttled mid-run leaves half a fork behind. A skip costs
  // nothing and waits for nothing.
  const pause = num('TCFEED_PR_PAUSE', 20);

  let opened = 0;
  const landed: { repo: string; pr: string }[] = [];
  for (const repo of repos) {
    const target = await prTarget(repo, me);
    if (typeof target === 'string') {
      console.log(`· ${repo} — skipped: ${target}`);
      continue;
    }

    if (opened > 0 && !dryRun && pause > 0) await sleep(pause);

    // The question first, and its failure is not the pull request's failure.
    // An issue that could not be opened — a repository that takes them through
    // a template this cannot fill, an account rate-limited on issues alone —
    // is a reason to ask on the other channel, not to give up on the repo.
    let issue = '';
    if (noIssue) {
      // Nothing: the caller asked for the diff on its own.
    } else if (!target.hasIssues) {
      console.log(`· ${repo} — issues are disabled here, so the request is the only channel`);
    } else {
      try {
        issue = await openIssue(repo, spec, dryRun);
        if (issue.startsWith('http')) console.log(`· ${repo} — asked ${issue}`);
      } catch (error) {
        console.log(`· ${repo} — issue failed: ${why(error)}`);
      }
    }

    try {
      const result = await openPr(repo, me, target.base, issue, dryRun);
      console.log(`· ${repo} — ${result}`);
      if (result.startsWith('http')) {
        opened++;
        landed.push({ repo, pr: result });
      }
    } catch (error) {
      console.log(`· ${repo} — failed: ${why(error)}`);
    }
  }

  // Every request opened, then every request watched — rather than watching
  // each one before opening the next. CI on the first repository runs while
  // the rest are still being opened, so by the time this loop reaches them
  // most have already settled and the wait is nearly free. Watching inline
  // would serialise a ten-minute wait behind every single request.
  if (!dryRun && !noFollow && landed.length > 0) {
    console.log('');
    console.log(`Watching ${landed.length} for red checks. Ctrl-C is safe — nothing is`);
    console.log('half-done, and `tcfeed check --fix` picks up exactly where this stops.');
    for (const { repo, pr } of landed) await followUp(repo, me, pr);
  }

  if (!dryRun && opened > 0) {
    console.log('');
    console.log(`${opened} opened. A maintainer who says no gets no second request, on either`);
    console.log('channel — the closed request and the answered issue are both remembered.');
  }
  return 0;
}

/* ------------------------------------------------------------------ *
 * follow — wait for the checks, then fix what is ours
 * ------------------------------------------------------------------ */

interface CheckRow {
  name: string;
  bucket: string;
  link: string;
}

/**
 * Wait for a request's checks to stop moving.
 *
 * `gh pr checks` rather than the Actions API, because the two failures that
 * mattered most in the first batch came from neither: SonarCloud and
 * CodeRabbit report as check runs from an app, and a poll that only reads
 * `actions/runs` sees a clean pull request while the maintainer is looking at
 * a red X. It exits non-zero whenever anything is failing or pending, so the
 * exit code is deliberately ignored and only the JSON is read.
 */
async function settle(repo: string, pr: string): Promise<CheckRow[] | string> {
  const number = pr.split('/').pop() ?? '';
  const every = num('TCFEED_FOLLOW_POLL', 30);
  const limit = num('TCFEED_FOLLOW_WAIT', 900);

  for (let waited = 0; ; waited += every) {
    const said = await run('gh', [
      'pr',
      'checks',
      number,
      '--repo',
      repo,
      '--json',
      'name,bucket,link',
    ])
      .then(({ stdout }) => stdout)
      .catch((error: { stdout?: string }) => error.stdout ?? '');

    let rows: CheckRow[] = [];
    try {
      rows = JSON.parse(said || '[]') as CheckRow[];
    } catch {
      return 'could not read the checks';
    }

    // No checks at all is an answer, not a wait. A repository with no CI never
    // grows a check run, and polling one for fifteen minutes is fifteen
    // minutes of nothing.
    if (rows.length === 0) return [];
    if (rows.every((row) => row.bucket !== 'pending')) return rows;
    if (waited >= limit) return `still running after ${Math.round(limit / 60)}m`;
    await sleep(every);
  }
}

/**
 * One request, from red to as-fixed-as-this-is-allowed-to-make-it.
 *
 * The division of labour is the same one `check` has always drawn and it is
 * the important part: this fixes the file it added and nothing else. A red
 * check that belongs to the repository is reported with its link and left
 * alone, because a stranger's failing test on a branch that only added files
 * under .github is their business.
 *
 * The one thing the first batch changed is the wording. "not ours, left
 * alone" was wrong often enough to be worth retiring: SonarCloud failed
 * AudioMuse-AI's gate *on our file*, and calling that theirs would have hidden
 * the single most useful review the batch received. When the branch adds only
 * our two files, a third-party scanner failing is at least as likely to be
 * judging them as anything else, and it says so.
 */
async function followUp(repo: string, me: string, pr: string): Promise<void> {
  const rows = await settle(repo, pr);
  if (typeof rows === 'string') {
    console.log(`· ${repo} — ${rows}; \`tcfeed check --fix\` later`);
    return;
  }

  const bad = rows.filter((row) => row.bucket === 'fail');
  if (bad.length === 0) {
    console.log(`· ${repo} — ${rows.length === 0 ? 'no checks' : `${rows.length} green`}`);
    return;
  }

  for (const row of bad) {
    console.log(`· ${repo} — ${row.name} failed`);
    if (row.link) console.log(`    ${row.link}`);
  }
  console.log('    the branch adds only .github/workflows/threatcrush-scan.yml and');
  console.log('    .github/scripts/threatcrush-to-sarif.py, so a scanner failing here may');
  console.log('    well be judging those — read it before assuming it is theirs.');

  // The remedy table, unchanged and still deliberately short. It patches only
  // what it recognises and prints the rest for a person, which is the line
  // this must not cross on somebody else's review.
  await checkOne(repo, me, true);
}

/* ------------------------------------------------------------------ *
 * check — did the request break, and was it us
 * ------------------------------------------------------------------ */

/** The file we add. A run from any other file is somebody else's CI. */
const OUR_WORKFLOW = '.github/workflows/threatcrush-scan.yml';

/**
 * What a failure has to look like before this touches anything.
 *
 * The table is short on purpose and it is allowed to stay short. Every entry
 * is a failure mode that has been reproduced and whose fix has been checked;
 * anything that does not match is printed for a person to read rather than
 * guessed at. Pushing a speculative fix onto a stranger's pull request is
 * worse than leaving it red — red is honest, and a wrong commit on somebody
 * else's review is a second thing for them to work out.
 */
interface Remedy {
  id: string;
  when: RegExp;
  /** null means the file is fine and the run was unlucky: re-run, do not patch. */
  patch: ((workflow: string) => string) | null;
  why: string;
}

const REMEDIES: Remedy[] = [
  {
    id: 'registry',
    // The install step already retries three times. Reaching this means the
    // registry was unreachable for the whole window, which says nothing about
    // the workflow and everything about npm that minute.
    when: /ThreatCrush install failed after 3 attempts|npm error code (ETIMEDOUT|ECONNRESET|EAI_AGAIN|E429|E503)/i,
    patch: null,
    why: 'the npm registry was unreachable, not a fault in the workflow',
  },
  {
    id: 'runner',
    when: /The (runner has received a shutdown signal|operation was canceled)|Received request to deprovision/i,
    patch: null,
    why: 'the runner went away mid-job',
  },
  {
    id: 'native-build',
    // better-sqlite3 falls through to a source build wherever no prebuilt
    // matches the runtime, and then wants a toolchain the runner may not have.
    // --ignore-scripts skips a native build only the daemon needs, which is
    // what this project's own install instructions have always said.
    when: /gyp ERR!|node-gyp rebuild|not found: make|prebuild-install\b.*\bfail/i,
    patch: (workflow) =>
      workflow.replace(
        /npm install -g "([^"]+)"/,
        'npm install -g --ignore-scripts "$1"'
      ),
    why: 'better-sqlite3 tried a source build; --ignore-scripts skips one only the daemon needs',
  },
];

interface RunRow {
  id: number;
  name: string;
  path: string;
  status: string;
  conclusion: string | null;
}

/**
 * One repository's standing. Ours and theirs are separated by the workflow
 * *path*, not by the job name — a job called "security" in somebody's ci.yml
 * is theirs, and a red one there is not an invitation to open their editor.
 */
async function checkOne(repo: string, me: string, fix: boolean): Promise<void> {
  const open = JSON.parse(
    await gh(['api', `repos/${repo}/pulls?state=open&head=${me}:${PR_BRANCH}&per_page=1`])
  ) as { number: number; head: { sha: string }; mergeable_state?: string }[];

  if (open.length === 0) {
    console.log(`· ${repo} — no open request`);
    return;
  }

  const pr = open[0];
  const state = await gh([
    'api',
    `repos/${repo}/pulls/${pr.number}`,
    '--jq',
    '.mergeable_state',
  ]).catch(() => 'unknown');

  // Both sides of the same commit. Pushing the branch to the fork sets off
  // whatever the upstream repository runs on push — on the fork, under our
  // account — and those runs never appear against the upstream repository at
  // all. Looking only upstream misses exactly the red X that gets noticed,
  // because the fork is where the notification mail comes from.
  const fork = `${me}/${repo.split('/')[1]}`;
  const runs: RunRow[] = [];
  for (const where of [repo, fork]) {
    const said = await gh([
      'api',
      `repos/${where}/actions/runs?head_sha=${pr.head.sha}&per_page=100`,
    ]).catch(() => '{"workflow_runs":[]}');
    runs.push(...((JSON.parse(said) as { workflow_runs: RunRow[] }).workflow_runs ?? []));
  }

  const ours = runs.filter((entry) => entry.path === OUR_WORKFLOW);
  const theirs = runs.filter((entry) => entry.path !== OUR_WORKFLOW);
  const badTheirs = theirs.filter((entry) => entry.conclusion === 'failure');
  const badOurs = ours.filter((entry) => entry.conclusion === 'failure');
  // `action_required` arrives as a conclusion on a completed run, not as a
  // status. Read as a status it never matches, and a request waiting on a
  // maintainer reads as one with nothing to say.
  const waiting = ours.filter(
    (entry) => entry.status === 'action_required' || entry.conclusion === 'action_required'
  );

  console.log(`· ${repo} #${pr.number} — ${state}`);

  if (waiting.length > 0) {
    // Not a failure and not fixable from this side. GitHub withholds workflow
    // runs on a first-time contributor's pull request until a maintainer
    // approves them, which is the usual reason a request sits with no checks.
    console.log('    ours: waiting for the maintainer to approve the run');
  }

  for (const entry of badTheirs) {
    // Reported and never touched — but no longer called "not ours". The
    // commit adds two files and nothing else, so their suite failing on it is
    // usually their suite meeting a commit, and occasionally their scanner
    // reading our workflow and being right about it. SonarCloud failed
    // AudioMuse-AI's gate on our file with a C security rating; both findings
    // were fair, and a line that said "not ours" would have buried the most
    // useful review the first batch got.
    console.log(`    theirs: ${entry.name} failed — their check, worth reading before dismissing`);
  }

  if (badOurs.length === 0) {
    if (waiting.length === 0 && badTheirs.length === 0)
      console.log(`    ours: ${ours.map((e) => e.conclusion ?? e.status).join(', ') || 'no runs'}`);
    return;
  }

  for (const entry of badOurs) {
    const log = await run('gh', ['run', 'view', String(entry.id), '--repo', repo, '--log-failed'])
      .then(({ stdout }) => stdout)
      .catch(() => '');

    const remedy = REMEDIES.find((candidate) => candidate.when.test(log));
    if (!remedy) {
      console.log(`    ours: ${entry.name} failed, and this does not recognise why.`);
      console.log(`      gh run view ${entry.id} --repo ${repo} --log-failed`);
      for (const line of log.trimEnd().split('\n').slice(-4)) console.log(`      | ${line.slice(-160)}`);
      continue;
    }

    console.log(`    ours: ${remedy.id} — ${remedy.why}`);
    if (!fix) {
      console.log('      --fix would ' + (remedy.patch ? 'push a fix' : 're-run it'));
      continue;
    }

    if (!remedy.patch) {
      await run('gh', ['run', 'rerun', String(entry.id), '--repo', repo, '--failed']);
      console.log('      re-run');
      continue;
    }

    console.log(`      ${await pushFix(repo, me, remedy)}`);
  }
}

/**
 * Apply a remedy to the branch the request is already on. Pushing to it
 * updates the open pull request, which is the whole point: a second request
 * for the same thing is the spam the first one promised not to be.
 */
async function pushFix(repo: string, me: string, remedy: Remedy): Promise<string> {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tcfeed-fix-'));
  const src = path.join(tmp, 'src');
  const git = (args: string[]) => run('git', ['-C', src, ...args]);
  const fork = `${me}/${repo.split('/')[1]}`;

  try {
    await run('git', [
      'clone',
      '--quiet',
      '--depth',
      '1',
      '--branch',
      PR_BRANCH,
      `https://github.com/${fork}.git`,
      src,
    ]);

    const full = path.join(src, OUR_WORKFLOW);
    const before = fs.readFileSync(full, 'utf8');
    const after = remedy.patch!(before);
    // A remedy that matched the log but changes nothing in the file has not
    // understood the failure. Say so rather than pushing an empty commit.
    if (after === before) return `${remedy.id} matched the log but changed nothing — left alone`;

    fs.writeFileSync(full, after);
    await git(['add', OUR_WORKFLOW]);
    await git(['commit', '--quiet', '-m', `ci: ${remedy.why}`]);
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
    return 'pushed';
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Bring one open request's files up to the current pack.
 *
 * The pack is read live from sh1pt precisely so a corrected workflow reaches
 * repositories, and until this existed that was only true of requests not yet
 * sent. Thirty-three went out carrying `npm install -g "…@latest"`, the pack
 * was fixed an hour later, and all twenty-four still open kept shipping the
 * defective version to anyone who looked.
 *
 * Three separate reviewers found it independently, which is as clear a signal
 * as this is going to get: SonarCloud failed a quality gate on it
 * (githubactions:S8543), CodeRabbit scored a request Moderate for "an unpinned
 * scanner with access to a write-scoped job", and Haven's maintainer declined
 * on exactly that ground —
 *
 *   whoever can publish that package can run code in this repository's CI
 *   from that point on, forever, without a further PR
 *
 * — while noting the project hash-pins thirteen tarballs in its ffmpeg stack
 * alone. That is not a maintainer being difficult; that is a maintainer
 * applying their own published bar to us and finding us under it.
 *
 * Written against the contents API rather than a clone because the open
 * requests include seastar and lightning, and cloning a kernel-sized
 * repository to rewrite two files under .github is minutes of transfer for a
 * diff that fits on a screen. It also cannot accidentally carry anything else
 * along with it, which on somebody else's review is the more important half.
 */
async function refreshOne(repo: string, me: string, spec: string): Promise<string> {
  const open = JSON.parse(
    await gh(['api', `repos/${repo}/pulls?state=open&head=${me}:${PR_BRANCH}&per_page=1`])
  ) as { number: number }[];
  if (open.length === 0) return 'no open request';

  const pack = packDir();
  const inputs = packInputs(spec);
  const want = [
    {
      path: OUR_WORKFLOW,
      content: render(fs.readFileSync(path.join(pack, 'workflow.yml'), 'utf8'), inputs),
    },
    {
      path: '.github/scripts/threatcrush-to-sarif.py',
      content: fs.readFileSync(path.join(pack, 'threatcrush-to-sarif.py'), 'utf8'),
    },
  ];

  const fork = `${me}/${repo.split('/')[1]}`;
  const changed: string[] = [];

  for (const file of want) {
    const said = await gh([
      'api',
      `repos/${fork}/contents/${file.path}?ref=${PR_BRANCH}`,
      '--jq',
      '{sha: .sha, content: .content}',
    ]).catch(() => '');
    if (!said) return `cannot read ${file.path} on ${fork}`;

    const have = JSON.parse(said) as { sha: string; content: string };
    // The API wraps base64 at 60 columns; decoding without stripping the
    // newlines yields a string that never equals the file and rewrites both
    // files on every run.
    const current = Buffer.from(have.content.replace(/\n/g, ''), 'base64').toString('utf8');
    if (current === file.content) continue;

    await gh([
      'api',
      '-X',
      'PUT',
      `repos/${fork}/contents/${file.path}`,
      '-f',
      `message=ci: update the ThreatCrush scan workflow to the reviewed pack`,
      '-f',
      `content=${Buffer.from(file.content, 'utf8').toString('base64')}`,
      '-f',
      `sha=${have.sha}`,
      '-f',
      `branch=${PR_BRANCH}`,
    ]);
    changed.push(path.basename(file.path));
  }

  return changed.length === 0 ? 'already current' : `updated ${changed.join(', ')}`;
}

/**
 * The subcommand. With no arguments it reads every repository this has an open
 * request on, which is the list it is entitled to act on and no wider.
 */
async function checkCommand(argv: string[]): Promise<number> {
  const fix = argv.includes('--fix');
  const refresh = argv.includes('--refresh');
  const named = argv.filter((arg) => !arg.startsWith('-'));

  for (const tool of ['git', 'gh']) {
    if (!(await usable(tool, ['--version']))) {
      console.error(`tcfeed: missing ${tool}`);
      return 1;
    }
  }

  const me = await gh(['api', 'user', '--jq', '.login']).catch(() => '');
  if (!me) {
    console.error('tcfeed: gh is not logged in');
    return 1;
  }

  let repos = named;
  if (repos.length === 0) {
    // Found by searching for the requests themselves rather than by keeping a
    // list on disk. A file would drift the first time one was opened by hand.
    const found = JSON.parse(
      await gh([
        'api',
        `search/issues?q=${encodeURIComponent(`is:pr is:open author:${me} head:${PR_BRANCH}`)}&per_page=100`,
        '--jq',
        '[.items[].repository_url]',
      ])
    ) as string[];
    repos = [...new Set(found.map((url) => url.replace(/^.*\/repos\//, '')))].sort();
  }

  if (repos.length === 0) {
    console.log('tcfeed: no open requests');
    return 0;
  }

  // Resolved once, and only when it is going to be used: --refresh is the only
  // path that renders the pack, and `check` should keep working on a machine
  // that has no sh1pt checkout beside it.
  const spec = refresh ? await resolveSpec() : '';

  for (const repo of repos) {
    if (refresh) {
      try {
        console.log(`· ${repo} — ${await refreshOne(repo, me, spec)}`);
      } catch (error) {
        console.log(`· ${repo} — could not refresh: ${why(error)}`);
      }
      continue;
    }

    try {
      await checkOne(repo, me, fix);
    } catch (error) {
      console.log(`· ${repo} — could not check: ${why(error)}`);
    }
  }

  if (!fix) {
    console.log('');
    console.log('Nothing was changed. `tcfeed check --fix` acts on the failures marked ours;');
    console.log('failures marked theirs are never touched, whatever --fix says.');
  }
  return 0;
}

/**
 * Worst first: a critical outranks any number of highs, and highs break the
 * tie. One ordering, used by the table and by `pr --all`, so "the top ones"
 * means the same thing whether it is read off the screen or off the file — two
 * rankings that drift is the sort of bug nobody notices until the wrong
 * repository has already been written to.
 */
const ranked = (rows: Row[]): Row[] => {
  const worst = (row: Row) => row.critical * 1000 + row.high;
  return [...rows].sort((a, b) => worst(b) - worst(a));
};

function table(rows: Row[]): void {
  const columns = [9, 6, 8, 7, 7];
  const line = (cells: string[]) =>
    cells.map((cell, i) => (i < columns.length ? cell.padEnd(columns[i]) : cell)).join(' ');

  console.log('');
  console.log(line(['CRITICAL', 'HIGH', 'MEDIUM', 'TOTAL', 'STARS', 'REPO']));

  for (const row of ranked(rows)) {
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
    console.log('       tcfeed pr owner/name [...] [--dry-run]  ask, then offer the workflow');
    console.log('       tcfeed pr --all [--dry-run]             the last scan, worst first');
    console.log('         --no-issue   skip the question, open the request alone');
    console.log('         --no-follow  skip waiting on their checks afterwards');
    console.log('       tcfeed check [owner/name ...] [--fix]   how are the open requests doing');
    console.log('         --refresh    bring open requests up to the current pack');
    console.log('       tcfeed rss [list|add|remove] [url ...]   feeds to read alongside reddit');
    return 0;
  }

  if (argument === 'pr') return prCommand(process.argv.slice(3), cache);
  if (argument === 'check') return checkCommand(process.argv.slice(3));
  if (argument === 'rss') return rssCommand(process.argv.slice(3));

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

  // Two sources, and either one is allowed to fail.
  //
  // Reddit refuses this address often enough that making it fatal meant a run
  // produced nothing on an afternoon when the other source was answering
  // perfectly. Whichever source came back is scanned; only losing both is an
  // error, and a source that failed says so rather than looking empty.
  const fromReddit: string[] = [];
  const fromSearch: string[] = [];
  const broke: string[] = [];

  try {
    fromReddit.push(...reposIn(await readFeed(sub, limit, cache)));
  } catch (error) {
    broke.push(`reddit: ${(error as Error).message}`);
  }

  const query = process.env.TCFEED_GH_QUERY ?? 'stars:1000..10000';
  const searchWanted = num('TCFEED_GH', 25);
  if (searchWanted > 0 && query) {
    try {
      fromSearch.push(...(await searchRepos(query, searchWanted)));
    } catch (error) {
      broke.push(`github search: ${(error as Error).message}`);
    }
  }

  const feeds = readFeeds();
  const fromRss: string[] = [];
  if (feeds.length > 0) {
    const { body, broke: dead } = await readRss(feeds, num('TCFEED_RSS_PAUSE', 1));
    fromRss.push(...reposIn(body));
    // Named individually rather than counted. "3 feeds failed" is a number to
    // shrug at; the URL is something to go and fix.
    for (const why of dead) broke.push(`rss ${why}`);
  }

  for (const why of broke) console.log(`tcfeed: ${why}`);

  if (fromReddit.length === 0 && fromSearch.length === 0 && fromRss.length === 0) {
    // Empty is only an error if something that was asked also broke. Every
    // source quiet and none of them failing is a slow day, not a fault.
    if (broke.length > 0) {
      console.error('tcfeed: no source answered');
      return 1;
    }
    console.log('tcfeed: no source mentioned a repository');
    return 0;
  }

  // Deduplicated across sources, because a repository trending on reddit is
  // exactly the kind that also turns up in a search sorted by recent activity,
  // or in the week's newsletter, and cloning it twice in one run is the one
  // thing worth avoiding here.
  const seenInThisRun = new Set<string>();
  const repos = [...fromReddit, ...fromSearch, ...fromRss].filter((repo) => {
    if (seenInThisRun.has(repo)) return false;
    seenInThisRun.add(repo);
    return true;
  });

  // "in both" no longer holds with three sources, and a source contributing
  // nothing is worth seeing — a feed that has stopped mentioning repositories
  // looks identical to one nobody added until its zero is on the screen.
  const overlap = fromReddit.length + fromSearch.length + fromRss.length - repos.length;
  const parts = [
    `${fromReddit.length} from r/${sub}`,
    `${fromSearch.length} from search (${query})`,
  ];
  if (feeds.length > 0)
    parts.push(`${fromRss.length} from ${feeds.length} feed${feeds.length === 1 ? '' : 's'}`);
  console.log(
    `tcfeed: ${repos.length} to consider — ${parts.join(', ')}` +
      (overlap > 0 ? `, ${overlap} seen more than once` : '')
  );

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

  // The table, worst first, for `pr --all` to read. Written rather than
  // recomputed because --all must mean the run whose output is on the screen:
  // a second scan between looking and acting would otherwise change what "all"
  // referred to without anybody saying so.
  //
  // Only scanned repositories reach `rows` — the archived, the gone and the
  // too-big were skipped further up and were never candidates — so the file
  // cannot offer --all something the scan itself declined to clone.
  fs.writeFileSync(
    path.join(cache, 'lastrun'),
    `${ranked(rows)
      .map((row) => row.repo)
      .join('\n')}\n`
  );

  console.log('');
  console.log(`reports: ${path.join(cache, 'reports')}`);
  console.log('Read one before acting on it. Most of these are false positives, and a');
  console.log('pull request about a finding is something you write, not something this sends.');
  console.log('');
  console.log('To ask about the scan workflow in one of them instead:');
  console.log('  tcfeed pr owner/name --dry-run   # the issue and the diff, opening nothing');
  console.log('  tcfeed pr owner/name             # issue, request, then watch their checks');
  console.log(`  tcfeed pr --all --dry-run        # the ${rows.length} above, worst first`);
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
