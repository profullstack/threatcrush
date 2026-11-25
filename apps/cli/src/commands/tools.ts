/**
 * Free utility tools inspired by GRC's classic free security tools (independent
 * re-implementations, not affiliated with GRC):
 *   haystack    — password search-space / brute-force-time calculator
 *   genpass     — cryptographically strong random strings
 *   fingerprint — a site's TLS certificate fingerprint (MITM check)
 *   dns-bench   — benchmark public DNS resolvers by speed and reliability
 */

import chalk from 'chalk';
import ora from 'ora';
import { banner, logger } from '../core/logger.js';
import { analyzePassword } from '../tools/haystack.js';
import { CHARSETS, generatePassword, perfectSet, type CharsetName } from '../tools/genpass.js';
import { getFingerprint, fingerprintsMatch } from '../tools/fingerprint.js';
import { PUBLIC_RESOLVERS, benchmarkDns } from '../tools/dnsbench.js';

// ── haystack ──────────────────────────────────────────────────────────────
export async function haystackCommand(password: string, opts: { json?: boolean }): Promise<void> {
  if (!password) { logger.error('Usage: threatcrush haystack <password>'); return; }
  const r = analyzePassword(password);
  if (opts.json) { console.log(JSON.stringify(r, null, 2)); return; }
  banner();
  console.log(chalk.green.bold('  Password Haystacks — brute-force search space'));
  console.log(chalk.gray("  Independent re-implementation of GRC's Haystacks idea; not affiliated."));
  console.log(chalk.gray('  Worst-case EXHAUSTIVE search only — not a guess-ability/dictionary score.'));
  console.log();
  const sets = [r.charset.lower && 'a-z', r.charset.upper && 'A-Z', r.charset.digits && '0-9', r.charset.symbols && 'symbols', r.charset.other && 'other'].filter(Boolean).join(', ');
  console.log(`  Length:        ${chalk.white(r.length)}`);
  console.log(`  Character set: ${chalk.white(sets)} (${r.poolSize} symbols)`);
  console.log(`  Entropy:       ${chalk.white(r.entropyBits)} bits`);
  console.log(`  Search space:  ${chalk.white(r.searchSpace)} combinations`);
  console.log();
  console.log('  Time to exhaustively search:');
  console.log(`    Online (1k/s):            ${chalk.cyan(r.times.online)}`);
  console.log(`    Offline fast (100B/s):    ${chalk.yellow(r.times.offlineFast)}`);
  console.log(`    Massive array (100T/s):   ${chalk.red(r.times.massiveArray)}`);
  console.log();
}

// ── genpass ───────────────────────────────────────────────────────────────
export async function genpassCommand(opts: { length?: string; charset?: string; count?: string; json?: boolean }): Promise<void> {
  if (!opts.length && !opts.charset) {
    const set = perfectSet();
    if (opts.json) { console.log(JSON.stringify(set, null, 2)); return; }
    banner();
    console.log(chalk.green.bold('  Perfect Passwords — fresh high-entropy random strings'));
    console.log(chalk.gray("  Independent re-implementation of GRC's Perfect Passwords idea; not affiliated."));
    console.log(chalk.gray('  Generated locally with your OS CSPRNG. Never sent anywhere.'));
    console.log();
    console.log(`  64 hex:        ${chalk.white(set.hex64)}`);
    console.log(`  63 alnum:      ${chalk.white(set.alnum63)}`);
    console.log(`  63 ASCII:      ${chalk.white(set.ascii63)}`);
    console.log();
    return;
  }
  const length = opts.length ? Number(opts.length) : 32;
  const name = (opts.charset ?? 'ascii') as CharsetName;
  const alphabet = CHARSETS[name] ?? opts.charset ?? CHARSETS.ascii;
  const count = opts.count ? Number(opts.count) : 1;
  const out = Array.from({ length: count }, () => generatePassword(length, alphabet));
  console.log(opts.json ? JSON.stringify(out, null, 2) : out.join('\n'));
}

// ── fingerprint ───────────────────────────────────────────────────────────
export async function fingerprintCommand(host: string, opts: { port?: string; compare?: string; json?: boolean }): Promise<void> {
  if (!host) { logger.error('Usage: threatcrush fingerprint <host> [--port 443] [--compare <sha256>]'); return; }
  const cleanHost = host.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const port = opts.port ? Number(opts.port) : 443;
  if (!opts.json) banner();
  const spinner = opts.json ? null : ora({ text: `Reading TLS certificate from ${cleanHost}:${port}...`, color: 'green' }).start();
  try {
    const fp = await getFingerprint(cleanHost, port);
    spinner?.stop();
    if (opts.json) {
      const match = opts.compare ? fingerprintsMatch(fp.sha256, opts.compare) : undefined;
      console.log(JSON.stringify({ ...fp, ...(match === undefined ? {} : { match }) }, null, 2));
      return;
    }
    console.log(chalk.green.bold(`  TLS fingerprint — ${cleanHost}:${port}`));
    console.log(chalk.gray("  Independent re-implementation of GRC's Fingerprints idea; not affiliated."));
    console.log();
    console.log(`  SHA-256:  ${chalk.white(fp.sha256)}`);
    console.log(`  SHA-1:    ${chalk.gray(fp.sha1)}`);
    console.log(`  Subject:  ${chalk.white(fp.subjectCN ?? '?')}`);
    console.log(`  Issuer:   ${chalk.white(fp.issuer ?? '?')}`);
    console.log(`  Valid:    ${chalk.gray(`${fp.validFrom ?? '?'} → ${fp.validTo ?? '?'}`)}`);
    if (opts.compare) {
      const ok = fingerprintsMatch(fp.sha256, opts.compare);
      console.log();
      console.log(ok
        ? `  ${chalk.green.bold('✓ MATCH')} — the fingerprint you supplied matches what we see.`
        : `  ${chalk.red.bold('✗ MISMATCH')} — differs from what you supplied. Your TLS may be intercepted (proxy/AV/MITM).`);
    } else {
      console.log();
      console.log(chalk.gray('  Compare this SHA-256 to what your browser shows for the same site.'));
      console.log(chalk.gray('  A different fingerprint in your browser means something is intercepting your TLS.'));
    }
    console.log();
  } catch (err) {
    spinner?.stop();
    logger.error(`Could not read certificate: ${(err as Error).message}`);
  }
}

// ── dns-bench ─────────────────────────────────────────────────────────────
export async function dnsbenchCommand(opts: { names?: string; timeout?: string; json?: boolean }): Promise<void> {
  const names = opts.names?.split(',').map((s) => s.trim()).filter(Boolean);
  if (!opts.json) banner();
  const spinner = opts.json ? null : ora({ text: 'Benchmarking public DNS resolvers...', color: 'green' }).start();
  const results = await benchmarkDns(PUBLIC_RESOLVERS, { names, timeoutMs: opts.timeout ? Number(opts.timeout) : 2000 });
  spinner?.stop();
  if (opts.json) { console.log(JSON.stringify(results, null, 2)); return; }
  console.log(chalk.green.bold('  DNS Benchmark — fastest resolver from this machine'));
  console.log(chalk.gray("  Independent re-implementation of GRC's DNS Benchmark idea; not affiliated."));
  console.log(chalk.gray('  Measured from THIS machine right now; results vary by network and location.'));
  console.log();
  console.log(`  ${'Resolver'.padEnd(12)} ${'IP'.padEnd(16)} ${'avg'.padStart(8)} ${'min'.padStart(7)} ${'max'.padStart(7)}  reliability`);
  for (const r of results) {
    const avg = r.avgMs === null ? '—' : `${r.avgMs}ms`;
    const min = r.minMs === null ? '—' : `${r.minMs}`;
    const max = r.maxMs === null ? '—' : `${r.maxMs}`;
    const color = r.avgMs === null ? chalk.red : r.reliabilityPct < 100 ? chalk.yellow : chalk.white;
    console.log(`  ${color(r.name.padEnd(12))} ${chalk.gray(r.ip.padEnd(16))} ${avg.padStart(8)} ${min.padStart(7)} ${max.padStart(7)}  ${r.reliabilityPct}%`);
  }
  console.log();
}
