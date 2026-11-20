import { isIP } from 'node:net';
import { connectionsFrom, parseSs, refuseIp, sshdSessionPids } from './ip.js';
import {
  auditFlags, countFailedAttempts, keyRows, lastUsedByFingerprint, lockoutCheck, parseAcceptedLogins,
  publicRow, replacementHelp, sessionKeyFingerprint,
} from './keys.js';
import { checkOrdering, effectiveValues, lockdownDropins, lockdownMismatches, LOCKDOWN_FILE, ROOT_LOCALHOST_FILE } from './sshd.js';
import type { Action, ActionOp, Report, RespondRequest, Snapshot } from './types.js';

export interface PlanContext {
  host: string;
  via: Report['via'];
  /** Extra never-ban entries (the daemon config's protected list). */
  allowlist?: string[];
  now?: number;
}

export const DEFAULT_BAN_TTL = '30d';

/**
 * Decide everything for one host from its snapshot. Pure: no I/O, so the
 * same plan comes out whether the snapshot was read here or over ssh.
 */
export function planRespond(snap: Snapshot, req: RespondRequest, ctx: PlanContext): Report {
  const root = snap.uid === 0;
  const report: Report = {
    host: ctx.host,
    hostname: snap.hostname,
    sub: req.sub,
    apply: req.apply,
    root,
    via: ctx.via,
    actions: [],
    warnings: [...snap.errors],
    needsRoot: [],
  };
  let n = 0;
  const add = (op: ActionOp, summary: string, refused?: string) => {
    report.actions.push({ id: `a${++n}`, kind: op.op, summary, status: refused ? 'refused' : 'planned', ...(refused ? { message: refused } : {}), op });
  };

  const logins = parseAcceptedLogins(snap.journal, new Date(ctx.now ?? Date.now()));

  if (req.sub === 'ip') {
    const ownClient = snap.sshConnection?.split(/\s+/)[0] ?? null;
    const conns = parseSs(snap.ss);
    report.connections = [];
    report.logins = [];
    report.failedAttempts = countFailedAttempts(snap.journal, req.ips ?? []);
    for (const ip of req.ips ?? []) {
      const refusal = refuseIp(ip, { gateways: snap.gateways, allowlist: ctx.allowlist, ownClient });
      const ttl = req.ttl ?? DEFAULT_BAN_TTL;
      if (refusal) {
        add({ op: 'ban', ip, ttl }, `ban ${ip}`, refusal);
        continue;
      }
      const mine = connectionsFrom(conns, ip);
      report.connections.push(...mine.map((c) => ({ ...c, ip })));
      report.logins.push(...logins.filter((l) => l.ip === ip).map(({ port: _port, ...l }) => l));
      // Ban first, so a killed session cannot simply reconnect.
      add({ op: 'ban', ip, ttl }, `ban ${ip} for ${ttl}`);
      const pids = sshdSessionPids(mine);
      if (pids.length) add({ op: 'kill', pids }, `kill sshd session process(es) ${pids.join(', ')} of ${ip}`);
      if (mine.length) add({ op: 'ss-kill', ip }, `close ${mine.length} established connection(s) from ${ip} (ss -K)`);
    }
    report.logins.sort((a, b) => b.at - a.at);
  }

  if (req.sub === 'key') {
    const fps = new Set(req.fingerprints ?? []);
    const rows = keyRows(snap.keyFiles, lastUsedByFingerprint(logins));
    const matches = rows.filter((r) => r.fingerprint !== null && fps.has(r.fingerprint));
    report.keys = matches.map((r) => ({
      ...publicRow(r),
      flags: r.parsed.command !== null
        ? ['deploy key (command=): restricted keys are still stolen keys; removing it like any other']
        : [],
    }));
    const found = new Set(matches.map((r) => r.fingerprint));
    const missing = [...fps].filter((fp) => !found.has(fp));
    if (missing.length) report.warnings.push(`not authorized anywhere on this host: ${missing.join(', ')}`);
    if (!root) report.warnings.push("not root: other users' homes were not readable, so this list is incomplete");

    const sessionFp = sessionKeyFingerprint(snap.sshConnection, logins);
    const verdict = lockoutCheck(rows, fps, snap.user, sessionFp);
    const lockoutRefusal = verdict.lockout && !req.allowLockout
      ? `lockout guard: ${verdict.reason}. Install a replacement first, or pass --allow-lockout`
      : undefined;
    if (lockoutRefusal) report.replacementHelp = replacementHelp(snap.user || 'root', snap.hostname || ctx.host);
    if (verdict.sessionKeyRemoved && !verdict.lockout) {
      report.warnings.push(`the key this session logged in with (${sessionFp}) is being removed; ${snap.user} keeps ${verdict.remaining} other key(s): make sure you hold one`);
    }
    if (verdict.othersEmptied.length) {
      report.warnings.push(`these accounts will have no SSH keys left: ${verdict.othersEmptied.join(', ')}`);
    }

    const byFile = new Map<string, typeof matches>();
    for (const m of matches) byFile.set(m.file, [...(byFile.get(m.file) ?? []), m]);
    for (const [file, ms] of byFile) {
      const live = ms[0].live;
      const fpsHere = [...new Set(ms.map((m) => m.fingerprint))].join(', ');
      if (live) {
        add({ op: 'strip-key', file, blobs: [...new Set(ms.map((m) => m.blob))] },
          `remove ${ms.length} line(s) from ${file} (${ms[0].user ?? '?'}): ${fpsHere}`, lockoutRefusal);
      } else {
        // A stale copy grants nothing, so the lockout guard does not apply.
        add({ op: 'rm', file }, `delete stale copy ${file} (holds ${fpsHere}; sshd does not read it)`);
      }
    }
    report.privateKeys = snap.privateKeys.filter((p) => p.fingerprint !== null && fps.has(p.fingerprint));
    for (const p of report.privateKeys) add({ op: 'shred', file: p.path }, `shred private key ${p.path} (${p.fingerprint})`);
  }

  if (req.sub === 'sshd') {
    const local = effectiveValues(snap.sshd.effectiveLocal, ['permitrootlogin']);
    report.effectiveBefore = {
      ...effectiveValues(snap.sshd.effectiveRemote),
      ...(local.permitrootlogin ? { 'permitrootlogin@127.0.0.1': local.permitrootlogin } : {}),
    };
    if (!snap.sshd.binary) report.warnings.push('sshd not found on this host');
    else if (!snap.sshd.effectiveRemote) report.warnings.push('`sshd -T` gave nothing (it needs root): effective values unknown');
    if (!req.lockdown) {
      for (const m of lockdownMismatches(report.effectiveBefore, null)) report.warnings.push(m);
    } else {
      const allowRoot = req.allowRootLocalhost === true;
      const others: Record<string, string> = {};
      for (const [k, v] of Object.entries(snap.sshd.dropins)) if (k !== LOCKDOWN_FILE && k !== ROOT_LOCALHOST_FILE) others[k] = v;
      const ordering = checkOrdering({ mainConfig: snap.sshd.mainConfig, dropinDir: snap.sshd.dropinDir, existing: others, allowRootLocalhost: allowRoot });
      report.warnings.push(...ordering.warnings);
      if (!allowRoot && snap.sshd.existing[ROOT_LOCALHOST_FILE] !== null) {
        report.warnings.push(`${snap.sshd.dropinDir}/${ROOT_LOCALHOST_FILE} exists from an earlier run and still lets root in from localhost; delete it if that is not wanted`);
      }
      const files = lockdownDropins({ allowRootLocalhost: allowRoot });
      const refusal = !snap.sshd.binary ? 'sshd not found' : ordering.blockers.length ? ordering.blockers.join('; ') : undefined;
      add({
        op: 'sshd-lockdown',
        dir: snap.sshd.dropinDir,
        files,
        restore: files.map((f) => ({ name: f.name, content: snap.sshd.existing[f.name] ?? null })),
      }, `write ${files.map((f) => f.name).join(' + ')}, validate with sshd -t, reload only if valid`, refusal);
    }
  }

  if (req.sub === 'keys-audit') {
    const rows = keyRows(snap.keyFiles, lastUsedByFingerprint(logins));
    report.keys = auditFlags(rows, { now: ctx.now ?? Date.now(), unusedDays: 30, journalAvailable: snap.journal.length > 0 });
    report.staleFiles = snap.keyFiles.filter((f) => !f.live).map((f) => f.path);
    if (!root) report.warnings.push("not root: other users' homes were not readable, so this list is incomplete");
  }

  // Without root nothing is applied; say exactly what would need it.
  if (!root) {
    for (const a of report.actions) {
      if (a.status !== 'planned') continue;
      report.needsRoot.push(a.summary);
      if (req.apply) {
        a.status = 'needs-root';
        a.message = 'run as root (sudo) to apply';
      }
    }
  }
  return report;
}

/**
 * Fold the apply script's results (and the daemon's ban replies) back into
 * the report, and check lockdown's effective values.
 */
export function recordResults(
  report: Report,
  results: Map<string, { ok: boolean; message: string }>,
  effective: { remote: string; local: string } | null,
): void {
  for (const a of report.actions) {
    const r = results.get(a.id);
    if (!r) {
      if (a.status === 'planned') {
        a.status = 'failed';
        a.message = 'no result came back (the apply script stopped early)';
      }
      continue;
    }
    a.status = r.ok ? 'done' : 'failed';
    a.message = r.message;
    if (a.kind === 'sshd-lockdown' && r.ok && effective) {
      const local = effectiveValues(effective.local, ['permitrootlogin']);
      report.effectiveAfter = {
        ...effectiveValues(effective.remote),
        ...(local.permitrootlogin ? { 'permitrootlogin@127.0.0.1': local.permitrootlogin } : {}),
      };
      const op = a.op as Extract<ActionOp, { op: 'sshd-lockdown' }>;
      const allowRoot = op.files.some((f) => f.name === ROOT_LOCALHOST_FILE);
      const bad = lockdownMismatches(effectiveValues(effective.remote), allowRoot ? local : null);
      if (bad.length) {
        a.status = 'failed';
        a.message = `${r.message}; but not effective: ${bad.join('; ')}`;
      }
    }
  }
}

/** Any action that did not do what was asked, or a host error. */
export function reportFailed(report: Report): boolean {
  return Boolean(report.error) || report.actions.some((a: Action) => a.status === 'failed' || a.status === 'refused' || (report.apply && a.status === 'needs-root'));
}

export function isValidIp(ip: string): boolean {
  return isIP(ip) !== 0;
}
