/**
 * The two POSIX shell scripts `respond` runs on a host, here or over ssh:
 *
 *   gather  reads what the analysis needs and prints tagged, base64 records;
 *   apply   performs concrete actions decided in TypeScript and prints results.
 *
 * Every decision (what to kill, which key lines go, whether a lockout looms)
 * is made in TypeScript from the gathered snapshot, so the local and remote
 * paths share one analysis. The scripts only read and execute. Private key
 * material never leaves its host: the gather script reports fingerprints.
 * Arguments are validated before they are embedded, and quoted anyway.
 */
import { parsePasswd } from '../host-scan/parsers.js';
import { DROPIN_DIR, LOCKDOWN_FILE, ROOT_LOCALHOST_FILE } from './sshd.js';
import type { Action, ActionOp, RespondRequest, Snapshot } from './types.js';

/** Single-quote for POSIX sh. */
export function sq(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

const b64 = (s: string) => Buffer.from(s, 'utf-8').toString('base64');
const unb64 = (s: string | undefined) => (s ? Buffer.from(s, 'base64').toString('utf-8') : '');

const PRELUDE = `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH
export PATH LC_ALL=C
e() { printf '%s' "$1" | base64 | tr -d '\\n'; }
ef() { base64 < "$1" 2>/dev/null | tr -d '\\n'; }
SSHD=$(command -v sshd 2>/dev/null)
[ -z "$SSHD" ] && [ -x /usr/sbin/sshd ] && SSHD=/usr/sbin/sshd
# Tests point this at a stand-in sshd.
[ -n "\${TC_RESPOND_SSHD:-}" ] && SSHD=$TC_RESPOND_SSHD
`;

export const DEFAULT_SEARCH_ROOTS = ['/root', '/home'];

function ipPattern(ips: string[]): string {
  return `from (${ips.map((ip) => ip.replace(/[.]/g, '\\.')).join('|')})( |$)`;
}

export function gatherScript(req: RespondRequest): string {
  const wantKeys = req.sub === 'key' || req.sub === 'keys-audit';
  const pattern = req.sub === 'ip' ? ipPattern(req.ips ?? []) : 'Accepted ';
  const roots = (req.searchRoots?.length ? req.searchRoots : DEFAULT_SEARCH_ROOTS).map(sq).join(' ');
  return `#!/bin/sh
# threatcrush respond: gather (${req.sub}). Read-only.
${PRELUDE}
printf 'META\\tuid\\t%s\\n' "$(id -u)"
printf 'META\\tuser\\t%s\\n' "$(e "\${SUDO_USER:-$(id -un)}")"
printf 'META\\thostname\\t%s\\n' "$(e "$(hostname 2>/dev/null || uname -n)")"
printf 'META\\tssh\\t%s\\n' "$(e "\${TC_SSH_CONNECTION:-\${SSH_CONNECTION:-}}")"
printf 'META\\tsshd\\t%s\\n' "$(e "$SSHD")"
printf 'BLOB\\tpasswd\\t%s\\n' "$(ef /etc/passwd)"
T=""
[ -n "$SSHD" ] && T=$("$SSHD" -T 2>/dev/null </dev/null)
printf 'BLOB\\tsshdT\\t%s\\n' "$(e "$T")"
printf 'BLOB\\troutes\\t%s\\n' "$(e "$( (ip -4 route show default; ip -6 route show default) 2>/dev/null)")"
${wantKeys ? keysSection(roots, req.sub === 'key') : ''}
${req.sub === 'ip' ? `printf 'BLOB\\tss\\t%s\\n' "$(e "$(ss -tnpH 2>/dev/null)")"` : ''}
${req.sub === 'sshd' ? sshdSection() : ''}
PAT=${sq(pattern)}
J=""
JA="-q --no-pager -o short-unix --since=-30d -t sshd -t sshd-session -t sshd-auth"
if command -v journalctl >/dev/null 2>&1 && [ -n "$(journalctl $JA -n 1 2>/dev/null </dev/null)" ]; then
  printf 'META\\tjournal\\t%s\\n' "$(e journalctl)"
  J=$(journalctl $JA 2>/dev/null </dev/null | grep -E "$PAT" | tail -n 20000)
elif [ -r /var/log/auth.log ] || [ -r /var/log/secure ]; then
  printf 'META\\tjournal\\t%s\\n' "$(e authlog)"
  J=$(cat /var/log/auth.log /var/log/secure 2>/dev/null | grep -E "$PAT" | tail -n 20000)
fi
printf 'BLOB\\tjournal\\t%s\\n' "$(e "$J")"
printf 'END\\n'
`;
}

function keysSection(roots: string, privateKeys: boolean): string {
  return `
set -f
SPEC=$(printf '%s\\n' "$T" | awk 'tolower($1)=="authorizedkeysfile"{ $1=""; sub(/^ +/,""); print; exit }')
[ -n "$SPEC" ] || SPEC=".ssh/authorized_keys .ssh/authorized_keys2"
while IFS=: read -r u _ _ _ _ h _; do
  [ -n "$h" ] || continue
  he=$(printf '%s' "$h" | sed 's/[|&\\\\]/\\\\&/g')
  ue=$(printf '%s' "$u" | sed 's/[|&\\\\]/\\\\&/g')
  for t in $SPEC; do
    [ "$t" = none ] && continue
    p=$(printf '%s' "$t" | sed -e "s|%h|$he|g" -e "s|%u|$ue|g" -e 's|%%|%|g')
    case "$p" in /*) ;; *) p="$h/$p" ;; esac
    [ -e "$p" ] || continue
    if [ -r "$p" ]; then printf 'AK\\t%s\\t%s\\t%s\\n' "$(e "$u")" "$(e "$p")" "$(ef "$p")"
    else printf 'ERR\\t%s\\n' "$(e "cannot read $p")"; fi
  done
done < /etc/passwd
set +f
find /root /home -xdev -maxdepth 4 -type f -name 'authorized_keys*' 2>/dev/null | while IFS= read -r p; do
  if [ -r "$p" ]; then printf 'AKX\\t%s\\t%s\\n' "$(e "$p")" "$(ef "$p")"
  else printf 'ERR\\t%s\\n' "$(e "cannot read $p")"; fi
done
${privateKeys ? `for r in ${roots}; do
  [ -d "$r" ] || continue
  find "$r" -xdev -maxdepth 8 \\( -name node_modules -o -name .git -o -name .cache -o -name .npm -o -name .pnpm-store -o -name .cargo -o -name .rustup \\) -prune -o -type f -size -65k \\( -path '*/.ssh/*' -o -name 'id_*' -o -name '*.pem' -o -name '*.key' -o -name '*_rsa' -o -name '*_ed25519' -o -name '*_ecdsa' -o -name '*deploy*' \\) ! -name '*.pub' -print 2>/dev/null
done | while IFS= read -r f; do
  head -c 128 "$f" 2>/dev/null | grep -q 'PRIVATE KEY-----' || continue
  fp=$(ssh-keygen -l -E sha256 -f "$f" 2>/dev/null </dev/null | awk '{print $2}')
  [ -z "$fp" ] && [ -f "$f.pub" ] && fp=$(ssh-keygen -l -E sha256 -f "$f.pub" 2>/dev/null </dev/null | awk '{print $2}')
  printf 'PRIV\\t%s\\t%s\\n' "$(e "$f")" "$fp"
done` : ''}
`;
}

function sshdSection(): string {
  return `
printf 'BLOB\\tsshdmain\\t%s\\n' "$(ef /etc/ssh/sshd_config)"
printf 'META\\tdropindir\\t%s\\n' "$(e ${sq(DROPIN_DIR)})"
for f in ${DROPIN_DIR}/*.conf; do
  [ -f "$f" ] || continue
  printf 'DROPIN\\t%s\\t%s\\n' "$(e "$(basename "$f")")" "$(ef "$f")"
done
if [ -n "$SSHD" ]; then
  printf 'BLOB\\teffR\\t%s\\n' "$(e "$("$SSHD" -T -C user=root,host=x,addr=1.2.3.4 2>/dev/null </dev/null)")"
  printf 'BLOB\\teffL\\t%s\\n' "$(e "$("$SSHD" -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null </dev/null)")"
fi
`;
}

/** Parse the gather script's output into a snapshot. */
export function parseGather(text: string): Snapshot {
  const meta: Record<string, string> = {};
  const blob: Record<string, string> = {};
  const live: Snapshot['keyFiles'] = [];
  const extra: Array<{ path: string; content: string }> = [];
  const privateKeys: Snapshot['privateKeys'] = [];
  const dropins: Record<string, string> = {};
  const errors: string[] = [];
  let ended = false;
  for (const line of text.split('\n')) {
    const f = line.split('\t');
    switch (f[0]) {
      case 'META': meta[f[1]] = f[1] === 'uid' ? f[2] ?? '' : unb64(f[2]); break;
      case 'BLOB': blob[f[1]] = unb64(f[2]); break;
      case 'AK': live.push({ user: unb64(f[1]), path: unb64(f[2]), live: true, content: unb64(f[3]) }); break;
      case 'AKX': extra.push({ path: unb64(f[1]), content: unb64(f[2]) }); break;
      case 'PRIV': privateKeys.push({ path: unb64(f[1]), fingerprint: f[2]?.trim() ? f[2].trim().replace(/=+$/, '') : null }); break;
      case 'DROPIN': dropins[unb64(f[1])] = unb64(f[2]); break;
      case 'ERR': errors.push(unb64(f[1])); break;
      case 'END': ended = true; break;
      default: break;
    }
  }
  if (!ended) errors.push('gather output was cut short');
  const passwd = parsePasswd(blob.passwd ?? '');

  // De-duplicate live files (two spec tokens can expand to one path) and
  // attribute every other authorized_keys* file to the home it sits in.
  const seen = new Set<string>();
  const keyFiles: Snapshot['keyFiles'] = [];
  for (const k of live) {
    if (seen.has(k.path)) continue;
    seen.add(k.path);
    keyFiles.push(k);
  }
  const homes = passwd.filter((p) => p.home && p.home !== '/').sort((a, b) => b.home.length - a.home.length);
  for (const x of extra) {
    if (seen.has(x.path)) continue;
    seen.add(x.path);
    const owner = homes.find((p) => x.path.startsWith(`${p.home.replace(/\/$/, '')}/`));
    keyFiles.push({ user: owner?.name ?? null, path: x.path, live: false, content: x.content });
  }

  const gateways: string[] = [];
  for (const l of (blob.routes ?? '').split('\n')) {
    const m = /\bvia\s+(\S+)/.exec(l);
    if (m) gateways.push(m[1]);
  }

  const existing: Record<string, string | null> = {
    [LOCKDOWN_FILE]: dropins[LOCKDOWN_FILE] ?? null,
    [ROOT_LOCALHOST_FILE]: dropins[ROOT_LOCALHOST_FILE] ?? null,
  };

  return {
    hostname: meta.hostname ?? '',
    uid: Number(meta.uid ?? NaN),
    user: meta.user ?? '',
    sshConnection: meta.ssh?.trim() ? meta.ssh.trim() : null,
    passwd,
    keyFiles,
    privateKeys,
    ss: blob.ss ?? '',
    journal: blob.journal ?? '',
    gateways,
    sshd: {
      binary: meta.sshd || null,
      dumpT: blob.sshdT ?? '',
      mainConfig: blob.sshdmain ?? '',
      dropinDir: meta.dropindir || DROPIN_DIR,
      dropins,
      existing,
      effectiveRemote: blob.effR ?? '',
      effectiveLocal: blob.effL ?? '',
    },
    errors: [...errors, ...(meta.journal ? [] : ['no sshd log found (journalctl or /var/log/auth.log): login history is empty'])],
  };
}

const FW_TABLE = 'threatcrush_respond';

function opScript(id: string, op: ActionOp): string {
  const ok = `printf 'RESULT\\t%s\\tok\\t%s\\n' ${sq(id)}`;
  const fail = `printf 'RESULT\\t%s\\tfail\\t%s\\n' ${sq(id)}`;
  switch (op.op) {
    case 'kill':
      return `(
  killed=""; skipped=""
  for p in ${op.pids.map((p) => String(Math.trunc(p))).join(' ')}; do
    c=$(cat /proc/$p/comm 2>/dev/null)
    case "$c" in
      sshd|sshd-session|sshd-auth) kill -TERM "$p" 2>/dev/null && killed="$killed $p" || skipped="$skipped $p" ;;
      *) skipped="$skipped $p($c)" ;;
    esac
  done
  ${ok} "$(e "killed:$killed\${skipped:+ skipped:$skipped}")"
)`;
    case 'ss-kill': {
      const dst = op.ip.includes(':') ? `[${op.ip}]` : op.ip;
      return `(
  ss -K dst ${sq(dst)} >/dev/null 2>&1
  left=$(ss -tnH state established dst ${sq(dst)} 2>/dev/null | grep -c .)
  if [ "\${left:-0}" -eq 0 ]; then ${ok} "$(e "no established connections left")"
  else ${fail} "$(e "$left connection(s) still open (kernel without CONFIG_INET_DIAG_DESTROY?)")"; fi
)`;
    }
    case 'ban': {
      const fam = op.ip.includes(':') ? 'ip6' : 'ip';
      const ipt = op.ip.includes(':') ? 'ip6tables' : 'iptables';
      return `(
  if command -v nft >/dev/null 2>&1; then
    nft list table inet ${FW_TABLE} >/dev/null 2>&1 || { nft add table inet ${FW_TABLE} && nft add chain inet ${FW_TABLE} input '{ type filter hook input priority -2; policy accept; }'; }
    if nft add rule inet ${FW_TABLE} input ${fam} saddr ${sq(op.ip)} drop 2>/dev/null; then ${ok} "$(e "nft: dropped in table inet ${FW_TABLE} (no expiry; remove with: nft delete table inet ${FW_TABLE})")"
    else ${fail} "$(e "nft add rule failed")"; fi
  elif command -v ${ipt} >/dev/null 2>&1; then
    if ${ipt} -I INPUT -s ${sq(op.ip)} -j DROP 2>/dev/null; then ${ok} "$(e "${ipt}: DROP inserted at top of INPUT (no expiry)")"
    else ${fail} "$(e "${ipt} -I failed")"; fi
  else ${fail} "$(e "no nft or ${ipt} on this host")"; fi
)`;
    }
    case 'strip-key':
      return `(
  f=${sq(op.file)}
  if [ -L "$f" ]; then ${fail} "$(e "refusing: $f is a symlink")"; exit 0; fi
  if [ ! -f "$f" ]; then ${fail} "$(e "$f is gone")"; exit 0; fi
  tmp=$(mktemp) || { ${fail} "$(e "mktemp failed")"; exit 0; }
  blobs=${sq(op.blobs.join(' '))}
  awk -v blobs="$blobs" 'BEGIN { n = split(blobs, B, " "); for (i = 1; i <= n; i++) S[B[i]] = 1 } { keep = 1; for (i = 1; i <= NF; i++) if ($i in S) keep = 0; if (keep) print }' "$f" > "$tmp" && cat "$tmp" > "$f"
  rm -f "$tmp"
  left=$(awk -v blobs="$blobs" 'BEGIN { n = split(blobs, B, " "); for (i = 1; i <= n; i++) S[B[i]] = 1 } { for (i = 1; i <= NF; i++) if ($i in S) c++ } END { print c + 0 }' "$f")
  if [ "$left" -eq 0 ]; then ${ok} "$(e "removed")"; else ${fail} "$(e "$left key(s) still present")"; fi
)`;
    case 'rm':
      return `(
  f=${sq(op.file)}
  if [ -L "$f" ]; then ${fail} "$(e "refusing: $f is a symlink")"; exit 0; fi
  rm -f -- "$f" && [ ! -e "$f" ] && ${ok} "$(e "deleted")" || ${fail} "$(e "rm failed")"
)`;
    case 'shred':
      return `(
  f=${sq(op.file)}
  if [ -L "$f" ]; then ${fail} "$(e "refusing: $f is a symlink")"; exit 0; fi
  if command -v shred >/dev/null 2>&1; then shred -u -z -- "$f" 2>/dev/null; else rm -f -- "$f"; fi
  [ ! -e "$f" ] && ${ok} "$(e "shredded")" || ${fail} "$(e "still present")"
)`;
    case 'sshd-lockdown': {
      const writes = op.files.map((f) => `printf '%s' ${sq(b64(f.content))} | base64 -d > "$d/.${f.name}.tmp" && chmod 644 "$d/.${f.name}.tmp" && mv -f "$d/.${f.name}.tmp" "$d/${f.name}"`).join('\n  ');
      const restores = op.restore.map((r) => (r.content === null
        ? `rm -f "$d/${r.name}"`
        : `printf '%s' ${sq(b64(r.content))} | base64 -d > "$d/${r.name}"`)).join('\n    ');
      return `(
  d=${sq(op.dir)}
  if [ -z "$SSHD" ]; then ${fail} "$(e "sshd binary not found")"; exit 0; fi
  mkdir -p "$d"
  ${writes}
  err=$("$SSHD" -t 2>&1 </dev/null)
  if [ $? -ne 0 ]; then
    ${restores}
    ${fail} "$(e "sshd -t rejected the config, files restored, sshd NOT reloaded: $err")"
    exit 0
  fi
  printf 'EFFECTIVE\\tremote\\t%s\\n' "$(e "$("$SSHD" -T -C user=root,host=x,addr=1.2.3.4 2>/dev/null </dev/null)")"
  printf 'EFFECTIVE\\tlocal\\t%s\\n' "$(e "$("$SSHD" -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null </dev/null)")"
  if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then ${ok} "$(e "sshd -t passed; sshd reloaded")"
  elif [ -f /run/sshd.pid ] && kill -HUP "$(cat /run/sshd.pid)" 2>/dev/null; then ${ok} "$(e "sshd -t passed; sent SIGHUP to sshd")"
  elif systemctl is-active ssh.socket >/dev/null 2>&1; then ${ok} "$(e "sshd -t passed; socket-activated sshd reads the new config on the next connection")"
  else ${fail} "$(e "config valid and written, but could not reload sshd")"; fi
)`;
    }
  }
}

export function applyScript(actions: Action[]): string {
  return `#!/bin/sh
# threatcrush respond: apply ${actions.length} action(s).
${PRELUDE}
${actions.map((a) => `# ${a.summary.replace(/\n/g, ' ')}\n${opScript(a.id, a.op)}`).join('\n')}
printf 'END\\n'
`;
}

export interface ApplyResults {
  results: Map<string, { ok: boolean; message: string }>;
  effective: { remote: string; local: string };
  complete: boolean;
}

export function parseApply(text: string): ApplyResults {
  const results = new Map<string, { ok: boolean; message: string }>();
  const effective = { remote: '', local: '' };
  let complete = false;
  for (const line of text.split('\n')) {
    const f = line.split('\t');
    if (f[0] === 'RESULT') results.set(f[1], { ok: f[2] === 'ok', message: unb64(f[3]) });
    else if (f[0] === 'EFFECTIVE' && (f[1] === 'remote' || f[1] === 'local')) effective[f[1]] = unb64(f[2]);
    else if (f[0] === 'END') complete = true;
  }
  return { results, effective, complete };
}
