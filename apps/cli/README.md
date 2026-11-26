<p align="center">
  <a href="https://threatcrush.com"><img src="https://threatcrush.com/logo.svg" alt="ThreatCrush" width="120" /></a>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@profullstack/threatcrush"><img src="https://img.shields.io/npm/v/@profullstack/threatcrush?color=00ff41&style=flat-square&label=version" alt="npm version" /></a>
  <a href="https://www.npmjs.com/package/@profullstack/threatcrush"><img src="https://img.shields.io/npm/dm/@profullstack/threatcrush?color=00ff41&style=flat-square&label=downloads" alt="downloads" /></a>
  <a href="https://github.com/profullstack/threatcrush"><img src="https://img.shields.io/github/license/profullstack/threatcrush?color=00ff41&style=flat-square" alt="license" /></a>
  <a href="https://github.com/profullstack/threatcrush"><img src="https://img.shields.io/github/stars/profullstack/threatcrush?color=00ff41&style=flat-square" alt="stars" /></a>
  <a href="https://github.com/profullstack/threatcrush"><img src="https://img.shields.io/badge/github-profullstack%2Fthreatcrush-00ff41?style=flat-square&logo=github" alt="github" /></a>
  <img src="https://img.shields.io/node/v/@profullstack/threatcrush?color=00ff41&style=flat-square" alt="node" />
  <img src="https://img.shields.io/badge/platform-linux-00ff41?style=flat-square" alt="platform" />
</p>

<h1 align="center">
  <br>
  ThreatCrush
  <br>
</h1>

<h4 align="center">All-in-one security agent — monitor, detect, scan, and protect servers in real-time.</h4>

<p align="center">
  <img src="https://threatcrush.com/images/gallery-cli.png" alt="ThreatCrush CLI" width="48%" />
  <img src="https://threatcrush.com/images/gallery-tui.png" alt="ThreatCrush TUI" width="48%" />
</p>
<p align="center">
  <img src="https://threatcrush.com/images/gallery-desktop.png" alt="ThreatCrush Desktop" width="60%" />
</p>
<p align="center">
  <img src="https://threatcrush.com/images/gallery-mobile.png" alt="ThreatCrush Mobile" width="30%" />
</p>

<p align="center">
  <a href="https://threatcrush.com">Website</a> •
  <a href="#install">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#features">Features</a> •
  <a href="#modules">Modules</a> •
  <a href="https://github.com/profullstack/threatcrush">GitHub</a>
</p>

---

ThreatCrush is a security daemon that runs on your server, **reading your logs and watching inbound connections** for live attacks. It checks every nginx request against 96 OWASP CRS rules (paranoia level 1) + 4 ThreatCrush rules with CRS anomaly scoring, runs 25 detection rules over auth, web, network and Postgres (Docker container log) events, auto-bans attackers, scans your codebase, spot-checks your URLs, and alerts you in real-time.

```
$ threatcrush monitor

2026-09-25 12:03:41 [INFO]    Starting foreground monitor...
2026-09-25 12:03:41 [INFO]    Monitoring 3 log source(s):
  ● ssh-guard      → /var/log/auth.log
  ● log-watcher    → /var/log/nginx/access.log
  ● log-watcher    → /var/log/syslog

  Press Ctrl+C to stop

2026-09-25 12:03:45 [CRITICAL] [log-watcher]  Attack detected [SQLI]: GET /api/users?id=1%20UNION%20SELECT%20password%20FROM%20users (185.43.21.8)
2026-09-25 12:03:46 [CRITICAL] [log-watcher]  Attack detected [PATH_TRAVERSAL]: GET /../../etc/passwd (185.43.21.8)
2026-09-25 12:03:47 [HIGH]     [ssh-guard]    Failed SSH login for root from 91.232.105.3 (91.232.105.3)
2026-09-25 12:03:48 [HIGH]     [ssh-guard]    Invalid SSH user attempt: admin123 from 103.77.88.99 (103.77.88.99)
2026-09-25 12:03:52 [LOW]      [log-watcher]  Client error 404: GET /wp-login.php (203.0.113.9)
```

`monitor` tails your logs in the foreground. The daemon (`threatcrush start`) adds the connection poller, DNS monitor, journald, the rule engine and auto-ban.

## Install

**Preferred install:**

```bash
curl -fsSL https://threatcrush.com/install.sh | sh
```

The CLI needs **Node.js 22.6 or newer**. The installer detects whether the machine is a server or desktop, uses your existing package manager when available, and on a machine with no Node.js sets up Node.js LTS with `mise`, adding mise's shims to `~/.profile` so new login shells find `threatcrush`. If it finds an older Node.js it stops without installing anything and tells you how to upgrade.

- **Linux server** → installs the CLI
- **Desktop (Linux, macOS, Windows)** → installs the CLI and points you to the desktop app, a separate download from [GitHub Releases](https://github.com/profullstack/threatcrush/releases/latest). The desktop app talks to a ThreatCrush daemon on the same machine; log monitoring and firewall bans need Linux.

After install, the supported lifecycle commands are:

```bash
threatcrush update   # upgrades the installed bundle
threatcrush remove   # removes the installed bundle
```

Manual package-manager installs still work (Node.js 22.6+):

```bash
npm i -g @profullstack/threatcrush
pnpm add -g @profullstack/threatcrush
yarn global add @profullstack/threatcrush
bun add -g @profullstack/threatcrush
```

## Usage

```bash
threatcrush              # Get started
threatcrush monitor      # Watch nginx, auth & syslog for attacks (foreground)
threatcrush tui          # Interactive dashboard (htop for security)
threatcrush action-center # Fleet-wide detections, host health and queued actions (login required)
threatcrush scan ./src   # Scan code for vulnerabilities & secrets
threatcrush scan . --format sarif --output out.sarif --fail-on critical,high
threatcrush scan . --verify    # AI second-read of every finding; drops confident false positives
sudo threatcrush scan --host   # Rootkit / host integrity scan of this machine (alias: host-scan)
sudo threatcrush respond ...   # Incident response: kill sessions, ban, pull stolen keys, lock sshd (dry run unless --apply)
threatcrush pentest URL  # Quick web security checks against a URL
threatcrush explore ./src # Blackboard state-space vulnerability research over code you own (docs/explore.md)
threatcrush init         # Auto-detect services, generate config
threatcrush status       # Show daemon status & loaded modules
threatcrush modules      # Manage security modules
threatcrush store        # Browse the module marketplace
threatcrush update       # Upgrade the CLI using the supported path
```

### AI-verified scan (`--verify`)

`threatcrush scan --verify` hands each rule hit, with about 20 lines of context,
to a model that must say whether it is real and quote the attacker-controlled
expression that reaches the sink. Confident false positives (test fixtures,
constant input, a match inside a regex or string, a value from your own API)
are dismissed from the report and from `--fail-on`; JSON output still lists
them under `dismissed`. A "confirmed" verdict that cites no source visible in
the code is downgraded to uncertain.

Opt-in, because code leaves the machine: by default masked excerpts go to a
[c0mpute](https://c0mpute.com) peer node (end-to-end encrypted to that worker).
High-entropy strings are masked first, so found secrets are described, never
sent. To keep everything local, point it at any OpenAI-compatible server:

```bash
threatcrush scan . --verify --ai-url http://localhost:11434/v1 --ai-model qwen2.5-coder:7b   # Ollama
C0MPUTE_API_KEY=ik_live_... threatcrush scan . --verify --format json   # c0mpute account key
```

See [docs/scan-verify.md](docs/scan-verify.md) for flags, models and output.

### Host integrity / rootkit scan

`threatcrush scan --host` (alias `--localhost`, or `threatcrush host-scan`) checks
the machine it runs on instead of a code tree. It only reads: it never installs,
deletes or fixes anything.

```bash
sudo threatcrush scan --host                        # every check, text report
sudo threatcrush host-scan --json > host-scan.json  # machine-readable
sudo threatcrush host-scan --since 3d --deny-keys ./stolen-keys.txt
sudo threatcrush host-scan --checks ssh-keys,persistence,uid0-accounts
sudo threatcrush host-scan --skip-checks rkhunter,chkrootkit,suid-sgid   # the slow ones
sudo threatcrush host-scan --checks network-exposure,secrets-on-disk     # what an intruder reaches and harvests
sudo threatcrush host-scan --checks secrets-on-disk --deep --secrets-timeout 600
```

| Check | Fails when | Warns when |
|---|---|---|
| `package-integrity` | `dpkg --verify` / `rpm -Va` says a binary in `/bin` `/sbin` `/usr/bin` `/usr/sbin`, a PAM module (`lib*/security`) or a shared object differs from its package | other `/usr/lib` files differ, packaged binaries are missing (config files are ignored) |
| `rkhunter` | a warning names a rootkit, trojan or backdoor | any other rkhunter warning; rkhunter is not installed (install command printed) |
| `chkrootkit` | a command is `INFECTED` and its binary does **not** match its package | `INFECTED` but the binary verifies against its package (e.g. rust-coreutils false positives); unpackaged suspicious files; not installed |
| `hidden-processes` | `unhide quick` finds a hidden PID, or (without unhide) a PID answers `stat()` but is missing from `/proc` or from `ps` | |
| `kernel-modules` | a module has an initstate in `/sys/module` but is missing from `/proc/modules`, or a loaded module is not from `/lib/modules/$(uname -r)` | |
| `ld-preload` | `/etc/ld.so.preload` exists | |
| `suspicious-exe` | | a process runs a `(deleted)` executable or one under `/tmp`, `/dev/shm`, `/var/tmp` (deleted after a package upgrade is common, so this is a warning) |
| `ssh-keys` | a key in any `authorized_keys` (root, every account home, `/home/*`, honouring `AuthorizedKeysFile`) matches `--deny-keys`; the same key authorizes root and another account; an unrestricted key has a dated CI/diagnostic-style comment (`ci-diag-YYYYMMDD`); an unrestricted key sits in a file modified inside `--since` | a key has no `command=` and no `from=`; the same key appears more than once; a restricted key has a dated CI/diagnostic-style comment |
| `sshd-config` | | `sshd -T` shows `PermitRootLogin` other than `no`, or `PasswordAuthentication yes` |
| `docker-containers` | | a running container is `--privileged`, `--pid=host`, or bind-mounts `/` or the Docker socket |
| `docker-group` | | anyone is in the `docker` group (docker group == root) |
| `persistence` | | a file under `/etc/cron*`, `/var/spool/cron`, `/etc/systemd/system`, `~/.config/systemd`, `/etc/pam.d`, `/etc/ssh/sshd_config.d`, `/etc/sudoers.d`, `/etc/profile.d`, `authorized_keys` and similar changed inside `--since` (default `7d`) |
| `uid0-accounts` | an account other than `root` has uid 0 | |
| `suid-sgid` | | a setuid/setgid file on the root filesystem is not owned by any package (container storage and snaps are skipped) |
| `network-exposure` | a datastore / admin port (see below) listens on a public address (`0.0.0.0`, `[::]`, a public IP) and no firewall rule blocks it | the `DOCKER-USER` chain is empty while Docker publishes ports on `0.0.0.0`; `DOCKER-USER` has live rules but nothing restores them at boot; a `DOCKER-USER` rule matches `--dport <host port>` for a mapping whose container port differs (it never fires); a sensitive port is explicitly allowed from anywhere in ufw; not root (firewall unreadable) |
| `secrets-on-disk` | a key, token or credential file is readable by other users (world-readable with every parent directory traversable, or group-readable by a shared group); `--deep`: a private key is in a git repository's history | each plaintext secret found (inventory: path, type, owner, mode, size, age; never the value) |

#### `network-exposure`

Sensitive ports: postgres 5432 / pgbouncer 6432 / 6543, mysql 3306, mongodb
27017, redis 6379, elasticsearch 9200 / 9300, clickhouse 8123 / 9000, couchdb
5984, memcached 11211, neo4j 7687 / 7474, influxdb 8086, rabbitmq 5672 / 15672,
kafka 9092, etcd 2379, Docker API 2375 / 2376, kubelet 10250, cups 631.

Listeners come from `ss -tlnpH` (or `/proc/net/tcp{,6}` without `ss`); Docker
port bindings from `docker ps`. A Docker mapping counts as sensitive when its
host port **or its container port** is on the list, so `-p 5601:5432` is postgres.

Docker-published ports never pass through ufw or the `INPUT` chain: only the
`DOCKER-USER` chain can block them, and it sees packets **after** DNAT. So for
`-p 6543:6432` the check looks for a `DROP`/`REJECT` matching `--dport 6432`
(the container port) or `-m conntrack --ctorigdstport 6543` (the host port),
walking the chain first-match (source-limited `ACCEPT`s are reported as an
allowlist, source-limited `DROP`s do not count as a block). Host processes are
judged by ufw when active, else the `INPUT` chain policy and rules, plus any
native nftables `hook input` chains. IPv6 bindings are only considered when the
host has a global IPv6 address.

Rules added with `iptables -I DOCKER-USER ...` live only in the kernel. The
check warns unless something restores them at boot: a file under
`/etc/systemd/system`, `/usr/local/{s,}bin`, `/etc/network/if-*.d`, `/etc/docker`,
a script a unit's `ExecStart` runs, `/etc/ufw/*.rules`, or `-A DOCKER-USER`
lines in `/etc/iptables/rules.v4`.

The check makes no outbound connections. To confirm from outside, from another
machine run `nc -vz -w3 <public-ip> 5432` (or `nmap -Pn -p 5432,6432,6543,3306,6379,27017 <public-ip>`)
for each port it lists; "Connection refused" or a timeout is what you want.

#### `secrets-on-disk`

Walks `/root` and `/home/*` (7 levels deep, never following symlinks; skips
`node_modules`, `.git`, `.cache`, package-manager caches, build output and
files over 1 MB) and `/etc` (4 levels; only world-readable findings are
reported there). It opens only files whose name suggests a secret and looks for:

- unencrypted private keys: `id_*`, `*.pem`, `*.key`, anything in `~/.ssh`
  (OpenSSH keys with cipher `none`, PKCS#1/SEC1 without `Proc-Type: 4,ENCRYPTED`,
  unencrypted PKCS#8; passphrase-protected keys are not reported)
- `~/.config/gh/hosts.yml` `oauth_token`, `.npmrc` `_authToken`, `.pypirc`
  passwords, `.git-credentials`, `.netrc`, `.vault-token`, Terraform Cloud tokens
- `~/.docker/config.json` registries with stored `auth`, `~/.aws/credentials`,
  `~/.config/gcloud` credentials, `~/.kube/config` with embedded tokens or keys
- `.env`, `.env.*`, `*.env` and backups such as `app.env.bak.<date>` (not `.example` / `.sample` / `.template`): the
  count and **names** of variables that look like keys, tokens, secrets or
  passwords, or URLs with an embedded password
- JSON identity / service-account files holding a private key, secret or token
- plaintext password-manager exports (Bitwarden / LastPass / 1Password /
  browser CSV headers, unencrypted Bitwarden JSON, `.1pux` / `.1pif`)

Paths under `test/`, `fixtures/`, `examples/` and similar are labelled
`[test fixture path]` and never fail. `--deep` also runs
`git log --all --pickaxe-regex -S '-----BEGIN [A-Z ]*PRIVATE KEY-----'` in each
repository found (as the repository's owner when run as root, so a hostile repo
config cannot run anything as root); worktrees sharing a leaked commit are
reported once. The whole check is time-boxed by `--secrets-timeout <seconds>`
(default 120); what it found before the budget ran out is reported and the check
is marked `[partial]`.

The exit code is 1 when any check fails, 2 on bad arguments, 0 otherwise.
`--json` prints `{ host, kernel, root, summary: {pass, warn, fail, skip}, skipped, checks: [{ id, status, reason, items, partial, install }] }`.
`--deep` and `--secrets-timeout` only affect `secrets-on-disk`.
`--deny-keys` takes one entry per line: a full public key line, a bare base64
key blob, or a `SHA256:` fingerprint.

Run it as root. Without root, `rkhunter`, `chkrootkit` and `sshd-config` are
skipped and listed as such, and checks that could only read part of the system
(other users' keys, other users' processes) are marked `[partial]`.

### GitHub Actions workflow rules

`threatcrush scan <path>` parses every `.github/workflows/*.yml` (and Forgejo/Gitea
`.forgejo/workflows`, `.gitea/workflows`, or any YAML with top-level `on:` and
`jobs:`) as YAML and reads each `run:` script together with the workflow around
it: which inputs are free text, which `env:` variables hold input or secrets, and
what `ssh`, `sh -c` and `eval` do with their arguments. Findings carry the exact
`file:line` inside multi-line `run: |` blocks, and a fix hint (`Fix:` in the text
report, in the rule help in SARIF and in `fix` in JSON).

| Rule | Severity | Flags |
|---|---|---|
| `gha-expression-injection` | high | `${{ inputs.* }}`, `${{ github.event.inputs.* }}`, issue/PR/discussion `title`/`body`, `pull_request.head.ref`, `comment.body`, `github.head_ref`, commit messages, `client_payload` and other attacker-controllable contexts pasted directly into a `run:` script or an `actions/github-script` body. Fix: pass through `env:` and use `"$VAR"`. |
| `gha-input-in-remote-shell` | critical | Such a value, or an env var assigned from one (step, job or workflow `env:`, an in-script assignment, or a `$GITHUB_ENV` export from an earlier step), expanded into a string another shell parses: the `ssh` remote command line (including the `"VAR='$VAR' bash -s"` pattern), a here-string, pipe or unquoted heredoc into a remote shell, `bash -c`/`sh -c`, `eval`, or an `appleboy/ssh-action` `script:`. Env keeps it data locally only. Reported at medium when the variable is checked with `[[ … =~ … ]]` or `case` in the same step. |
| `gha-dispatch-remote-exec` | critical | A `workflow_dispatch`/`repository_dispatch` workflow that runs a free-text input as the whole remote command: `ssh host "$CMD"`, `ssh host bash -s <<<"$CMD"`, `echo "$CMD" \| ssh host bash`. |
| `gha-ssh-key-secret` | medium | A step writes a secret to `~/.ssh/id_*` (or uses an ssh-key action) and the job runs `ssh`/`scp`/`rsync`. Whether the server-side key is limited with `restrict,command=…` cannot be verified from the repository; the finding asks you to check. |
| `gha-pull-request-target-checkout` | high | A `pull_request_target` workflow whose `actions/checkout` `ref`/`repository` is the PR head (`github.event.pull_request.head.sha`/`ref`, `github.head_ref`). |
| `gha-secrets-to-log` | medium | `echo`/`printf` of `${{ secrets.* }}` or of a variable holding one to the log (not to a file or a `--password-stdin` consumer), a secret piped through `base64`/`openssl enc`/`gpg --armor` and printed (masking bypass), `toJSON(secrets)`, and `set -x` in a step that uses secrets. |

Not flagged: inputs used only in `with:` of other actions or in `if:` conditions,
`boolean`/`choice`/`number` inputs, env vars used by the local shell as `"$VAR"`,
single-quoted ssh commands (`ssh host 'echo $X'` does not expand locally), and
input piped as data to a non-shell remote command
(`printf '%s\n' "$IPS" | ssh host 'xargs -n1 threatcrush unblock --'`). Step
outputs and reusable-workflow inputs are not followed. Suppress a reviewed line
with `# threatcrush-disable-next-line <rule-id>`.

### Deploy-path rules

`threatcrush scan <path>` also reads whole files for the relationships that
turn write access to a repository into a shell on a host. Each finding links
(`Ref:` in the text report, `helpUri` in SARIF) to the matching write-up in
[`attack-vectors/`](../../attack-vectors/README.md).

| Rule | Severity | Flags |
|---|---|---|
| `compose-host-root-mount` | critical | A `compose*.yml` / `docker-compose*.yml` service bind-mounts `/`, `/root`, `/etc`, `/boot`, `/home` or a home directory, or any `.ssh` directory (short or long volume syntax, read-only included). |
| `compose-docker-socket` | high | A service mounts `/var/run/docker.sock`. |
| `compose-privileged` | high | `privileged: true`, or `cap_add` of `SYS_ADMIN` / `ALL`. |
| `compose-root-user` | medium | `user: 0`, `0:0` or `root`. |
| `deploy-compose-from-synced-repo` | high | In a shell script, workflow or `SSH_ORIGINAL_COMMAND` wrapper: `docker compose -f <path>` run on a host where the path is under a directory the same file uploads to with `rsync`/`scp`, under a checkout updated with `git pull` on the host, or in a forced-command allowlist that also accepts `rsync --server`. |
| `deploy-remote-exec-uploaded-script` | high | A script uploaded with `rsync`/`scp`/`appleboy/scp-action` then run over ssh (`bash /srv/app/deploy.sh`, `cd /srv/app && ./deploy.sh`, an `appleboy/ssh-action` `script:`), and `ssh host bash -s < scripts/deploy.sh`. |
| `github-app-installation-idor` | high | Source code: a handler reads `installation_id` from the query string and writes it to a database without calling `GET /user/installations` (or a helper in the same file that does). |
| `authorized-keys-unrestricted` | medium | An `authorized_keys` file in the tree has a key with no `from=`, `command=` or `restrict`. |
| `authorized-keys-suspicious-comment` | high | A key comment that is a temporary role word plus a date (`ci-diag-20261120`, `ops-recovery-20261027`), with no `user@host`. |
| `authorized-keys-sftp-unjailed` | medium | A key forced to `internal-sftp` / `sftp-server`: limits what it runs, not what it reads. |
| `sshd-sftp-without-chroot` | medium | An `sshd_config` (or `sshd_config.d/*.conf`) `ForceCommand internal-sftp` with no `ChrootDirectory`. |

Credential rules added alongside them: `secret-github-app-private-key`
(a PEM key with a body in a file that also names `GITHUB_APP_ID`/`APP_ID`),
`secret-resend-key`, `secret-supabase-service-role` (a JWT whose payload role
is `service_role`; the anon key is not flagged) and
`secret-generic-high-entropy` (an unquoted `*_SECRET=`, `*_PRIVATE_KEY=`,
`*_TOKEN=`, `*_API_KEY=` or `*_PASSWORD=` value that is long, mixed-class and
high-entropy). `secret-private-key` now also matches `ENCRYPTED PRIVATE KEY`.
`secret-committed-env-file` (critical) reports a dotenv file by name (`.env`,
`.env.*`, `*.env`, `*.env.*`, so `.env.bak-2026-07-28` and `deploy.env.bak-1`;
never `.env.example`/`.sample`/`.template`/`.dist`/`.defaults`/`.schema`) once,
on its first secret-named key (`*KEY*`, `*SECRET*`, `*TOKEN*`, `*PASS*`,
`*PEPPER*`, `*PRIVATE*`, `*CREDENTIAL*`, `*DSN*`, `*AUTH*`) whose value is not a
placeholder, with the count of such keys and never a value. `secret-resend-key`
also accepts a `re_` key without the inner underscore when the body reads as key
material. Env backups (`*.env.bak*`, `.env.old`, ...) are read for secrets and,
when none match, reported by name as critical; `id_rsa`/`id_ed25519`/`id_ecdsa`/`id_dsa`
are reported by name. Excerpts are always masked.

### Incident response: `threatcrush respond`

Containment for a box, or a fleet, after stolen SSH keys or a stolen password.
It is a **dry run by default**: it shows what it found and what it would do.
`--apply` acts. Every action is reported, in text or `--json`, with its status
(`planned`, `done`, `failed`, `refused`, `needs-root`); the exit code is 1 when
anything failed or was refused.

| Subcommand | What it does |
|---|---|
| `respond ip <ip...>` | Lists established connections and recent sshd logins/failures from the address; with `--apply` bans it (through `threatcrushd`, else a direct `nft`/`iptables` drop), then kills its per-connection `sshd-session` processes and closes its sockets with `ss -K`. Refuses private/loopback/tailnet ranges, Cloudflare and public resolvers, the gateway, the daemon's protected list and the address of your own session. `--ttl` sets the ban (default `30d`). |
| `respond key <SHA256:fp \| key-file...>` | Finds the key in **every** `authorized_keys*` file under `/root` and `/home/*` and every `AuthorizedKeysFile` (a non-root glob silently misses other users' homes, so run it as root), shows user, file, line and restrictions, and with `--apply` removes those lines, deletes stale copies (`authorized_keys.bak`, `.old`, ...) holding it, and shreds private-key files whose public half matches. `command=` (deploy) keys are removed like any other: a restricted key is still a stolen key. Nothing is backed up; the removed fingerprints are printed. |
| `respond sshd [--lockdown]` | Shows the effective `PermitRootLogin`, `PasswordAuthentication` and `KbdInteractiveAuthentication` (`sshd -T -C user=root,host=x,addr=1.2.3.4`). `--lockdown` writes `00-0-threatcrush-lockdown.conf` (all three `no`) and, only with `--allow-root-localhost`, `99-threatcrush-root-localhost.conf` (`Match Address 127.0.0.1,::1` then `PermitRootLogin prohibit-password`), validates with `sshd -t`, restores the old files and does **not** reload if that fails, then shows the values before and after. |
| `respond keys-audit` | Every authorized key on the box with user, file, fingerprint, comment, restrictions and last use (from the sshd journal), flagging unrestricted keys, the same key on several accounts, keys unused for 30 days, stale copies, and deploy keys (`command=`): treat those as secrets and rotate them if CI secrets may have leaked. |

Two guards come from the 2026-11-20 incident:

- **Lockout guard.** `respond key` refuses to remove a key when it would leave
  the invoking user (`SUDO_USER`, or the ssh login user on a remote host) with
  no key that gives a shell, and says so when the key is the one this very
  session logged in with. `command=` and `restrict` keys do not count as a way
  back in. It prints how to install and test a replacement first;
  `--allow-lockout` overrides it when you have console access.
- **Drop-in ordering.** sshd keeps the **first** value it reads, and a `Match`
  block swallows every directive after it. So the global settings go in a file
  that sorts first and the `Match` in one that sorts last. `--lockdown` refuses
  to write when `sshd_config` does not include `sshd_config.d`, when a file read
  earlier sets a different value, or when another drop-in sorts after the
  `Match` file.

`--hosts <file|list>` runs any subcommand on remote hosts over ssh (a file with
one host per line, or `dev1,dev2`), 3 at a time, and prints one report per host
plus a summary. A host with `threatcrush respond` installed runs
`sudo -n threatcrush respond ... --json` itself; any other host gets the same
read-only gather script streamed over ssh's stdin, the same analysis runs here,
and with `--apply` a second script performs exactly the planned actions. Key
targets travel as fingerprints only; private keys never leave their host and
nothing secret is put on a command line. `sudo` must work without a password
(`sudo -n`); otherwise the host is audited read-only.

Without root nothing is changed: the run is read-only and lists the actions that need root.

Incident runbook (stolen key `SHA256:AbC...`, attacker at `203.0.113.7`):

```bash
# 0. What is out there? Run read-only across the fleet first.
threatcrush respond keys-audit --hosts fleet.txt
threatcrush respond ip 203.0.113.7 --hosts fleet.txt

# 1. Cut the attacker off everywhere: ban, then kill live sessions.
threatcrush respond ip 203.0.113.7 --hosts fleet.txt --apply

# 2. Install and TEST your replacement key on every host before removing anything.
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_new
for h in $(cat fleet.txt); do ssh-copy-id -i ~/.ssh/id_ed25519_new.pub "$h"; done

# 3. Pull the stolen key (dry run first: read the lockout guard's verdict).
threatcrush respond key SHA256:AbC... --hosts fleet.txt
threatcrush respond key SHA256:AbC... --hosts fleet.txt --apply

# 4. No root and no passwords over ssh; validated before reload.
threatcrush respond sshd --lockdown --hosts fleet.txt --apply

# 5. Re-audit, and rotate every deploy key it flags.
threatcrush respond keys-audit --hosts fleet.txt --json > audit.json
```

### CIS evidence report export

Export the current `harden` findings as Markdown, JSON, or PDF:

```bash
threatcrush harden --report cis --format md --no-upload
threatcrush harden --report cis --format json --no-upload
threatcrush harden --report cis --format pdf --output ./cis-evidence.pdf --no-upload
```

The report is **evidence for an auditor, not certification**; that disclaimer
is in every format. It carries the timestamp, host, OS, the current CIS edition
for that OS, and each `harden` check's result, observed evidence and CIS mapping.

**Where the CIS ids come from.** Every id, title and level is copied from a
[ComplianceAsCode](https://github.com/ComplianceAsCode/content) control file at
the pinned release tag `v0.1.82`, never guessed. A check is mapped only when a
CaC rule under the control tests the same setting the check reads. Each mapping
records the profile, benchmark edition, CaC tag, file, git blob SHA and rule id.
The catalog lives in `packages/scan/src/cis/crosswalk.ts`, and
`CIS_VERIFY_ONLINE=1 pnpm --filter @threatcrush/scan exec vitest run cis-crosswalk`
re-checks it against the pinned files.

| Pinned profile (CaC file) | Edition it implements | Current CIS edition |
|---|---|---|
| Ubuntu 24.04 (`cis_ubuntu2404.yml`) | v1.0.0 | v2.0.0 |
| Ubuntu 22.04 (`cis_ubuntu2204.yml`) | v2.0.0 | v3.0.0 |
| Debian 12 (`cis_debian12.yml`) | v1.1.0 | v2.0.0 |
| Debian 13 (`cis_debian13.yml`) | v1.0.0 | v1.1.0 |

CaC `v0.1.82` does not yet carry the current editions, so the report names the
edition each id comes from and claims no mapping to the newer one. Other OS
releases (Ubuntu 26.04 and 20.04, Debian 11, non-Debian distros) have no pinned
profile, so every check is reported as `unverified` with no id.

| Check | Ubuntu 24.04 | Ubuntu 22.04 | Debian 12 | Debian 13 | Coverage |
|---|---|---|---|---|---|
| `ssh-root-login` | 5.1.20 | 5.1.20 | 5.1.20 | 5.1.21 | full |
| `ssh-weak-config` (MaxAuthTries only) | 5.1.16 | 5.1.16 | 5.1.16 | 5.1.17 | partial |
| `firewall-active` | 4.2.3, 4.3.4 | 4.1.3, 4.2.4 | 4.2.3, 4.3.4 | 4.1.2 | partial |
| `world-writable-dirs` | 7.1.11 | 7.1.11 | 7.1.11 | 7.1.11 | partial |
| `risky-services` (tftp only) | 2.1.16 | 2.1.16 | 2.1.16 | 2.1.17 | partial |
| `ssh-password-auth`, `auto-updates`, `exposed-ports`, `fail2ban-present` | unmapped | unmapped | unmapped | unmapped | - |

*Partial* means the check reads the same setting with a narrower scope or a
looser threshold (for example ThreatCrush flags `MaxAuthTries` above 6, CIS
wants 4 or less): a FAIL is a real finding against the control, a PASS does not
satisfy it. Unmapped checks have no matching control in any pinned profile, and
the report says why. The PRD 0005 `code-scanner config` checks are in the same
catalog: `world-writable` maps to 7.1.11 (partial); the web-root, debug,
container, CORS and credential-file checks are unmapped because the OS
benchmarks have no control for them.

The dashboard's fleet export (Findings, Export MD/JSON/PDF) re-derives each
mapping from the same catalog using the OS the agent reported, and never trusts
ids sent by the agent. Most findings uploaded by agents older than this release show
as `unverified` until the host runs `harden` again.

## Features

| Feature | Description |
|---------|-------------|
| 🔍 **Live Attack Detection** | Tails nginx, auth, syslog and journald, and polls inbound connections to the ports you serve. Detects SQLi, XSS, path traversal, RFI, SSH brute force, port scans, SYN floods, DNS tunneling. |
| 🛡️ **Code Security Scanner** | Scan your codebase for vulnerabilities, hardcoded secrets, and misconfigurations. |
| 💥 **Pentest Checks** | `threatcrush pentest URL` spot-checks security headers, CSP, CORS, cookie flags, server banners, directory listings and error leaks, then probes for SQL errors, path traversal and unsafe HTTP methods. |
| 🔀 **Network Monitor** | Polls conntrack/`ss` every 5 s for inbound TCP connections to your listening ports. Flags port scans (10+ ports in 30 s) and SYN floods (50+ half-open from one source). No packet capture. |
| 🔔 **Real-time Alerts** | Slack, email, webhook notifications the instant a threat is detected. |
| ⚙️ **systemd Daemon** | Runs as a background service on your server. Auto-starts on boot, monitors 24/7. |
| 📊 **TUI Dashboard** | Interactive terminal dashboard — htop for security. |

## Modules

ThreatCrush uses a pluggable module system. Install from the marketplace or build your own:

```bash
threatcrush modules list                # List built-in and installed modules
threatcrush modules install ssh-guard   # Install a module
threatcrush modules install docker-monitor
threatcrush store search "firewall"     # Search marketplace
threatcrush store publish https://github.com/you/my-module  # Publish your own
```

### Built in

| Component | What it covers |
|-----------|----------------|
| `log-watcher` | nginx access log + syslog — 96 OWASP CRS rules (PL1: SQLi, XSS, path traversal, RFI, RCE, PHP/Java injection, SSRF, scanners) + 4 ThreatCrush rules (OS files in the path; PHPUnit, ThinkPHP and XWiki RCE probes) scored on every request |
| `ssh-guard` | auth.log / secure — failed logins, brute force, root logins, user enumeration |
| `user-journal` | journald — the systemd journal |
| `network-monitor` | Inbound connections to your listening ports — port scans, SYN floods |
| `dns-monitor` | Resolver logs (systemd-resolved, dnsmasq, bind, Pi-hole) — DNS tunneling, DGA detection |
| `threatcrush scan` | Vulnerabilities, secrets, GitHub Actions injection and remote-exec workflows, dependency CVEs (OSV.dev, with `--deps`) |
| `threatcrush scan --host` | Rootkit / host integrity scan: package file integrity, rkhunter, chkrootkit, hidden processes and kernel modules, `ld.so.preload`, SSH keys, Docker, recent persistence, SUID outside packages |
| `threatcrush pentest` | Header, CORS, cookie, SQL-error, path-traversal and HTTP-method checks |
| auto-defend | Bans via fail2ban, nftables or iptables |
| alerts | Slack, Discord, email, webhook, PagerDuty |

### Community Modules

Build and sell your own modules on the ThreatCrush marketplace:
- `docker-monitor` — Container escape detection
- `k8s-watcher` — Kubernetes cluster security
- `honeypot` — Deploy decoy services
- `geo-blocker` — Block traffic by country/ASN
- `compliance-reporter` — SOC2, HIPAA, PCI-DSS reports

## Configuration

```bash
threatcrush init                    # Auto-detect & generate config
threatcrush init --offline          # Same, without signing in (scripts, CI, containers)
```

Config lives at `/etc/threatcrush/threatcrushd.conf` with module configs in `/etc/threatcrush/threatcrushd.conf.d/`.

### Postgres in Docker (brute-force bans)

Docker's default `json-file` log driver keeps container output out of journald and `/var/log`, so a Postgres container with its port published is invisible to log tailing. When `/var/run/docker.sock` exists, the daemon follows matching containers over the Docker Engine API (picking up restarts and recreates) and turns `password authentication failed` and `no pg_hba.conf entry` lines into `postgres-guard` events. The `postgres-auth-bruteforce` rule bans an address after 5 failures in 10 minutes. Private, loopback and Docker-bridge addresses and the `[remediation] protected` list are never counted. The client address is read from the line, so `log_line_prefix` needs `%h` or `%r` (Supabase's images have it); pg_hba rejects always name the host.

```toml
[docker_logs]
enabled = true                          # default: on when the Docker socket exists
name_pattern = "supabase-db$"           # container name regex
image_pattern = "(^|/)postgres(:|@|$)"  # image regex; either match is enough
poll_seconds = 15                       # how soon new or restarted containers are followed
```

Check a line without touching the firewall: `threatcrush rules test postgres-auth-bruteforce --repeat 5 --line '<log line>'`.

### Postgres running a shell (COPY FROM PROGRAM)

A database superuser can run OS commands with `COPY ... FROM PROGRAM`, which starts `/bin/sh -c` as a child of the backend. Every few seconds the daemon walks `/proc` (which includes processes inside containers) and raises a critical `postgres-shell-exec` alert for any shell or common LOLBin (`sh`, `bash`, `dash`, `busybox`, `curl`, `wget`, `nc`, `ncat`, `python*`, `perl`, `base64`, anything touching `/dev/tcp`) whose parent chain includes `postgres`, `postmaster` or `.postgres-wrapper`. With `[docker_logs]` on, Postgres container log lines naming `FROM PROGRAM`/`TO PROGRAM` raise `postgres-copy-program` (critical), and plain shell errors or job-control output in that log (`sh: 1: curl: not found`, `Killed`, `Terminated`) raise `postgres-shell-output` (high). A command that finishes between two polls can be missed by the process check; reverse shells, downloaders and miners cannot.

```toml
[postgres_shell]
enabled = true          # default on (Linux)
poll_seconds = 3
kill = false            # SIGKILL the process tree postgres spawned; never postgres itself; not in dry_run
allow_cmdline = []      # extra regexes (whole command line) for programs postgres may run, e.g. an archive_command
```

Supabase's `pgsodium_getkey` and plain `sh -c wal-g|pgbackrest|barman-wal-* ...` archive commands (with no shell metacharacters) are allowed by default.

### Suspicious successful SSH logins

A stolen key logs in without a single failure. Every accepted SSH login is classified:

- `ssh-login-tor` (critical): from a Tor exit.
- `ssh-login-sensitive` (critical for root, high otherwise): root, a `sensitive_users` entry or a member of `sensitive_groups` logged in from an address outside `trusted_login_cidrs` and the `[remediation] protected` list. With no trusted CIDRs, every public login of those users alerts.
- `ssh-login-new-network` (medium): the user's first login from that /24 (IPv6: /48). Seen networks are kept in the state db; the first start learns the last 30 days from the journal.

A key pinned to a forced command in that user's `authorized_keys` (`restrict,command="... ci-deploy owner/repo" ssh-ed25519 ...`, as CI deploy keys are) logs from any address at info as `ssh-login-forced-command`, with the command, instead of raising `ssh-login-sensitive` or `ssh-login-new-network`; from a Tor exit it still raises `ssh-login-tor`. The fingerprint-to-command map is cached per user and re-read when `~/.ssh/authorized_keys` (or `authorized_keys2`) changes. Keys named by a custom `AuthorizedKeysFile` are not read.

Alerts name the user, address, auth method and key fingerprint. Private, loopback and tailnet ranges (10/8, 172.16/12, 192.168/16, 100.64/10, 127/8, ::1, fc00::/7) are never flagged or acted on.

```toml
[login_watch]
enabled = true
sensitive_users = ["root"]                            # root is always included
sensitive_groups = ["sudo", "admin", "wheel", "docker"]
trusted_login_cidrs = []                              # e.g. ["203.0.113.0/24"]; empty = alert on every public login of those users
first_seen = true                                     # first login per user per /24
auto_response = false                                 # high/critical: ban the address and kill that user's sshd sessions from it (not in dry_run)
```

`kill` and `auto_response` need `CAP_KILL`, which the unit from `threatcrush install-service` now grants; re-run it after upgrading if you turn either on.

### SSH login context

Every accepted SSH login carries `ssh_context` to the dashboard and the desktop app, so an "SSH Login Accepted" alert explains itself:

- **when and where**: host, host-local time and UTC;
- **login**: user, auth method, key type and fingerprint, and the matching `authorized_keys` line from root's and every login account's `authorized_keys`/`authorized_keys2`: comment, options (`restrict`, `command=`, `from=`), every file that carries it, with the key blob masked (`AAAAC3Nz…[masked]`). Flags a key that authorizes both root and another account, and a dated ci/diag-style comment ([planted-authorized-keys](../../attack-vectors/planted-authorized-keys.md));
- **source**: loopback, one of this host's addresses, Tailscale (100.64.0.0/10), private, a GitHub Actions runner (api.github.com/meta `actions`, cached a day on disk) or public, plus reverse DNS and Team Cymru ASN, owner and country (DNS lookups, 2.5 s timeout, cached);
- **before it**: failed attempts in the last 10 minutes, how many from the address that got in and how many from others, with addresses and users. The rule `ssh-success-after-failures` fires on every accepted login; this says whether a brute force actually preceded it;
- **the session**: for a forced-command key, the `ci-deploy` journal line from the same address (ALLOW/DENY, repo, action, command with secret-looking values redacted) and the session length when it closed within the settle time;
- **verdict**: e.g. `Likely CI deploy: GitHub Actions IP, forced-command deploy key, ci-deploy ALLOW deploy app 5addb4f2` or `Suspicious login: unrestricted key (no command=, from= or restrict) from a non-CI address`. The `ssh-success-after-failures` detection takes the verdict's severity: expected key info, likely CI low, internal low, review high, suspicious critical. A lowered detection is still uploaded, as a quiet row.

```toml
[ssh_context]
enabled = true
network_lookups = true         # reverse DNS + Team Cymru ASN/country for public addresses
github_actions_ranges = true   # api.github.com/meta, refreshed daily
expected_keys = []             # ["SHA256:..."]: CI keys whose logins become a quiet info row
ci_deploy_tag = "ci-deploy"    # syslog identifier of the forced command
failure_window_seconds = 600
settle_ms = 5000               # wait for the ci-deploy line / session close before sending (max 20000)
```

Accepted logins reach the rule engine after at most `settle_ms` plus the lookup timeouts. Nothing secret leaves the box: no key blob, no private material, no environment.

### Local shell history protection

Command-history collection is opt-in because shell histories may contain credentials or private work details:

```toml
[command_history]
enabled = true
```

The system daemon checks Bash, Zsh, Fish, and Ksh history files every minute, keeps compressed local snapshots under `/var/lib/threatcrush/command-history/`, and retains up to 96 archived snapshots plus the current backup per file for up to 90 days. The directory is root-only. Snapshot contents stay on the host and are never sent to the dashboard. If a history file is replaced by a symlink, hard link, or removed after a backup exists, the daemon restores the last snapshot and emits a medium-severity event. Re-run `threatcrush install-service` after enabling collection so systemd grants write access only to supported interactive users' home directories.

Snapshots contain only commands the shell has flushed to its history file. Bash commonly writes its in-memory history when the shell exits, so these backups are an audit trail, not a real-time activity clock or proof of hours worked. Use OS command auditing when you need complete per-command records.

### File integrity monitoring

Hash selected system or application paths locally and alert when a file is added,
removed, or changes. It is opt-in because walking large directories reads every
regular file. Symlinks are skipped, each file is opened without following a
symlink, and file contents are never stored or uploaded. SHA-256 hashes remain
in the local root-owned state directory; events include changed paths but not
hashes. Linux inotify events trigger prompt scans for watched directories; the
periodic rehash remains a fallback (up to 2,048 directories are watched). A
first complete scan records the baseline without generating alerts; an
incomplete scan never replaces it. To keep daemon work bounded, scans stop
at 50,000 visited paths, 64 MiB per file, or 512 MiB total; choose narrower
paths if a scan reaches one of those limits.

```toml
[file_integrity]
enabled = true
paths = ["/etc", "/usr/local/bin", "/var/www"]
canaries = ["/var/www/.customer-export-decoy"] # existing decoy file; any change/removal is critical
canary_directories = ["/srv/customer-data"] # place a hidden canary without overwriting existing files
poll_interval_seconds = 900
```

Use `threatcrush integrity` to inspect the local baseline and
`sudo threatcrush integrity rebaseline` after reviewing expected system or
application changes. A single changed file is high severity; a burst of 25 or
more changes in one scan is grouped into one critical alert. A burst of at
least 10 changed files with a 0.5-bit average entropy increase is also critical.
Each configured
`canary_directories` entry gets a hidden, writable `.threatcrush-canary` file
on its first baseline; existing files are never replaced, and the canary is
not recreated after a baseline exists if it is deleted. The entropy signal is
a mass-change heuristic, not a content classifier.

#### Stopping the writer (opt-in)

By default a canary hit or mass change only alerts. Set `contain_writer` to
have the daemon find the process doing the writing and freeze or kill it:

```toml
[file_integrity]
contain_writer = "stop"     # "off" (default) | "stop" (SIGSTOP, recommended) | "kill" (SIGKILL)
contain_max_processes = 3   # more candidate writers than this: alert only
never_contain = ["/usr/bin/rsync", "/opt/backup/bin/"] # exact executables, or a directory ending in /
```

inotify does not say which process changed a file, so the daemon walks
`/proc/<pid>/fd` and keeps processes holding a changed file open **for
writing** (read from `/proc/<pid>/fdinfo`). Only when nobody holds the changed
files does it fall back to processes writing inside the same directories. The
walk is bounded (8,192 processes, 4,096 descriptors each, 1.5 s); a writer that
already closed its files cannot be found.

It never signals pid 1, the daemon or its parent, kernel threads, `sshd`
(including `sshd-session`), anything named `systemd*`, or a `never_contain`
executable. It alerts without acting when the `/proc` walk was incomplete,
when it finds more than `contain_max_processes` candidates, or when nobody
holds the files. Each pid's start time is re-checked just before the signal so
a recycled pid is never hit, and `[remediation] dry_run = true` reports the
signal instead of sending it. The critical event and the daemon log record
what was done under `details.containment` (pid, executable, signal, result,
files).

`"stop"` is reversible: after reviewing, resume with `kill -CONT <pid>` or end
it with `kill -KILL <pid>`. Use `"kill"` only if you would rather lose the
process than leave it suspended.

Reading another user's `/proc/<pid>/fd` needs `CAP_SYS_PTRACE`. Re-run
`sudo threatcrush install-service` after enabling `contain_writer`; the unit
gets that capability only while `contain_writer` is on. Without it, only
writers running as root can be identified.

### Auditd and eBPF process detections

EDR reads process events from Linux auditd or, optionally, eBPF. It
detects shells or downloaders started by configured web-service accounts,
execution from configured temporary or world-writable paths, and known miner
process names. It is disabled until you install the generated rules and opt in:

```toml
[edr]
enabled = true
source = "auditd" # "auditd" (default) | "ebpf" | "auto"
audit_log_path = "/var/log/audit/audit.log"
web_service_users = ["www-data", "nginx", "caddy"]
temp_exec_paths = ["/tmp", "/var/tmp", "/dev/shm"]
watch_network_syscalls = false # opt in; successful connect/listen rules can produce high audit volume
network_baseline_seconds = 60 # learn outbound executables before alerting on new ones
watch_unknown_temp_cpu = true # alert after 80% CPU sustained for 60 seconds
```

Review the host-specific rules before loading them:

```bash
sudo threatcrush edr rules | sudo tee /etc/audit/rules.d/90-threatcrush.rules
sudo augenrules --load
sudo threatcrush edr status
```

Some auditd 4.x distributions use `audit-rules.service` instead of
`augenrules`; use the rule loader supported by the host. Loading rules changes
kernel audit behavior, so ThreatCrush prints them for review and never installs
or reloads them itself. Auditd may record arguments for selected executions in
its root-protected log; ThreatCrush discards those arguments and remote
addresses. The opt-in network rules identify shell connect behavior, first-seen
outbound executables after a learning window, and processes that begin
listening. A root-owned local file remembers learned executable paths.
Temporary-path executables that sustain at least 80% of one CPU core for 60
seconds raise a critical event, including when auditd is unavailable. These
signals are not proof of compromise; the agent does not kill processes or
automatically ban them.

#### eBPF source (bpftrace)

`source = "ebpf"` feeds the same rules from eBPF instead of the audit log,
with no audit rules to load and no native npm dependency: the daemon runs the
`bpftrace` CLI as a child process (argv, no shell) with an embedded program
that traces successful `exec` (pid, ppid, effective uid, file name) and, when
`watch_network_syscalls = true`, TCP connect (`SYN_SENT`) and listen
transitions. Each event becomes the same normalized record the auditd parser
produces, so reverse-shell, web-service shell, writable-path execution, miner,
new-outbound and listener detections behave identically on either source.
Command arguments are not traced.

With `watch_network_syscalls = true` the eBPF source also reads the remote
address and port of every outbound TCP connect and looks it up in the
`[threat_feeds]` lists. A hit raises a critical `threat-feed-outbound` event
naming the process and its binary. This is the path that sees a one-second
download or a connection made inside a container: the threat-feeds socket
snapshot runs every 15 seconds in the host's own network namespace and misses
both. An address that is not listed is dropped at once and never stored or
sent anywhere. Set `match_threat_feeds = false` under `[edr]` to trace no
remote addresses at all. The auditd source does not do this matching.

Inbound is covered by the snapshot: a listed host connected to one of this
box's listening ports raises a high `threat-feed-inbound` event that carries
the source address, so auto-defence can ban it.

It needs root, `bpftrace` (`apt install bpftrace`) and kernel BTF
(`/sys/kernel/btf/vmlinux`). Under systemd the unit must also grant `CAP_BPF`
and `CAP_PERFMON`: enable `[edr]` first, then run `threatcrush install-service`
again, which adds them when the eBPF source is configured. A unit installed
before that makes bpftrace exit with "Missing CAP_BPF capability". `source = "auto"` picks eBPF when all three are
present and auditd otherwise; `source = "ebpf"` logs why and uses auditd when
they are not. If bpftrace exits it is restarted with exponential backoff (1s
up to 60s); if it fails to start three times in a row, the daemon falls back
to auditd. The daemon logs the active source and records it in
`edr-source.json` in its state directory; `threatcrush edr status` shows the
configured source, what this host would select, and what the daemon is using.
Review the exact program with:

```bash
threatcrush edr bpftrace
```

### Findings in the cloud

Signed in (`threatcrush login`), every `scan`, `pentest` and `ai-scan` result is
saved to your current org (`threatcrush orgs use <slug>`), where findings are
tracked across runs: new, still open, and fixed automatically once a later run of
the same scope no longer sees them. Triage them in the CLI, on the web
(threatcrush.com/org/&lt;slug&gt;/findings, installable as a PWA), in the desktop
app (Findings, sign in with your browser) or over MCP (`findings_list`,
`findings_get`, `findings_triage` at threatcrush.com/api/mcp):

```bash
threatcrush findings                       # open + acknowledged
threatcrush findings --status all --severity critical,high --source ai-scan
threatcrush findings show 3f2a9c1d
threatcrush findings ack|fix|fp|ignore|reopen 3f2a9c1d 7b1e… --note "why"
```

In CI, set `THREATCRUSH_API_KEY` to a `tc_agent_` key with write and runs
upload into that key's org with no login (workflow example in
docs/SCANNING.md). `--no-upload` (or `THREATCRUSH_UPLOAD=0`) keeps a run local. A repo is named by
its origin remote (credentials stripped); URL targets lose their query string.

### Usage counts

Each `threatcrush ai-scan` / `ai-scan-run` sends one anonymous count to the API
(`THREATCRUSH_API_URL`, default threatcrush.com): command, CLI version, OS, Node
version, CI or not, a random install ID (`~/.threatcrush/usage-ping.json`), and
probe/finding counts and run time. Never the target, prompts, responses or
finding text. Turn it off with `THREATCRUSH_TELEMETRY=0` or `DO_NOT_TRACK=1`.
Requests to our API also carry the user agent `threatcrush/<version>`.

## Cloud dashboard

The daemon reports to your ThreatCrush dashboard once the machine is logged in and linked to a server there:

```bash
threatcrush login                      # prints a link: approve it in a browser where you are signed in
threatcrush servers link               # reuses the dashboard server with this hostname, or registers one
threatcrush servers link --org acme --name web-1
threatcrush save                       # store this machine's daemon config on its server (secrets redacted)
threatcrush status                     # shows the link
threatcrush servers unlink             # stop reporting
```

`threatcrush login` needs no browser on the machine and never asks for a password: it prints a `threatcrush.com/cli/login` link and a short code, you approve it from any signed-in browser after checking the code matches, and the terminal finishes signing in on its own (PKCE-bound, so only the terminal that started it can redeem it; the link expires after 10 minutes). Each machine gets its own session. `threatcrush login --password` keeps the email-and-password prompt.

`threatcrush save` uploads the config the daemon reads (`/etc/threatcrush/threatcrushd.conf` as root). Values under keys that look like secrets (passwords, tokens, webhook URLs, API keys) are replaced with `[redacted]` before upload, and again by the server.

A running daemon picks up `link` and `unlink` within a minute; no restart. It then:

- uploads detections at or above `[cloud] min_severity` (rule detections, plus events from modules no rule reads, such as dns-monitor), batched (100 events or every 10 s), and every ban and unban the daemon makes;
- sends a heartbeat every 60 s with its version and hostname;
- runs the `threatcrush harden` checks and `threatcrush patches` a minute after it starts and every 24 h, and uploads the findings (both commands upload too; `--no-upload` skips it);
- every 15 s, picks up blocks and unblocks queued on the dashboard and applies them through auto-defence, so protected and allowlisted addresses and dry-run apply as they do locally;
- every 5 min, adds the organization's IP/CIDR allowlist to the never-block set (an entry wider than /8 for IPv4 or /16 for IPv6 is ignored, and the dashboard can never remove a built-in, shared-infrastructure or locally configured protected address).

What the dashboard can make a daemon do is limited to block, unblock, allowlist add/remove, restart, and "update now" (which installs the newest `@profullstack/threatcrush` from the npm registry; the dashboard never supplies a version, URL or command). Property scans and pentests queued on the dashboard run on a machine only when its operator opts in, and then only for the linked organization:

Uploads never hold up detection or a ban. While the dashboard is unreachable, events wait in a spool (`/var/lib/threatcrush/cloud-spool.jsonl`, or `~/.threatcrush/state/` for a user daemon) of at most 10,000 events / 20 MB, oldest dropped first, which survives a restart and is sent when the dashboard answers again. The daemon uses the login of the user it runs as (`/root/.threatcrush/config.json` for the system service) and refreshes the session itself; if the refresh token is refused, it logs that `threatcrush login` is needed and keeps spooling.

```toml
[cloud]
enabled = true            # false: the daemon neither reports to nor takes actions from the dashboard
min_severity = "medium"   # info | low | medium | high | critical
runs = false              # true: run property scans/pentests queued on the dashboard here
run_scan_paths = []       # the only directories a dashboard scan may read; empty refuses scans
```

Pentests from the dashboard only reach public addresses: a target that resolves to loopback, a private range or link-local (cloud metadata) is refused.

### Every machine, with what it costs

The Fleet panel lists linked daemons. To also list the machines that do not run one, and what each box costs a month, upload an [OpenDevice](https://logicsrc.com/docs/opendevice) inventory (org owners and admins):

```bash
threatcrush fleet import opendevice.json         # or an https:// URL; --org <slug> to pick the org
threatcrush fleet cost                           # per-box $/mo, provider, daemon status and the total
```

Devices are matched to linked servers by hostname, name or IP. A device with no daemon shows as "no agent"; a cost the inventory does not state shows as "unstated" and is never guessed. Totals are per currency, never converted. `GET /api/fleet/costs` returns the recurring costs in the shape CoinPay imports.

## Automatic updates

The daemon keeps itself on the latest release. About every 6 hours (plus up to an hour of jitter, so a fleet does not restart in step) it asks the npm registry for `latest`. When a newer version has been published for at least 2 hours, and is on the same major version, it installs it and restarts onto it. The update shows in the live feed as an info event (`auto-update`).

Under systemd the unit's sandbox keeps the daemon from writing its own install, so it hands `npm i -g` to a transient unit (`systemd-run`) run as whoever owns the install, then restarts the service. A user-mode daemon runs npm itself. Only the npm global layout the installer produces is updated in place. A daemon running from a pnpm store or a source checkout logs that `threatcrush update` is needed instead. A version that was tried and did not take is not retried for a day.

```toml
[update]
auto = true          # false (or THREATCRUSH_AUTO_UPDATE=0): upgrade by hand with `threatcrush update`
interval = "6h"      # how often to check (at least 15m)
min_age = "2h"       # how long a release must be public before it is taken
allow_major = false  # true: also move to a new major version
```

## Pricing

The CLI is MIT-licensed (see [License](#license)). For pricing, [contact us for a quote](https://threatcrush.com/hire).

## Browser Extension

Monitor security from your browser:

- **Chrome** — Chrome Web Store (coming soon)
- **Firefox** — Firefox Add-ons (coming soon)
- **Safari** — Coming soon

Features: scan any site, real-time alerts, security headers check, dashboard popup.

## Links

- 🌐 **Website:** [threatcrush.com](https://threatcrush.com)
- 📦 **npm:** [@profullstack/threatcrush](https://www.npmjs.com/package/@profullstack/threatcrush)
- 🐙 **GitHub:** [profullstack/threatcrush](https://github.com/profullstack/threatcrush)
- 🐛 **Issues:** [GitHub Issues](https://github.com/profullstack/threatcrush/issues)

## License

MIT © [Profullstack, Inc.](https://profullstack.com)
