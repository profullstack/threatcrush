# Session persistence via planted authorized_keys entries

## Summary

After gaining a shell, the attacker appended their own public key, with an
innocuous dated comment such as `ci-diag-YYYYMMDD`, to both a regular user's
and root's `authorized_keys`. The keys had no `from=`, `command=` or
`restrict`. Bursts of logins followed from rotating residential-proxy
addresses, which made address-based blocking useless.

## Preconditions

- Any foothold that can write a home directory: a compromised deploy path
  (see [CI forced command that runs a repo-controlled compose file](ci-forced-command-compose.md)),
  a root container with `~/.ssh` mounted, a stolen password with sudo.
- sshd accepts public keys for those accounts (root login allowed with keys,
  `PermitRootLogin prohibit-password`).
- Nobody reviews `authorized_keys` content, so a plausible name survives.

## Chain

1. Attacker writes `ssh-ed25519 AAAA... ci-diag-<date>` to
   `/home/<user>/.ssh/authorized_keys` and `/root/.ssh/authorized_keys`
   (sometimes `authorized_keys2` too, which many people forget is read).
2. The comment imitates CI or diagnostic tooling, so a skim of the file reads it
   as "something the ops team added".
3. The attacker logs in from a pool of residential proxy addresses, a few
   sessions per address, so rate limits and per-IP bans see nothing unusual.
4. When the original entry point is closed, the planted keys keep working.

## Indicators of compromise

- `authorized_keys` lines whose comment is a role word plus a date
  (`ci-diag-20261120`, `ops-recovery-20261027`, `tmp-20261101`) and no
  `user@host`.
- The same key fingerprint in root's file and another account's file.
- `authorized_keys` mtime inside the incident window; a new line with no
  options.
- sshd: `Accepted publickey for root from <addr> port <p> ssh2: ED25519 SHA256:<fp>`
  where `<fp>` maps to the planted comment, from many distinct residential ASNs
  in a short period.

## Detection

- **host `ssh-keys`** (`threatcrush host-scan`): reads every
  `authorized_keys` and `AuthorizedKeysFile` path for root and every account.
  Fails a key that authorizes **both root and another account**, a key with a
  **temporary CI/diagnostic dated comment** that is unrestricted (warns if
  restricted), and an **unrestricted key in a file changed inside the
  `--since` window**. Still warns on every unrestricted key and on duplicates,
  and fails `--deny-keys` matches.
- **daemon `priv-authorized-key-added`** (`threatcrushd`): alerts in real time
  when a key is added to any watched `authorized_keys`, critical unless the key
  is listed in `[privileged] expected_keys`.
- **`authorized-keys-unrestricted`** and **`authorized-keys-suspicious-comment`**
  (`threatcrush scan` over a tree that contains `authorized_keys` files: a
  config repo, an image build context, a mounted backup): the same rules,
  per file.
- `threatcrush respond key <fingerprint>` finds and removes a key from every
  account at once.

## Mitigation

- Prefix every legitimate key with `restrict` and, where possible, `from=` and
  `command=`. A planted unrestricted key then stands out by shape alone.
- Manage `authorized_keys` from configuration management or
  `AuthorizedKeysCommand`, so unmanaged lines are overwritten and noticed.
- Disable root ssh login (`PermitRootLogin no`) and stop reading
  `authorized_keys2` (`AuthorizedKeysFile .ssh/authorized_keys`).
- If it already happened: remove the key from **every** account, check
  `authorized_keys2` and backups (`authorized_keys.bak`), hunt for other
  persistence (cron, systemd units, PAM, sudoers), then rotate everything the
  box held.

## References

- OpenSSH `sshd(8)`: AUTHORIZED_KEYS FILE FORMAT
- OpenSSH `sshd_config(5)`: `AuthorizedKeysFile`, `AuthorizedKeysCommand`, `PermitRootLogin`
- MITRE ATT&CK T1098.004: Account Manipulation: SSH Authorized Keys
- Related: [CI forced command that runs a repo-controlled compose file](ci-forced-command-compose.md)
