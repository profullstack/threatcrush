# Over-broad sftp "landlock" jail: writes confined, reads allowed on /

## Summary

Deploy keys were limited to sftp through a custom jail (a Landlock-style
wrapper) that confined **writes** to an upload directory but allowed **reads**
on `/`. Any holder of a deploy key could therefore download every file the
deploy user could read, including application env files and private keys.

## Preconditions

- A key or account restricted to sftp (`command="internal-sftp"`,
  `ForceCommand internal-sftp`, or a wrapper around `sftp-server`).
- No `ChrootDirectory`, or a custom jail whose read rules default to allow.
- Secrets on the host readable by the deploy user (env files in app
  directories, backups, keys with loose modes).
- The deploy key leaks: it sits in CI secrets, on developer laptops and in
  every runner that ever used it.

## Chain

1. Attacker obtains a deploy key (CI secret exfiltration, a laptop, a previous
   host compromise).
2. Attacker connects with sftp. Uploads outside the jail fail, which is what
   the jail was tested for.
3. Attacker lists and downloads outside the jail: `get /srv/*/app.env`,
   `get /home/*/.ssh/id_*`, `get /etc/<app>/*.pem`. Reads succeed because the
   jail only restricted writes.
4. The harvested secrets open the next stage (see
   [Stolen GitHub App keys left unrotated](unrotated-github-app-keys.md)).

## Indicators of compromise

- sftp-server logging (`-l INFO`) showing `open "/srv/<app>/app.env" flags READ`
  or `opendir "/"` from the deploy account.
- Deploy-key sessions from addresses that are not your CI runners.
- Large outbound transfer volume on sshd sessions that normally only upload.

## Detection

- **`sshd-sftp-without-chroot`** (`threatcrush scan` on an `sshd_config` or
  `sshd_config.d/*.conf`): a `ForceCommand internal-sftp` (or `sftp-server`)
  block with no `ChrootDirectory`, in the same `Match` block or globally.
- **`authorized-keys-sftp-unjailed`** (on an `authorized_keys` file): a key whose
  `command=` is sftp. That limits what the key runs, not what it reads.
- Not visible: a custom jail's read policy. Test it directly: connect with the
  deploy key and try `ls /` and `get` of a file outside the upload directory.
  If either works, the jail is write-only.

## Mitigation

- Use `ChrootDirectory` (root-owned path, containing only the upload
  directory) together with `ForceCommand internal-sftp` in a `Match User`
  block. A chroot confines reads and writes alike.
- If you use a Landlock, seccomp or AppArmor jail, write the read rules
  explicitly and default-deny them; test reads, not only writes.
- Keep secrets out of anything the deploy user can read: mode `0600`, owned by
  the service user, not the deploy user.
- If it already happened: treat every file the deploy user could read as
  disclosed and rotate accordingly; rotate the deploy key itself.

## References

- OpenSSH `sshd_config(5)`: `ChrootDirectory`, `ForceCommand`, `Match`
- Linux kernel docs: Landlock (filesystem access rights are per operation:
  read rights must be restricted separately from write rights)
- Related: [CI forced command that runs a repo-controlled compose file](ci-forced-command-compose.md)
