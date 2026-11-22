# CI forced-command allowlist that runs a repo-controlled docker compose file

## Summary

A CI deploy key was pinned with an ssh `command=` allowlist that permitted two
things: `rsync` into a build directory, and
`docker compose -f <that dir>/compose.yml up --build`. The compose file came
from the repository, so one push changed it to run as `user: "0:0"` with `/`
and `~/.ssh` mounted, and the next deploy appended an ssh key to
`authorized_keys` and copied the host's private key out.

## Preconditions

- A deploy path where the host runs something the repository controls: a
  compose file, a `deploy.sh` uploaded by the workflow, or a daemon started
  from the checked-out tree.
- The deploy user can reach Docker (it is in the `docker` group, or the
  allowlist runs compose via sudo). Docker group membership is root on the host.
- Anyone who can push to the deploy branch, or anyone holding a credential that
  can (a stolen App key, a CI token), can change what the host runs.

## Chain

1. Attacker gains write to the repository or the deploy branch (for example
   with a stolen GitHub App key, see
   [Stolen GitHub App keys left unrotated](unrotated-github-app-keys.md)).
2. Attacker edits `compose.yml`:
   ```yaml
   services:
     app:
       user: "0:0"
       volumes:
         - /:/host:ro
         - ~/.ssh:/x:rw
       command: sh -c 'cat /x/pub >> /x/authorized_keys; cp /host/etc/ssh/ssh_host_ed25519_key /host/tmp/.k'
   ```
3. CI runs as usual: `rsync` the tree into `/srv/builds/<app>/`, then
   `ssh deploy@<host> docker compose -f /srv/builds/<app>/compose.yml up -d --build`.
   The forced command allows both, because both are on the list.
4. The container starts as root with the host filesystem mounted, appends the
   attacker's key to `authorized_keys`, and stages the host key for exfil.
5. Attacker logs in with the new key.

The same class without compose:

- The workflow `scp`s `deploy.sh` to the host and runs `ssh <host> bash /srv/app/deploy.sh`.
- The workflow runs `ssh <host> bash -s < scripts/deploy.sh`.
- A host-side cron or service does `git pull && docker compose up -d --build`
  in a checkout, as a user in the `docker` group.

## Indicators of compromise

- Git history: changes to `compose*.yml` adding `user: "0:0"`, `privileged`,
  `/:/…`, `~/.ssh`, `/root` or `/var/run/docker.sock` mounts; changes to
  `deploy.sh` or workflow deploy steps, by an App or an unusual author.
- Docker: `docker inspect` on recent containers shows `User: 0:0` with `Binds`
  covering `/` or a `.ssh` directory; `docker events` with a container start
  right after a deploy that nobody reviewed.
- Host: `authorized_keys` mtime equal to a deploy time; new key lines with no
  `from=`/`command=`; files staged in `/tmp` or `/var/tmp` copied from
  `/etc/ssh` or `~/.ssh`.
- sshd: `Accepted publickey for <user>` with a key fingerprint that is not the
  CI key, shortly after a deploy.

## Detection

- **`deploy-compose-from-synced-repo`** (`threatcrush scan`, shell scripts,
  workflows, forced-command wrappers): `docker compose -f <path>` (or
  `docker-compose`, or `docker compose up` after `cd`) run on a host where the
  path is under a directory the same file uploads to with `rsync`/`scp`, under
  a checkout updated with `git pull` on the host, or inside a
  `SSH_ORIGINAL_COMMAND` allowlist that also accepts `rsync --server`.
- **`deploy-remote-exec-uploaded-script`**: a script uploaded with
  `rsync`/`scp`/`appleboy/scp-action` and then executed over ssh (or an
  `appleboy/ssh-action` `script:`), and `ssh <host> bash -s < local-script`.
- **`compose-host-root-mount`** (critical), **`compose-docker-socket`**,
  **`compose-privileged`**, **`compose-root-user`**: compose services that bind
  `/`, `/root`, `/etc`, `/boot`, `/home` or a home directory, any `.ssh`
  directory, or the Docker socket; `privileged: true`, `cap_add` of
  `SYS_ADMIN`/`ALL`; `user: 0`, `0:0` or `root`.
- **host `docker-group`** and **`docker-containers`** (`threatcrush host-scan`):
  who is effectively root through Docker, and running containers with
  dangerous mounts or privileges.
- Not visible to a repository scan: what the server-side `authorized_keys`
  entry actually allows. `gha-ssh-key-secret` asks you to check it.

## Mitigation

- The host must run only code and config it owns. Keep the compose file the
  host runs outside the synced tree, root-owned and not writable by the deploy
  user, and deploy by pulling a **pinned image tag** built in CI, not by
  building pushed sources on the host.
- Send data, not code: the forced command should be a fixed script on the host
  (`restrict,command="/usr/local/bin/deploy <app>"`) that reads at most a
  version string from `SSH_ORIGINAL_COMMAND` and validates it against an
  allow-list regex.
- Remove deploy users from the `docker` group; if a service must manage
  containers, give it a narrow sudo rule for one fixed command or a filtering
  Docker API proxy.
- Run containers as an unprivileged uid with only the data directories they
  need mounted.
- If it already happened: assume root. Rotate the host's ssh host keys and every
  secret on it, remove unknown `authorized_keys` lines for every account, and
  rebuild the host if you cannot account for every change.

## References

- Docker Docs: "Protect the Docker daemon socket" and "Docker security: Docker daemon attack surface"
- OpenSSH `sshd(8)`: AUTHORIZED_KEYS FILE FORMAT (`command=`, `restrict`, `from=`)
- Related: [Planted authorized_keys persistence](planted-authorized-keys.md),
  [sftp jail that confines writes but not reads](sftp-jail-reads-root.md)
