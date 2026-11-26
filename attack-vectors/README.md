# Attack vectors

A field guide to the attack chains ThreatCrush has seen against real
infrastructure, written so you can recognise them on your own systems and so
every scanner rule has a story behind it.

Each entry describes one technique: what the attacker needed, the exact steps,
what it leaves behind, which ThreatCrush check catches it, and how to close it.
The seed entries all come from one incident on our own fleet in November 2026.
They are written generically ("a fleet host", "an app"): no hostnames,
addresses, accounts or key material from the incident appear here.

## Index

| Entry | Summary | Detected by |
|---|---|---|
| [GitHub App installation_id takeover](github-app-installation-idor.md) | A setup callback bound any `?installation_id=` to the signed-in user, so a throwaway account claimed another org's installation and wrote to its repos through the app. | `github-app-installation-idor` |
| [Stolen GitHub App keys left unrotated](unrotated-github-app-keys.md) | App private keys in plaintext env files (and `.bak` copies) on a rooted host were never regenerated; days later the attacker pushed to a default branch as `<app>[bot]`. | `secret-github-app-private-key`, `secret-private-key`, `secret-generic-high-entropy`, `secret-committed-env-file`, `sensitive-file-committed`, host `secrets-on-disk` |
| [CI forced command that runs a repo-controlled compose file](ci-forced-command-compose.md) | An ssh allowlist accepted `rsync` into a build dir and `docker compose -f <that dir>/compose.yml up --build`; a push made the service root with `/` and `~/.ssh` mounted. | `deploy-compose-from-synced-repo`, `deploy-remote-exec-uploaded-script`, `compose-host-root-mount`, `compose-docker-socket`, `compose-privileged`, `compose-root-user`, host `docker-group`, `docker-containers` |
| [sftp jail that confines writes but not reads](sftp-jail-reads-root.md) | A deploy key's jail blocked writes outside an upload dir but allowed reads on `/`, so any key holder could download every secret file on the host. | `sshd-sftp-without-chroot`, `authorized-keys-sftp-unjailed` |
| [Planted authorized_keys persistence](planted-authorized-keys.md) | Unrestricted keys with innocuous dated names (`ci-diag-YYYYMMDD`) added to a user's and root's `authorized_keys`, then logins from rotating residential proxies. | `authorized-keys-unrestricted`, `authorized-keys-suspicious-comment`, host `ssh-keys`, daemon `priv-authorized-key-added` |

Related checks that already existed when the incident happened and cover parts
of these chains: `gha-expression-injection` (`${{ github.event.* }}` or
`${{ inputs.* }}` pasted into `run:`), `gha-input-in-remote-shell`,
`gha-dispatch-remote-exec` and `gha-ssh-key-secret`.

## Running the checks

```sh
threatcrush scan .                  # repository / file tree: secret, deploy and workflow rules
sudo threatcrush host-scan          # a live host: ssh-keys, secrets-on-disk, docker-group, ...
```

Each finding prints a `Ref:` line linking back to the entry here, and the SARIF
output carries the same link as the rule's `helpUri`.

## Entry format

One markdown file per vector, named by slug (`kebab-case.md`). Every entry has
these sections, in this order:

1. **Title** (the `#` heading): the technique in a few words.
2. **Summary**: two or three sentences a responder can read in ten seconds.
3. **Preconditions**: what had to be true for the chain to work.
4. **Chain**: numbered steps, attacker's point of view.
5. **Indicators of compromise**: log lines, file changes, GitHub events. Use
   placeholders such as `<host>`, `<user>`, `<app>`; never paste real values.
6. **Detection**: which ThreatCrush checks fire, by check id, and what they
   cannot see.
7. **Mitigation**: what to change so the chain stops working, then what to do
   if it already ran.
8. **References**: upstream documentation and related entries.

## Adding an entry

1. Write `attack-vectors/<slug>.md` in the format above. Keep it generic: no
   hostnames, IP addresses, email addresses, account names or key material.
2. Add the slug to `ATTACK_VECTOR_SLUGS` in
   `packages/scan/src/references.ts`, and point the rules that detect it at it
   with `attackVector('<slug>')`.
3. Add a row to the index above. A test fails if a rule's reference points at
   a missing file or if a deploy rule id is missing from this README.
