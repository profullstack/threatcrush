# Stolen GitHub App private keys left unrotated after a host compromise

## Summary

GitHub App private keys lived in plaintext env files (`app.env`, plus `.bak`
copies) on a host that was rooted. The host was cleaned, but the App keys were
never regenerated. Days later the attacker used them to mint installation tokens
and push commits directly to a default branch as `<app>[bot]`.

## Preconditions

- One or more GitHub Apps whose private key (and App id) sit on disk in
  plaintext: an env file, a `.pem` beside the app, a backup copy of either.
- The host is compromised (any route: the other entries in this collection
  describe several).
- Incident response rotates passwords, ssh keys and database credentials but
  treats the App keys as "still on GitHub, so still ours".
- The App has `contents: write` (or broader) on repositories whose default
  branch is not protected against the App, or the App is a bypass actor.

## Chain

1. During the original compromise the attacker sweeps the host for secrets and
   copies every env file and its backups (`app.env`, `app.env.bak.<date>`).
2. Responders remove the attacker's access to the host. The App private keys
   are not regenerated; old keys remain valid on GitHub.
3. Days later, the attacker signs a JWT with a stolen App key and calls
   `POST /app/installations/{id}/access_tokens` for each installation.
4. With an installation token, the attacker writes through the contents API
   (`PUT /repos/{owner}/{repo}/contents/{path}`), creating commits on the
   default branch. The commit author is `<app>[bot]`; the committer is
   `web-flow` because the API created it.
5. The pushed change targets whatever runs automatically: a workflow file, a
   deploy script, a compose file (see
   [CI forced command that runs a repo-controlled compose file](ci-forced-command-compose.md)).
6. Responders suspend the App. Suspension is reversible by anyone holding the
   App's key, so the attacker unsuspends it and continues.

## Indicators of compromise

- Commits on a default branch authored by `<app>[bot]` with committer
  `web-flow`, not via a pull request, at times nobody deployed.
- Org audit log: `integration_installation.unsuspend` shortly after a
  suspend, or installation token creation from addresses outside your runners.
- On the host: env files or `.pem` files containing
  `PRIVATE KEY` banners next to `GITHUB_APP_ID`/`APP_ID`; backup copies
  (`*.env.bak*`, `.env.old`) older than the last rotation.
- GitHub App settings page shows more than one private key, or a key created
  before the incident date.

## Detection

- **`secret-github-app-private-key`** (critical): a PEM private key with a body,
  in any packaging (bare, inside a quoted multi-line env value, as a
  `\n`-escaped one-liner, inside JSON), in a file that also names a GitHub App
  id. Replaces the plain `secret-private-key` finding on that line.
- **`secret-private-key`**: the same, for any PEM key (`RSA`, `EC`, `DSA`,
  `OPENSSH`, `ENCRYPTED`, PKCS#8).
- **`secret-github-token`**, **`secret-aws-access-key`**,
  **`secret-slack-token`**, **`secret-stripe-key`**, **`secret-resend-key`**,
  **`secret-openai-key`**, **`secret-supabase-service-role`** and the rest of
  the vendor-format table in `packages/scan/src/secret-rules.ts`: issued token
  formats wherever they appear.
- **`secret-generic-high-entropy`**: an unquoted `*_SECRET=`, `*_PRIVATE_KEY=`,
  `*_TOKEN=`, `*_API_KEY=` or `*_PASSWORD=` whose value is long, mixed-class
  and high-entropy.
- **`sensitive-file-committed`**: `.env`, `app.env`, any env backup
  (`*.env.bak*`, `.env.old`, ...; critical), `id_rsa` / `id_ed25519` /
  `id_ecdsa` / `id_dsa`, `*.pem`, `*.p12`, keystores.
- **host `secrets-on-disk`** (`threatcrush host-scan`): unencrypted private
  keys and env files (including backups) under `/root` and `/home/*`, by path,
  owner and mode; never the value.
- Findings never contain the full secret: excerpts are masked before they reach
  a terminal, SARIF file or CI log.

## Mitigation

- After any host compromise, treat **every** secret that was on disk as burned,
  including backups and files you think nobody could read. Make a list from the
  host itself (`threatcrush host-scan --checks secrets-on-disk`) rather than
  from memory.
- For each GitHub App: generate a new private key, deploy it, then **delete
  every old key** in the App settings. Deleting the file on the host does
  nothing; the key on GitHub is what matters.
- Prefer **deleting** affected installations over suspending them. A deleted
  installation needs an organisation owner to reinstall; a suspended one can be
  unsuspended with the stolen key.
- Protect default branches with rulesets that apply to Apps too (no bypass
  actors you do not need), and require pull requests for workflow and deploy
  paths.
- Keep App keys out of env files on shared hosts: load them from a secret
  manager at start-up, or use a KMS-backed signer so the key never touches
  disk.

## References

- GitHub Docs: "Managing private keys for GitHub Apps"
- GitHub Docs: "Suspending a GitHub App installation"
- GitHub Docs: "About rulesets" (bypass list and App actors)
- Related: [GitHub App installation_id takeover](github-app-installation-idor.md),
  [CI forced command that runs a repo-controlled compose file](ci-forced-command-compose.md)
