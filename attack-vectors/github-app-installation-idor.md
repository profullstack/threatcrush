# GitHub App installation_id takeover (setup-callback IDOR)

## Summary

An app's GitHub App setup callback took `?installation_id=` from the query
string and bound it to whoever was signed in, after checking only that the
installation existed. Any account could therefore claim any organisation's
installation and then use the app's own "open a PR" and "commit a file"
features to write into that organisation's repositories.

## Preconditions

- The app offers a GitHub App install flow whose "Setup URL" callback receives
  `installation_id` (and `setup_action`) as query parameters.
- The callback verifies the id with an **App JWT** (`GET /app/installations/{id}`).
  That call succeeds for every installation of the App, so it proves the
  installation exists, not that the visitor has anything to do with it.
- The binding is persisted (`insert` / `upsert` of `user_id, installation_id`)
  and later used to mint installation tokens on that user's behalf.
- Signup is open, so a throwaway email is enough to get a session.

## Chain

1. Attacker learns a target organisation's installation id. Ids are sequential
   integers and leak through URLs, screenshots, webhook payloads and support
   threads; they are not secrets and must not be treated as such.
2. Attacker signs up with a disposable email address.
3. Within the same minute, attacker requests
   `GET /api/github/setup?installation_id=<victim id>&setup_action=install`.
4. The callback looks the id up with the App JWT (succeeds), then stores
   `(attacker_user_id, victim_installation_id)`.
5. Attacker uses the app's write features ("create a PR", "commit this file",
   "add a workflow") against the victim's repositories. The app mints an
   installation token for the victim installation and performs the write as
   `<app>[bot]`.

## Indicators of compromise

- One `installation_id` bound to more than one user in the app's database:
  `SELECT installation_id, count(DISTINCT user_id) FROM installations GROUP BY 1 HAVING count(DISTINCT user_id) > 1;`
- A user account created and an installation bound within the same minute,
  especially from a disposable-email domain.
- Setup callback requests with no preceding redirect from `github.com`
  (no `Referer`, no `code` parameter, no matching `state`).
- In the victim organisation: pull requests, commits or workflow files authored
  by `<app>[bot]` that nobody in the organisation asked for; audit log entries
  for the App's installation acting on repositories outside normal usage.

## Detection

- **`github-app-installation-idor`** (`threatcrush scan`, source code):
  a handler that reads `installation_id` from the query string
  (`searchParams.get('installation_id')`, `req.query.installation_id`,
  `request.args.get('installation_id')`, `$_GET['installation_id']`,
  `r.URL.Query().Get("installation_id")`, ...) and writes it to a database in
  the same handler, without calling `GET /user/installations`
  (`listInstallationsForAuthenticatedUser`) or a helper in the same file that
  does. It is a heuristic over text: a verification done in an imported module
  under an unrelated name is not visible, so a finding asks you to confirm.
- The IoC query above is the runtime check; run it against production.

## Mitigation

- In the callback, exchange the OAuth `code` for a **user-to-server** token and
  require the installation id to appear in `GET /user/installations` for that
  user. That is the only call that answers "can this person see this
  installation".
- Carry a signed, single-use, short-lived `state` from the moment you send the
  user to `github.com/apps/<app>/installations/new` and reject callbacks whose
  `state` is missing or reused.
- Make `installation_id` unique per tenant in the schema so a second binding
  fails loudly instead of silently sharing access.
- If it already happened: unbind every duplicate binding, revoke sessions of
  the accounts that made them, review every write the app performed for those
  installations, and notify the affected organisations.

## References

- GitHub Docs: "About the setup URL" and "Generating a user access token for a GitHub App"
- GitHub REST: `GET /user/installations` (List app installations accessible to the user access token)
- OWASP: Insecure Direct Object Reference (CWE-639)
- Related: [Stolen GitHub App keys left unrotated](unrotated-github-app-keys.md)
