# Bulk GitHub monitoring

Account → GitHub accounts & organizations connects multiple identities to an
existing ThreatCrush organization, including accounts signed in through CoinPay.
Connect an identity, install ThreatCrush on an account/org with **All repositories**,
and choose **Monitor all installed accounts & orgs**. No per-repo secrets or
checkboxes are needed. Future repositories are discovered every six hours;
**Sync new repositories** requests discovery immediately.

## Required GitHub App permission

“All repositories” selects repositories; it does not grant permission to read
their code. The app must request **Repository permissions → Contents → Read-only**.
The GitHub App owner configures this under its **Permissions & events** settings.
For the Profullstack-owned ThreatCrush app:

https://github.com/organizations/profullstack/settings/apps/threatcrush/permissions

Existing installations must then accept the new permission. Installations created
after the app permission is updated request it during installation. The account
page displays both app-level and installation-level missing permissions and links
directly to the appropriate GitHub settings. Metadata-only installations cannot
be bulk-enabled as if they had private-code coverage. Public scans already in
progress may continue; inaccessible private repositories remain visibly failed.
After approval, refresh GitHub app access and bulk-enable monitoring to retry all
previously inaccessible repositories.

The account verification OAuth/token requests only identity and organization
membership access. Its token is used once and never stored. Content reads use
short-lived GitHub App installation tokens.

## Warning defaults and critical paging

Test/docs/example warnings are silenced by default, with an account/org switch
that applies across its repositories. Critical findings bypass warning silences
and raise deduplicated incidents for organization **Owners + Admins**, respecting
their existing notification channel settings and hourly limits.

Scanning runs in a durable server-side queue, independently of the browser.
The UI distinguishes queued, running, complete, failed and limited scans. API
quota exhaustion defers work until GitHub's reset time. Pausing monitoring stops
new job claims. Private code, snippets and credentials are not stored in the queue.
