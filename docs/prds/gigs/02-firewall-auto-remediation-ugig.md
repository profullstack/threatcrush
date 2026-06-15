# Build ThreatCrush firewall auto-remediation (nftables/iptables)

> ugig.net gig posting — implements [PRD-02](../02-firewall-auto-remediation.md)

- **Title:** Build ThreatCrush firewall auto-remediation (nftables/iptables)
- **Skills required:** `typescript`, `nodejs`, `linux`, `nftables`, `iptables`, `networking`, `security`, `systemd`
- **Budget type:** fixed
- **Budget (USD):** 1,800 – 3,000
- **Repo:** https://github.com/profullstack/threatcrush · branch `feat/firewall-remediation`
- **Spec:** `docs/prds/02-firewall-auto-remediation.md`

## What we need

The product's central promise — "what the tool already blocked" — is currently
vapor: there is zero firewall code. Build the `firewall-rules` module that blocks
offending IPs in response to detections, safe-by-default, with a clean audit
trail synced to `remediation_actions`.

## Scope

1. Firewall adapters: nftables first, iptables fallback, auto-detected behind a
   generic interface.
2. Actions: temporary ban (with expiry), permanent blocklist, unblock; a daemon
   worker that unblocks expired bans (mirror the existing `runs-worker`).
3. Dry-run mode (default until opted in), allowlist enforcement (reads
   `allowlists`), full local + server-synced audit trail.
4. Graceful `EACCES` handling when the daemon lacks `CAP_NET_ADMIN` — surface a
   hardening recommendation instead of crashing.
5. CLI: `threatcrush block <ip> [--ttl] | unblock <ip> | blocklist |
   allowlist add|remove`; `[remediation]` config block in `threatcrushd.conf`.

## Acceptance criteria

- nftables + iptables adapters pass integration tests in a container.
- Dry-run writes an audit entry but makes no firewall change.
- Allowlisted IP is never blocked; expired bans auto-clear; manual unblock works.
- Actions surface in the dashboard via `remediation_actions`. PR with green CI.
</content>
