---
openprd: "0.2"
id: "0005"
title: "Catch the misconfigurations that actually get servers breached"
status: Draft
authors:
  - anthony@profullstack.com
created: 2026-07-28
updated: 2026-07-28
repo: profullstack/threatcrush
discussion:
implementation: modules/code-scanner (config subsystem)
tags: code-scanner, config, misconfiguration, hardening, exposure, modules
supersedes:
superseded-by:
---

## Problem

`PRD.md` lists "misconfigs" in `code-scanner`'s remit. It is the last of the
four subsystems and, on the evidence, the one that matters most for the users
this product targets.

**Small-team servers are far more often breached by configuration than by code.**
The recurring causes are unglamorous and completely mechanical: a `.env` served
by a web root, a `.git` directory reachable over HTTP, a database bound to
`0.0.0.0` with a default password, debug mode left on in production, an
`APP_DEBUG` stack trace disclosing paths and credentials, a Docker socket
mounted into a container, `chmod 777` on a deploy directory, a `docker-compose`
file with `privileged: true`. None of these require an exploit. Each is a
default that was never changed or a temporary fix that became permanent.

**This is the one subsystem where the daemon is unambiguously the right place
to look.** The other three have a CI counterpart doing overlapping work:
Dependabot for `deps`, gitleaks for `secrets`, CodeQL for `sast`. Configuration
is different — a `docker-compose.yml` in a repository tells you what someone
*intended*; the file on the box, plus what is actually listening, plus the
permissions on the directory, tell you what is *true*. Only an agent on the
host can see the second.

**The failure mode to avoid is the compliance checklist.** Tools in this space
tend toward hundreds of CIS benchmark items, most irrelevant to a four-person
team on a single VPS, delivered as an undifferentiated report. That output does
not get read. This subsystem should check a small number of things that have
actually caused breaches, and rank them by whether they are *reachable* — an
exposed `.env` in a served directory is an emergency; the same file outside any
web root is a tidiness issue.

## Goals

- The handful of misconfigurations that most often lead to compromise are
  detected on a running server, with the specific file or setting named.
- **Findings are ranked by reachability**, not by benchmark severity. What is
  exposed to the network outranks what is merely untidy.
- Each finding states the **fix**, not just the rule — a config finding without
  a remediation line is an interrupt.
- Low enough volume that the output is read. A first run should produce a short
  list, not a compliance report.
- **Honest scope.** The subsystem states plainly that it is not a CIS benchmark
  tool, so nobody mistakes a clean result for compliance certification.

## Non-Goals

- **Not a CIS/STIG benchmark implementation.** Hundreds of controls scored for
  an audit is a different product with a different buyer.
- **Not compliance certification.** SOC2/HIPAA/PCI reporting is listed in
  `PRD.md` as a separate marketplace module (`compliance-reporter`).
- **Not automatic remediation.** Changing a webserver config or a file mode on a
  running production host, unattended, is how a monitoring agent causes the
  outage it was bought to prevent. Report and explain.
- **Not secret detection or dependency scanning** — those are `secrets/` and
  `deps/`. A `.env` file's *exposure* is this subsystem's finding; its
  *contents* are `secrets/`'s.
- **Not full webserver config parsing.** nginx and Apache configuration
  languages are large; targeted checks for known-dangerous directives are in
  scope, a general parser is not.

## Users

- **Solo founders and small teams** deploying to a VPS by hand, who have never
  run a hardening checklist and would not read a 300-item one. Primary persona.
- **Platform/ops engineers** verifying that a fleet still matches its intended
  posture after months of manual changes.
- **Incident responders** enumerating what was reachable at the time of a
  compromise.

## Requirements

### Detect — exposure

- R1 [P0] **Sensitive files inside a web root.** `.env*`, `.git/`, `*.sql`,
  `*.bak`, `*.log`, `.htpasswd`, `id_rsa`, `docker-compose.yml`,
  `package-lock.json` under a directory that a running webserver serves.
  Highest-value check in the subsystem: it is how a large share of small-site
  breaches begin.
- R2 [P0] **Web root inference.** Read nginx/Apache config for `root`/
  `DocumentRoot`, and fall back to conventional locations (`/var/www`,
  `/usr/share/nginx/html`, `/srv/www`). When the root cannot be determined,
  say so — an unknown root must not read as "nothing exposed".
- R3 [P1] **Directory listing enabled** (`autoindex on`, `Options +Indexes`).

### Detect — services and permissions

- R4 [P0] **Dangerous file modes** on sensitive paths: world-writable
  directories in a deploy path, `.env` or key files readable by others,
  `authorized_keys` group-writable.
- R5 [P1] **Services bound to all interfaces** where a loopback binding is
  almost certainly intended — databases, caches, admin ports.
- R6 [P1] **Default or empty credentials** in config files for common services
  (`postgres/postgres`, `root` with no password, `admin/admin`).

### Detect — application and container

- R7 [P0] **Debug mode in production**: `NODE_ENV` not `production` alongside a
  production marker, `DEBUG=true`, `APP_DEBUG=true`, Django `DEBUG = True`,
  Rails `config.consider_all_requests_local = true`.
- R8 [P0] **Container escapes waiting to happen**: `privileged: true`, the
  Docker socket bind-mounted into a container, `network_mode: host`,
  `--cap-add=SYS_ADMIN`, a container running as root with a writable host mount.
- R9 [P1] **Permissive CORS**: `Access-Control-Allow-Origin: *` combined with
  `Allow-Credentials: true` — individually defensible, together a
  vulnerability.
- R10 [P1] **Missing security headers** on a served application (HSTS, CSP,
  `X-Content-Type-Options`). Low severity by design; these are hardening rather
  than holes.

### Report

- R11 [P0] **Every finding carries a remediation line.** "Move `.env` outside
  `/var/www/html`, then rotate anything it contained" — not "CIS 3.4.1".
- R12 [P0] **Reachability ranking**: `exposed` (network-reachable) outranks
  `local` (needs host access) outranks `hardening` (defence in depth).
- R13 [P1] Dedupe per (check, path) so a long-standing misconfiguration alerts
  on discovery and on change, not every scan.
- R14 [P1] `threatcrush code-scanner config audit` one-shot, exit non-zero above
  a threshold.

## UX Notes

Ships as the `config` subsystem of `code-scanner`, configured under `config_*`.

```bash
threatcrush code-scanner config audit
threatcrush code-scanner config audit --json
threatcrush code-scanner config checks      # every check, with what it looks at
```

```toml
[code-scanner.config]
enabled = true
web_roots = []              # empty: infer from webserver config, then conventions
check_permissions = true
check_containers = true
min_reachability = "local"  # exposed | local | hardening
```

```
[CRITICAL] code-scanner · config · environment file inside a served directory

  /var/www/html/.env          reachability: exposed
  nginx serves /var/www/html (site: app.example.com)

  Anyone who requests /.env receives this file, including whatever
  credentials it holds.

  Fix: move it above the web root, or add a location block denying dotfiles.
       Then rotate every credential it contained — assume it was read.
```

Design constraints:

- **Lead with reachability**, because that is what determines whether this is a
  tonight problem or a Friday problem.
- **State the fix and its follow-through.** Moving an exposed `.env` is not
  sufficient; the credentials must be rotated, and operators routinely miss the
  second half.
- **Keep the check list short and defensible.** Every check should be traceable
  to a way servers actually get breached.

## Success Metrics

- **Zero findings** on a correctly configured host: app outside the web root,
  no debug flags, sane permissions. The acceptance test for staying enabled.
- **100% detection** of a fixture host carrying one instance of every P0 check.
- Every finding in the fixture set has a remediation string; asserted by test,
  because a rule added without one is the beginning of the checklist failure
  mode.
- **Web-root inference correctness** ≥95% on a corpus of real nginx/Apache
  configs; when inference fails the subsystem reports `unknown` rather than
  assuming nothing is exposed.
- Median ≤3 findings per host on a maintained server.

## Risks & Open Questions

- **Web-root inference is the weakest link.** Every check in R1 depends on
  knowing what is served, and real nginx configs use includes, variables,
  regex locations and per-vhost roots. Getting this wrong in the safe direction
  (reporting `unknown`) costs a missed finding; getting it wrong in the unsafe
  direction (assuming a root that is not served) produces confident false
  alarms about files nobody can reach. **Open:** should the subsystem verify by
  actually requesting the path from localhost, rather than inferring? That is
  far more accurate and means the security agent making HTTP requests to its own
  host — which needs thought before it is a default.
- **Permission checks are noisy on shared hosts** where group-writable
  directories are intentional. Ranking, not suppression, plus a path allowlist.
- **Container checks need Docker access**, which is itself a privilege boundary.
  Reading `docker-compose.yml` from disk is safe; querying the daemon is not
  equivalent and should stay opt-in.
- **Scope creep toward the checklist is the standing risk.** Every new check is
  individually defensible, and 200 of them make the output unreadable — the
  outcome this PRD exists to avoid. **Open:** should the subsystem cap itself,
  requiring a check to be retired when one is added?
- **A clean result must not read as compliance.** Operators will screenshot this
  for customers. The output should state that it is a targeted check set, not an
  audit.
