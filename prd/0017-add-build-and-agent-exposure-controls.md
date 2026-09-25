---
openprd: "0.3"
id: "0017"
title: "Add build and agent exposure controls to ThreatCrush Surface"
status: Draft
authors:
  - anthony@profullstack.com
owner: anthony@profullstack.com
repo: profullstack/threatcrush
created: "2026-09-12"
updated: "2026-09-12"
discussion: "https://www.reddit.com/r/ArtificialInteligence/s/KyfL0zQhrC"
implementation: null
tags:
  - surface
  - build-security
  - agent-guard
  - supply-chain
  - cache-isolation
  - openstack
  - moshcode
  - chovy
supersedes: null
superseded-by: null
---

# Add build and agent exposure controls to ThreatCrush Surface

**Product:** ThreatCrush Surface — Build & Agent Exposure.
**Delivery:** An extension of ThreatCrush, not a separate security product.
**Decision state:** Proposed requirements; not a claim that these controls already ship.
**OpenStack interpretation:** This document treats “OpenStack” as the OpenStack cloud infrastructure platform. It retains the Profullstack application stack and adds an explicit OpenStack deployment and isolated-runner profile. OpenStack is not a PRD standard or a replacement for Node.js, Next.js, or PostgreSQL.
**Repository placement:** `prd/0017-add-build-and-agent-exposure-controls.md`. The repository index inspected for this draft ends at `0016`; recheck the actual directory and renumber the file and manifest together if another proposal lands first. No repository changes or infrastructure provisioning are performed by this document.

## Problem

ThreatCrush needs to answer a question that ordinary endpoint inventories and source-pattern scanners do not answer on their own:

> What can this build service or AI agent execute, which credentials can it reach, and where can it send or publish the result?

An untrusted package, documentation hook, pull request, or agent-generated change can enter a legitimate workflow. The workflow may then execute code with more authority than its task requires. A domain allowlist cannot express the difference between downloading a dependency and publishing a new package to the same registry. A warning from a scanner is not an enforcement boundary. An agent that can edit its own security policy or suppress its own findings can undermine a review without changing the application’s apparent functionality.

A related exposure exists at the application/CDN boundary: authenticated responses may not remain isolated between users under every response-compression path. RubyGems’ published advisory describes a legacy-key exposure that was conditional on gzip requests; an ordinary request without that header did not reproduce the issue. This motivates testing identity isolation and compression together, rather than treating headers from one response as proof of safety. [S5]

This proposal follows the preceding discussion of package-build abuse. It does not establish who authored any incident, prove that reported exploitation succeeded, or claim that ThreatCrush would have prevented an historical attack. The release must demonstrate its own controls against controlled fixtures.

### Existing foundation and boundaries

The inspected repository documents a Next.js web/API application, CLI/daemon, terminal UI, Electron desktop client, and shared SDK in one pnpm monorepo. Its scanning documentation describes static source/dependency-manifest checks, Ruby support, JSON/SARIF output, suppression reporting, and explicit confidence limits. These are documented integration points, not an independent production audit. [S1][S2]

Extend those foundations rather than creating a second scanner, tenant system, alert pipeline, or daemon. The existing numbered proposals cover dependencies, secrets, code patterns, configuration, networking, DNS, containment, and authorized active testing. Their presence and Draft status do not establish implementation. [S3]

There is a material compatibility issue: Draft PRD `0016`, requirement R3, rejects shared-CDN targets. This proposal needs tightly scoped testing through a customer’s own CDN distribution. Adoption therefore requires an explicit, reviewed amendment to that restriction. Until that amendment is accepted, CDN-path tests stay disabled; no undocumented override is allowed. [S4]

## Goals

1. Show evidence-backed paths from untrusted input to executable hooks, sensitive authority, and external publication, including what remains unknown.
2. Verify cross-user cache isolation using synthetic identities and harmless markers on explicitly authorized targets.
3. Let operators grant agents only the actions needed for an assigned job, with enforcement outside the agent’s writable environment.
4. Separate dependency retrieval, code execution, and artifact publication so a build worker does not inherit publishing credentials.
5. Support isolated execution on OpenStack without requiring existing ThreatCrush users to migrate their control plane or infrastructure.
6. Provide consistent CLI, API, MCP, mobile-first PWA, and desktop workflows with reusable machine-readable evidence and retests.
7. Demonstrate bounded protection through reproducible tests, clear coverage states, and measurable operational behavior—not claims of perfect security.

## Non-Goals

- Rebuilding ThreatCrush, introducing another product/domain, or replacing existing authentication and tenancy as a side effect of this feature.
- Deploying or operating an OpenStack cloud from bare metal. The OpenStack profile consumes an operator-provided cloud and approved resources.
- A full cloud-security-posture suite, universal DAST platform, or replacement for a manual penetration test.
- Proving whether an action was generated by a human or AI; reading model thoughts; or making semantic intent detection an authorization dependency.
- Executing suspicious packages on an operator workstation, publishing test malware to public registries, harvesting real credentials, or scanning unowned infrastructure.
- Arbitrary Internet access for guarded jobs, generic TLS interception, or claiming that a port firewall understands package-publishing semantics.
- Guaranteed prevention of every covert channel, malicious behavior inside an approved artifact, kernel escape, compromised hypervisor, or compromised trusted administrator.
- A wholesale database migration, a Turso/SQLite backend for new shared write-heavy data, or a mandatory managed Supabase dependency for the new module.
- New native mobile applications or browser-extension features as a v1 release blocker. Mobile-first PWA is required; existing desktop integration is required at the shared-contract level.
- Automatic source edits, production firewall changes, key revocation, or package yanking merely because a scanner reports a suspected issue.

## Users

| User | Job to be done | Primary interface |
| --- | --- | --- |
| Founder or developer using moshcode/Chovy | Let an agent work without giving it unrestricted publishing or infrastructure authority | CLI, MCP, PWA |
| Platform or DevSecOps engineer | Discover risky build paths and enforce a repeatable release boundary | CLI, CI, API |
| Security operator | Review evidence, approve a specific sensitive action, contain an affected session, and verify remediation | PWA, desktop, TUI |
| OpenStack operator | Provide bounded, disposable workers without granting workloads cloud-management credentials | API, deployment configuration |
| Module/integration developer | Add an analyzer or registry adapter without inventing a different finding or approval format | SDK, contracts, fixtures |

A person’s application role and OpenStack role are separate. A ThreatCrush tenant administrator does not automatically receive OpenStack administrator privileges.

## Requirements

### Priority and implementation convention

`[P0]` requirements are release gates for the capability they govern. v1 is complete only when all P0 gates pass. `[P1]` items may follow without weakening the P0 baseline. `[P2]` items are explicitly later enhancements. Each `R#` is one independently tracked requirement; the elaborations below provide acceptance details.

### Surface discovery and trustworthy scanning

- R1 [P0] Extend the existing ThreatCrush scanner, finding model, property/tenant model, and alert integrations rather than shipping parallel equivalents.
- R2 [P0] Enforce tenant- and role-scoped authorization for every asset, scan, credential reference, policy, approval, event, and artifact operation.
- R3 [P0] Inspect untrusted source and package metadata without executing project code, build hooks, dependency installers, or configuration evaluators.
- R4 [P0] Bound archive and source parsing against traversal, symlink escape, decompression bombs, excessive nesting, file-count exhaustion, and parser resource exhaustion.
- R5 [P0] Discover supported executable hooks and their execution context across Node.js package workflows, Ruby package/documentation workflows, Python build metadata, CI configuration, and declared container/service configuration.
- R6 [P0] Produce evidence-backed exposure paths linking untrusted input, executable hooks, execution identity, credential references, network destinations, and publication authority.
- R7 [P0] Distinguish package retrieval, package publication, ownership changes, and other external mutations in findings and policies.
- R8 [P0] Preserve the existing scanner confidence/severity contract and represent runtime verification separately from static evidence.
- R9 [P0] Evaluate untrusted contributions using a protected scanner/policy baseline and require independent review for newly introduced suppressions or weakened security settings.
- R10 [P1] Compare exposure paths between revisions and deployments to show newly introduced authority and verified remediation.

### Authorized cache-isolation verification

- R11 [P0] Require an explicit target/path scope, current ownership evidence, and an operator authorization declaration before sending active test traffic.
- R12 [P0] Keep shared-CDN testing disabled unless a reviewed amendment to PRD 0016 authorizes an exact customer hostname/distribution and synthetic test scope.
- R13 [P0] Bound cache tests by declared read-only semantics, request limits, response limits, timeout limits, cancellation, and automatic health-abort conditions.
- R14 [P0] Exercise independent synthetic identities and anonymous/invalid-auth controls across explicitly controlled response-encoding variants.
- R15 [P0] Confirm cache-isolation failures only when a synthetic identity-specific marker crosses the expected identity boundary under a reproducible test sequence.
- R16 [P0] Capture a redacted, reproducible wire-request/response summary with actual encoding, identity aliases, cache indicators, route, and execution vantage.
- R17 [P0] Report incomplete, unsupported, denied, and failed checks distinctly from completed checks with no observed issue.

### Agent Guard and publication control

- R18 [P0] Expose separate observe and enforce modes, with enforce mode available only after a runner capability and isolation self-test succeeds.
- R19 [P0] Store and enforce policy outside the agent’s writable filesystem, identity, process boundary, and configuration authority.
- R20 [P0] Authorize normalized actions against versioned, deny-by-default capabilities rather than command-name matching or model judgments.
- R21 [P0] Bind each sensitive-action approval to its tenant, session, action, target, immutable artifact, policy version, expiry, and single-use authorization record.
- R22 [P0] Require guarded workloads to use approved network and action gateways, with no unrestricted direct route that bypasses publication policy.
- R23 [P0] Keep registry and infrastructure credentials in a trusted broker that executes approved actions without exposing those credentials to the workload.
- R24 [P0] Verify the exact artifact and request digest at execution time so content or destination changes invalidate an approval.
- R25 [P0] Provide moshcode and Chovy integration contracts that attribute actions to a guarded local or remote execution session without granting the agent approval authority.
- R26 [P0] Contain a guarded session through revocation and runner control, tracking observed completion separately from a requested stop.
- R27 [P0] Fail closed for new sensitive actions during policy, approval, audit, or gateway failures while keeping unguarded workloads unaffected.
- R28 [P0] Record security decisions and enforcement outcomes in a redacted audit trail outside the workload’s deletion authority.
- R29 [P0] Isolate analyzers and runner agents from control-plane secrets and authenticate their communication through scoped, revocable identities.

### OpenStack deployment and runner profile

- R30 [P0] Support deployment of the existing control-plane application and new workers on an operator-provided OpenStack cloud without requiring cloud-wide administration.
- R31 [P0] Use separate, scoped OpenStack application credentials for inventory and runner lifecycle operations, with no cloud-management credential accessible inside an untrusted job.
- R32 [P0] Verify effective worker ingress/egress isolation, including IPv4, IPv6, metadata access, and additive security-group rules, before enabling enforcement.
- R33 [P0] Provision disposable, quota-bounded workers with leases and idempotent cleanup of resources created for the job.
- R34 [P0] Discover OpenStack service endpoints and supported API capabilities and report unsupported or insufficiently verified controls without a protected-status claim.

### Interfaces, storage, operations, and delivery

- R35 [P0] Provide one versioned API/SDK contract for discovery, verification, findings, policy simulation, action requests, approvals, sessions, and containment.
- R36 [P0] Expose the P0 workflows through CLI commands with text/JSON output, appropriate SARIF export, stable exit behavior, and noninteractive-safe authentication.
- R37 [P0] Expose scoped MCP tools for inspection and requesting permitted actions while excluding approval and policy-elevation authority from agent credentials.
- R38 [P0] Provide a mobile-first PWA review/approval experience and shared SDK/IPC support for the existing desktop client.
- R39 [P1] Add dedicated exposure and guarded-session views to the existing TUI and desktop presentation layers without rebuilding their application shells.
- R40 [P0] Store new shared operational data in self-hosted PostgreSQL while preserving existing account/tenant compatibility and avoiding a new shared SQLite/Turso dependency.
- R41 [P0] Make queued work, action execution, and audit persistence resilient to retries, duplicate delivery, crashes, and uncertain external outcomes.
- R42 [P0] Deliver deduplicated alerts for confirmed exposure, denied sensitive actions, degraded enforcement, and incomplete containment with links to redacted evidence.
- R43 [P0] Support scoped retesting and close findings only when the relevant check completes with adequate coverage and no reproduced issue.
- R44 [P0] Ship isolated positive, negative, bypass, failure, and regression fixtures mapped to the requirement IDs and safety boundaries.
- R45 [P0] Publish capability-accurate documentation and product claims that distinguish configured, observed, verified, enforced, and unsupported behavior.
- R46 [P0] Integrate the accepted proposal into the repository’s OpenPRD index and preserve traceability from requirements to implementation changes and tests.
- R47 [P0] Apply explicit resource and customer-spend budgets before starting hosted jobs, without disabling existing local protection when billing fails.
- R48 [P0] Keep source, raw credentials, and sensitive response bodies customer-side by default, with explicit data handling and retention controls for any uploaded evidence.

### A. Discovery contract and first rule pack — R3–R10

Start with repository files and operator-authorized local configuration. Optional OpenStack inventory supplies instance, image, network, and project context; it does not authorize reading arbitrary guest files. A guest collector is separately enrolled and scoped.

Supported v1 inputs include `package.json` lifecycle scripts and relevant lockfiles; `.gemspec`, Gemfile/lockfile, Rake/documentation configuration; `pyproject.toml` and statically readable Python build configuration; GitHub Actions workflows; Dockerfiles/Compose; and explicitly selected service definitions. Dynamic Ruby and Python configuration is inspected as source, never evaluated to obtain metadata. Unknown dynamically assembled behavior is reported as unresolved.

| Proposed rule ID | What is evaluated | Evidence required and claim boundary |
| --- | --- | --- |
| `build.untrusted-hook` | Untrusted content introduces an automatically invoked hook | Source location plus runner/trigger configuration; a hook alone is not proof of malicious behavior |
| `build.secret-reachability` | A hook-capable workload is assigned sensitive credential access | Secret reference, mount/env assignment, identity and scope; no secret value collected |
| `build.publish-authority` | A worker has publication authority although the declared task is read/build-only | Task declaration and verified credential/policy metadata; unknown scope stays unknown |
| `build.unrestricted-egress` | A guarded build can reach destinations outside its required retrieval/action gateways | Effective network configuration plus controlled egress probe when authorized |
| `build.mutable-security-baseline` | A contribution changes scanner rules, exclusions, CI gates, or suppressions | Protected-base versus proposed-change diff, with approver provenance |
| `registry.unapproved-action` | A session attempts publication or another external mutation without matching approval | Broker decision with normalized action and target; do not infer solely from a process name |
| `cache.cross-principal-marker` | One test principal receives another principal’s private marker | Repeated response evidence and controls from the declared route and encoding matrix |
| `guard.policy-bypass` | A job can reach a protected action without its gateway | Self-test/fixture evidence; enforcement becomes degraded or unavailable |

Represent the path as linked records: `input → hook → runner identity → permission/credential reference → destination/action`. Every edge includes its evidence origin, timestamp, revision, and verification state. Do not draw a confirmed path through an unknown edge.

Reuse the existing `pattern`, `contextual`, and `evidence` confidence meanings; do not raise a bare pattern above its documented medium-severity cap. Add separate fields such as `verification.status` and `enforcement.status` rather than redefining source confidence. No weighted “risk score” may erase unknown coverage. [S2]

Parsing limits are explicit job inputs with safe defaults: maximum archive bytes, decompressed bytes, files, nesting depth, per-file size, CPU time, and memory. Reject escaping paths and unsafe links before extraction. Analyze a staged read-only snapshot, not a writable live checkout that an agent can alter during inspection.

### B. Cache test protocol — R11–R17

The operator supplies an owned hostname, exact route, synthetic test accounts A and B, and a harmless response field containing distinct private markers. Authentication material is supplied by secret reference, not CLI argument or committed YAML. The route must use the actual relevant auth/compression/cache configuration; testing a separate diagnostic handler without configuration equivalence does not establish protection for production routes.

For each supported encoding, establish direct baselines for A, B, anonymous, and invalid authentication; then run A-primes/B-reads and B-primes/A-reads sequences, with anonymous and invalid-auth follow-ups. Use independent cookie jars. Compare identity markers and expected visibility, not equality of entire pages or HTTP status alone. Run at least two controlled cycles before a confirmed cross-principal finding.

The initial matrix covers absent `Accept-Encoding`, explicit `identity`, and `gzip`; include `br` only when negotiated and supported. Use an HTTP transport that can control the actual wire headers and decoding behavior; do not assume a high-level client sends what its options appear to request. Decode responses once, enforce both compressed and decompressed byte limits, and preserve the observed content-encoding metadata.

Keep the same cache key across the principals within a cycle. A cache-busting parameter unique to each identity would hide the flaw. A run-scoped test path or fixture namespace may isolate harmless test traffic, but must remain constant during that cycle and must be declared representative of the target cache configuration. Never prime shared caches with real customer secrets. Cleanup is limited to the declared synthetic namespace; no broad CDN purge.

Default limits: one request/second/hostname, at most two concurrent requests, 96 requests per route and 512 per run, 10-second request timeout, 2 MiB compressed and 8 MiB decoded response limits. Budget exhaustion yields partial coverage, not a pass. Abort on explicit cancellation, unexpected state mutation, credential lockout signals, or three consecutive target `5xx` responses; also abort when `5xx` exceed 20% of a rolling 20-request window. Honor `Retry-After` and stop rather than repeatedly challenging authentication.

Only explicitly declared read-only routes are eligible. HTTP GET is not evidence that a route is side-effect-free. Key-generation/sign-in routes that create credentials are excluded from default active testing; reproduce those semantics with a synthetic staging fixture under separate permission. Never automatically send PUT, DELETE, package-publish requests, or mutating login retries.

For CDN targets, verify and address the exact customer hostname with correct TLS/SNI and Host handling. Never scan the shared edge IP as an asset. Revalidate DNS destinations and redirects, prevent rebinding into forbidden networks, and strip credentials on any origin change. Internal targets require an enrolled internal runner and separate scope; cloud metadata, control-plane management endpoints, and unrelated tenants are forbidden. Operator attestation must cover provider permission, not merely domain control.

A confirmed result is evidence that a marker crossed an identity boundary. Missing cache headers, an `Age` header, identical public content, or absence of `Vary: Authorization` alone does not prove a leak. A completed negative run means “not reproduced in these identities, variants, routes, and vantage points,” not “all CDN nodes are safe.” Header-only observations remain posture findings. [S5]

### C. Agent Guard trust boundary — R18–R29

The trusted boundary comprises the supervisor, policy evaluator, action/publication broker, isolated runner controller, and audit writer. The model, prompts, repository, build hooks, retrieved documents, subprocesses, and generated artifacts are untrusted. Scanner output and third-party tool text never grant authority.

A guarded job receives a stable tenant, session, task, and runner identity. Policy defines permitted filesystem roots, retrieval sources, action types, target resources, data classifications, duration, and resource limits. A developer or agent may request a capability; only an independently authenticated authorized person or preapproved organizational policy may grant it.

Proposed action vocabulary: `dependency.read`, `workspace.read`, `workspace.write`, `test.run`, `pull_request.create`, `package.publish`, `package.owner_change`, `infrastructure.change`, and `account.create`. Unknown actions are denied. v1 implements Node/npm and RubyGems retrieval/publication adapters and GitHub pull-request creation where authorized; Python is initially static build inspection and read-only retrieval. Unsupported publishing adapters remain denied rather than using generic unrestricted HTTP.

The broker normalizes an action into a canonical manifest. An approval binds at least: tenant, requester, session, job, action, registry/repository, package name/version or target resource, artifact SHA-256, request digest, policy version/epoch, maximum size, expiry, and a single-use identifier. Step-up authentication is required for high-risk approvals. The agent cannot approve its own request, replay it into another session, or apply it after policy revocation.

The trusted broker—not the workload—submits an approved package. It checks immutable bytes immediately before sending and verifies that package metadata matches the approved manifest. It never accepts a mutable workspace path as proof that previously approved bytes are still present. Registry credentials are narrowly scoped and short-lived when supported; persistent credentials remain broker-side with rotation and explicit limitations. Signing an artifact is not proof that its contents are harmless.

All guarded job traffic goes through approved retrieval, model, artifact, or action gateways. A dependency gateway exposes a constrained retrieval interface; it is not a general proxy to all paths on an approved host. Shell commands, embedded HTTP clients, child processes, direct registry APIs, IPv6, UDP/QUIC, custom DNS, and alternate proxy paths must not bypass the boundary. Validate requested hosts and redirect destinations and prevent arbitrary CONNECT tunneling. Do not claim URL/action inspection of opaque HTTPS traffic at the network layer.

Approved model calls, stdout, logs, pull requests, and artifacts are also output channels. Assign data-handling rules and output-size limits to them. Do not make sensitive files readable to a job whose allowed output channel would expose them. v1 bounds named channels and credentials; it does not claim universal prevention of covert encoding or all unwanted disclosure through otherwise approved content.

For moshcode/Chovy, adapt existing execution/session management after inspecting those implementations. Preserve persistent remote sessions where available; attach a stable guard session identity rather than spawning an unrelated remote login per file. Enforcement must be installed at the execution host or isolated runner. A remote session without a trustworthy enforcement point is observe-only and cannot be labeled protected. These adapters are proposed contracts, not verified existing integration features.

Containment immediately denies new broker actions and revokes session authorization, then asks the supervisor to terminate the session process tree and revoke its network path. The UI tracks `containment_requested`, `containment_in_progress`, `contained`, `partially_contained`, or `containment_failed`. A successful cloud API request alone does not prove that existing connections stopped. Verify gateway closure, local process state, and runner state where available. Contain only enrolled job resources, not the user’s unrelated host or production workload.

When control-plane connectivity is lost, a signed cached policy may continue only already permitted nonsensitive local computation for a bounded lease. Sensitive external mutations require an online atomic decision and durable audit write. Expired leases, unhealthy enforcement, full audit spool, or unknown session identity deny new sensitive actions. Broker crashes must not release credentials or silently downgrade enforce mode.

### D. OpenStack profile — R30–R34

Use an existing OpenStack deployment with an operator-approved project, region, image, flavor, network, and resource budget. Required service capabilities are Keystone authentication/catalog, Nova compute lifecycle, Neutron networking/security groups, and an approved image source. Persistent control-plane storage uses the operator’s persistent-volume service; Cinder is the reference OpenStack mapping. Swift, Barbican, Octavia, Heat, and Kubernetes are not mandatory module dependencies.

Two deployment profiles are supported: an existing ThreatCrush control plane with OpenStack workers, or the same containerized control plane plus workers hosted on OpenStack. Provide documented operator-managed deployment configuration; do not put cloud bootstrap or cloud-wide network administration in the application.

OpenStack documentation supports project-scoped application credentials and delegated role subsets. Additional access-rule enforcement depends on service configuration. Therefore, this design requires negative capability tests before claiming least-privilege enforcement; a role label alone is insufficient. [S6]

Keep inventory and lifecycle identities separate. The inventory identity is read-only. The lifecycle identity can operate only within a dedicated runner project and approved resources. No administrator password, `admin` role, unrestricted self-replicating application credential, or cloud token is passed into an untrusted workload. Supported lifecycle access must be verified against the actual cloud’s policies; an application-side tag filter is not a cloud authorization boundary.

The operator provisions the required project boundaries. Hosted deployments use separate runner projects for mutually untrusted customer tenants by default. A single-customer self-hosted deployment may use one dedicated runner project with per-job network/resource isolation. No runner project contains production workloads. The broker checks its own tenant-to-project mapping independently of caller input.

For each job, boot an ephemeral Nova VM from a pinned, approved image, with no floating IP, no public inbound access, and egress only to necessary controlled gateways. Containers may run inside that VM for packaging; they do not replace the VM boundary for mutually untrusted hosted jobs. Read-only inputs and a scoped output channel replace shared host mounts. No host Docker socket, production disk, cloud-management credential, or general SSH agent is exposed.

Neutron security groups are additive and commonly begin with egress permissions. Inspect every attached group and effective rule, remove unwanted defaults only from dedicated job-owned groups, and verify IPv4/IPv6 behavior. Never assume “a restrictive group is attached” cancels a permissive group. Layer-3/4 controls constrain reachability; the trusted broker still decides application actions. [S7]

Account for DHCP, DNS, time synchronization, and enrollment explicitly. Complete controlled boot/enrollment before executing untrusted code. Block job access to metadata and management services; never place long-lived secrets in user-data or config-drive. Short-lived enrollment material is single-use and consumed before workload launch. Verify that no reachable alternate metadata address or management route remains.

Worker leases include a maximum runtime, concurrency, CPU, memory, disk, and outbound-byte budget. The controller tags owned resources, records provider IDs durably, and reconciles incomplete operations after crashes. A reaper cleans expired job-owned VMs, ports, disks, and temporary grants. Missing permission or quota exhaustion yields a specific non-started/partial state, not a retry storm. Nova quotas provide a resource ceiling but are not a financial invoice or a complete per-job spend limit. [S8]

Discover service URLs through the catalog and negotiate only required supported API capabilities. Pin the tested cloud image, component versions, API ranges, and network-driver behavior in the release compatibility matrix; do not advertise support for every OpenStack release. Partial service inventory remains partial. An inaccessible service is not an empty inventory. [S9]

### E. Shared entities and state — R35–R48

The following are logical entities. Reuse existing tables and identifiers where their semantics fit; exact migration/table names follow the repository audit.

| Entity | Required information |
| --- | --- |
| Asset/exposure edge | Tenant, stable resource ID, type, source revision, evidence reference, observed time, completeness |
| Scan run | Authorized scope, actor, runner, rule version, request/resource budgets, coverage summary, status |
| Finding | Existing finding fields plus path references, confidence, verification state, remediation, fingerprint |
| Cache case | Synthetic identity aliases, encoding, route, controlled sequence, vantage, redacted marker evidence |
| Policy version | Tenant, immutable document/hash, author, reviewer, lifecycle, effective time, revocation epoch |
| Guard session | Task, runner identity, allowed capabilities, lease, observe/enforce state, health, containment state |
| Action/approval | Canonical manifest digest, approver, scope, one-use ID, expiry, execution state, external receipt |
| Audit event | Tenant/session/job, actor, normalized action, decision/reason, policy version, artifact hash, outcome |
| Worker resource | Provider/project/region, resource IDs, desired/observed states, owner, lease, cleanup state |

Use PostgreSQL transactions and uniqueness constraints for action claims and single-use approvals. Redis/BullMQ delivery is at-least-once; it is not the authority for approvals, completed billing, or authorization. Use a transactional outbox/inbox or an equivalent tested pattern for events.

External publication is not assumed exactly-once. After a timeout with an uncertain outcome, mark `outcome_unknown` and reconcile the registry’s recorded package/version/artifact before retrying. Do not blindly replay a publish or bill twice. Each job and usage event has an idempotency key. If the external system cannot establish the artifact identity safely, require operator review.

State dimensions remain separate: job execution (`queued/running/completed/failed/cancelled`), coverage (`complete/partial/unsupported/denied`), finding verification (`untested/reproduced/not_reproduced/inconclusive`), and enforcement (`observe/starting/enforced/degraded/stopped`). Zero findings with a failed scan is never green.

Use append-only audit records under a separate write role. Optional hash chaining and signed checkpoints can make edits detectable; they are not protection against an administrator who controls all keys and storage. A customer-controlled destination can receive checkpoints/exports. Default retention proposal: operational events 30 days, redacted finding evidence 90 days, minimal approval/action records 90 days; make retention tenant-configurable and document any longer contractual requirement. Raw tokens, response secrets, and model chain-of-thought are never audit fields.

### F. Acceptance and abuse-case matrix — R44

All fixtures use synthetic data and private/local registries or stub endpoints. No acceptance test sends malicious packages, harvested credentials, or exploitation traffic to a public third party.

| Test | Requirements | Passing result |
| --- | --- | --- |
| T01: Scanner reuse and compatibility | R1, R8 | Existing scan fixtures/output contracts still pass; bare-pattern severity cap remains intact |
| T02: Cross-tenant resource references | R2, R35, R40 | Another tenant’s IDs, approval records, artifacts, and worker IDs cannot be read or acted on |
| T03: Executable metadata and unsafe archives | R3–R5 | Parsing does not execute hook sentinels; traversal/bomb fixtures stop within declared limits |
| T04: Real versus inferred authority | R6–R8 | Unknown credential scope is not called verified publication authority; evidence links remain traceable |
| T05: Agent suppresses its own findings | R9 | New exclusions, ignore files, inline suppressions, or modified scanner configuration require independent approval |
| T06: Unverified targets and rebinding | R11–R13 | No active probes reach unverified paths, metadata services, redirected third parties, or another tenant |
| T07: Shared-CDN amendment absent/present | R12 | Disabled before accepted policy change; afterward limited to the verified synthetic hostname/path scope |
| T08: Gzip-only cache leak | R14–R16 | Synthetic cross-user marker is reproduced under gzip; uncompressed success does not conceal it |
| T09: Safe shared public response | R15 | Equal public responses or absent `Vary` alone do not become a confirmed secret leak |
| T10: Independent identities and reverse order | R14–R16 | A→B and B→A cycles use separate sessions and one stable cache key per cycle |
| T11: Unsupported encoding, timeout, lockout, budgets | R13, R17 | Coverage becomes partial/inconclusive and health abort stops new probes; no clean verdict |
| T12: Read-only declaration violated | R13 | Side-effectful synthetic endpoint causes an abort and explicit incident record |
| T13: Guard absent or weak isolation | R18, R19, R29 | Observe mode works, but enforce/protected claims are refused |
| T14: Shell/direct-HTTP/network bypass | R20, R22, R32 | Child clients, direct registry APIs, alternate DNS, IPv6, and unauthorized UDP paths cannot bypass gateways |
| T15: Self-approval, stale approval, replay | R21, R37 | Agent tokens cannot approve; cross-session/expired/revoked/used approvals cannot execute |
| T16: Change artifact after approval | R24 | Any artifact, package metadata, registry, or canonical request change invalidates the authorization |
| T17: Approved publication | R7, R23, R24 | Correct immutable artifact is published once through the broker; workload never sees the credential |
| T18: Remote moshcode/Chovy session | R25 | Stable session/action attribution persists; missing remote guard prevents enforce mode |
| T19: Active-connection containment | R26, R32 | New actions stop and existing fixture connection/process is terminated or explicitly reported unresolved |
| T20: Policy/control-plane/audit outage | R27, R28 | New sensitive actions fail closed; healthy unrelated workloads are unchanged; no audit loss is hidden |
| T21: OpenStack least privilege | R30, R31, R34 | Lifecycle identity cannot access another project, mutate production resources, or grant itself credentials |
| T22: Additive security groups and metadata | R32 | Permissive attached groups and alternate metadata paths fail the preflight; no workload starts enforced |
| T23: Nova timeout, duplicate job, controller restart | R33, R41 | Existing owned resources are reconciled, not duplicated blindly; expired resources are eventually cleaned |
| T24: Quota, cloud/API outage, missing service | R33, R34, R47 | Bounded retries and explicit partial/unsupported states; no runaway job or invented empty inventory |
| T25: Interface parity and output safety | R35–R39 | CLI/API/MCP/PWA share authorization and states; JSON stdout stays parseable; desktop bridge does not bypass scopes |
| T26: Action timeout after external success | R41 | Outcome is reconciled before replay; no duplicate publish/charge from at-least-once delivery |
| T27: Alerts, fix, and retest | R42, R43 | Deduplicated evidence-backed alert links to a finding; closure needs a completed relevant retest |
| T28: Redaction and retention | R28, R48 | Synthetic secret sentinels never enter exports/logs; expiry/deletion rules and role separation are exercised |
| T29: Billing failure or exhausted credits | R47 | New hosted jobs stop at the budget; existing local guard and operator containment still work |
| T30: Fixture manifest, documentation, and OpenPRD integration | R44–R46 | The fixture manifest maps every P0 requirement to verification; commands match shipped behavior; compatibility limits, requirement links, and PRD index are correct |

### G. Delivery sequence

**Milestone 0 — Baseline and decisions.** Audit repository implementation, auth/storage boundaries, daemon capabilities, and API naming. Confirm numbering. Resolve the PRD 0016 CDN restriction explicitly. Approve this draft through the OpenPRD lifecycle before claiming accepted requirements.

**Milestone 1 — Surface checks and safe verification.** Deliver static build/authority discovery, protected suppression baseline, cache protocol, evidence exports, and authorization fixtures. Label this an inspection release, not Agent Guard enforcement.

**Milestone 2 — Guarded actions.** Deliver supervisor/broker boundaries, approvals, immutable artifact publication, failure behavior, and moshcode/Chovy contracts on an enrolled Linux execution environment. Test containment rather than treating a requested stop as success.

**Milestone 3 — OpenStack and v1 release gate.** Deliver deployment assets, project-scoped workers, effective-network checks, lifecycle reconciliation, all required interfaces, and a real integration run against the declared OpenStack compatibility target. All P0 acceptance tests must pass before the full feature is marked shipped.

**Later P1 work.** Richer TUI/desktop exposure views, revision/deployment comparisons, additional registry adapters, and additional cache vantage points. Do not defer any trust-boundary check while advertising the related feature as enforced.

## UX Notes

### Navigation and onboarding

Use the existing property/organization dashboard. Proposed section: **Surface → Build & Agents**, with **Exposure paths**, **Cache isolation**, **Guarded sessions**, **Approvals**, and **OpenStack runners** views. Reuse existing navigation where these concepts already have a home.

Onboarding asks the operator to choose an owned property/repository, enroll a runner, select an observe/enforce profile, and declare permissions. OpenStack onboarding accepts a secret reference plus project/region identifiers, then shows discovery/permission/network checks. Never request credentials in chat, screenshots, or a committed configuration file.

The first page distinguishes “not configured,” “configured but unverified,” “observing,” “enforced on these runners,” and “degraded.” An asset count is not a protected-asset count. An unsupported target remains visible with a reason.

A finding detail shows the source-to-authority path, evidence confidence, verification scope, affected session/revision, remediation, and a retest action. For a suspected issue, use “Potential exposure” rather than “Exploit confirmed.” A retest cannot silently expand target scope.

### Approval flow

An agent requests a specific operation. The operator sees the artifact/name/version, destination, digest, requested authority, triggering task, expiration, and security findings. The default is deny. Approval is for that exact manifest, not “allow this agent forever.” Mobile approval requires an authenticated PWA session and step-up when required; push notifications contain no actionable bearer approval token.

A contained session shows what actually stopped and what remains unresolved. A new approval is required to resume sensitive actions; a late worker heartbeat must not resurrect a revoked session.

### Proposed CLI contract

The following commands are **new contract examples, not claims about current command availability**. Reconcile with existing command names before implementation; preserve current `threatcrush scan` behavior. Secrets are referenced by identifiers or protected files, not included on command lines.

```bash
# Static inspection only; no project code execution.
threatcrush surface build scan ./repo --format json

# Explicit verification/permission enrollment precedes active cache testing.
threatcrush surface target verify --property prop_example
threatcrush surface cache test --profile cache-staging --format json
threatcrush surface finding retest FINDING_ID --format json

# Guard self-test, policy simulation, and an enrolled execution session.
threatcrush guard doctor --runner RUNNER_ID
threatcrush guard policy simulate --policy ./policy.yaml --request ./action.json
threatcrush guard run --profile build-only -- moshcode
threatcrush guard session show SESSION_ID --format json

# Operator-only control plane operations.
threatcrush guard approval review APPROVAL_ID
threatcrush guard session contain SESSION_ID --reason "unexpected publication"

# OpenStack support; cloud credentials live in the configured secret store.
threatcrush surface openstack check --profile private-cloud --format json
```

For new inspection commands: exit `0` means completed within required coverage and no threshold finding, `1` means findings meet the configured failure threshold, `2` means execution/configuration failure, `3` means authorization or policy denial, and `4` means required coverage is incomplete/unsupported. If incomplete coverage and findings coexist, return `4` and retain findings in JSON. Existing scanner exit codes remain unchanged. `guard run` reports guard state separately from the child exit status in its machine-readable result.

### Proposed API and MCP contract

Use the existing API authentication and route conventions. The paths below show semantics; they are not a second authentication service or a claim that the routes exist.

| Operation | Proposed REST shape | MCP exposure |
| --- | --- | --- |
| List exposure paths | `GET /api/v1/surface/exposures` | `surface_list_exposures` |
| Start an authorized inspection | `POST /api/v1/surface/runs` | `surface_start_scan`, constrained by server-side scope |
| Read a run/finding | `GET /api/v1/surface/runs/{id}` | `surface_get_run` |
| Simulate a policy | `POST /api/v1/guard/policy-simulations` | `guard_simulate_action`, no grant implied |
| Request sensitive action | `POST /api/v1/guard/action-requests` | `guard_request_action`, returns approval-needed or denied |
| Review/decide approval | `POST /api/v1/guard/approvals/{id}/decision` | Not exposed to an agent credential |
| Contain a session | `POST /api/v1/guard/sessions/{id}/contain` | Operator-scoped tools only, never implicitly granted |
| Check cloud profile | `POST /api/v1/surface/openstack/checks` | Read/check scope; no implicit provisioning |

All writes use idempotency keys where relevant. Check scope server-side using the authenticated tenant, never a caller-supplied tenant ID alone. Stream status through the existing SSE/WebSocket/IPC mechanism with reconnect cursors and retention-aware gap reporting. MCP-discovered descriptions cannot modify the caller’s authority.

PWA clients may cache static UI assets, but must not cache secrets, approval tokens, or sensitive findings through a service worker. Offline mode is read-only for explicitly retained redacted summaries; it cannot approve, enroll, or claim live enforcement health.

## Tech Stack

### Application stack

| Layer | Required choice and boundary |
| --- | --- |
| Repository | Existing `profullstack/threatcrush` pnpm monorepo; use its established package/versioning conventions |
| Language/runtime | TypeScript, ESM, repository-supported Node.js; target Node 24 for new service images after compatibility tests; retain declared Node compatibility unless changed explicitly |
| Additional runtime | Bun compatibility where tested for CLI/helpers; do not make a Bun-only path a prerequisite for daemon or shared-library correctness |
| Web/PWA | Existing Next.js 16 application, React, mobile-first layouts; use shadcn/ui components for new UI rather than a replacement application shell |
| API | Existing Next.js API and auth conventions; shared typed service layer, not an unrelated Hono service added solely for this module |
| CLI/daemon/TUI | Existing ThreatCrush CLI and Linux supervisor/module architecture; reuse existing terminal components after checking the live dependency tree |
| Desktop | Existing Electron app and authenticated IPC/SDK; no new desktop framework |
| Primary new datastore | Self-hosted PostgreSQL with tenant-scoped access, migrations, backups, indexes, and separate audit-write permissions |
| Work queue | Redis + BullMQ for scheduling/retries; PostgreSQL remains authoritative for actions, approvals, and usage |
| Artifact/evidence storage | Customer-controlled persistent volumes by default; encrypted at rest where configured, bounded retention, content-addressed immutable approved artifacts |
| Local spool | Bounded supervisor-owned append-only files for offline redacted events; not a shared application database or unbounded source archive |
| Packaging/deployment | Existing Docker/Compose conventions; Linux runner/supervisor on approved Ubuntu images; Railway may continue hosting the existing control plane |
| OpenStack | Keystone, Nova, Neutron, approved images, persistent volumes as required; operator-owned cloud and scoped projects |
| Cloud API adapter | Typed TypeScript REST adapter with catalog discovery, strict TLS validation, bounded retry/backoff, and capability tests; no shell interpolation of user input into `openstack` commands |
| Auth/secrets | Preserve current product identity; customer-configured secret references for credentials; scoped worker identity, rotation and revocation; separate human approval authority |
| Notifications | Existing ThreatCrush alerts/webhooks; reuse current mail transport, with Resend only where the product already supports/configures it |
| Payments | Reuse CoinPayPortal integration for approved hosted usage; no payment credentials or billing authority in an untrusted runner |
| Tests | Existing repository test runner plus isolated HTTP/cache fixtures, private registry fixtures, API/IPC tests, and real OpenStack contract/integration tests |

The inspected monorepo documentation still references Supabase migrations and legacy local SQLite dependencies. This proposal does not assume they have been removed. New shared operational data must use self-hosted PostgreSQL; add adapters/migrations without silently replacing identity, breaking existing users, or expanding SQLite into the new write-heavy backend. A complete Supabase/auth migration requires a separate proposal. [S1]

Do not introduce managed Supabase, Turso, a new payment provider, a new frontend, or a mandatory object-storage service merely for this feature. Existing Tailwind infrastructure may remain where required by the app/shadcn; the design choice is reusable components, not an unrelated styling rewrite.

### Component placement and data flow

Reuse verified entry points: `apps/web/src/app/api/`, `apps/cli/src/commands/`, `apps/cli/src/daemon/`, `apps/desktop/`, `apps/sdk/`, and the existing scan implementation. Suggested new internal boundaries are a build-exposure analyzer, cache verifier, policy evaluator, action broker, and OpenStack runner adapter. Exact new directories/package names are implementation decisions after checking for existing equivalents. [S1]

```text
CLI / PWA / Desktop / MCP
             |
             v
Existing ThreatCrush API + tenant authorization
             |
             +--> PostgreSQL: scope, findings, policies, approvals, audit
             +--> Queue: bounded discovery and verification jobs
             |
             v
Trusted runner controller + policy/action broker
             |
             +--> Enrolled Linux execution environment
             +--> OpenStack disposable VM
                        |
                 Untrusted job/agent
                        |
                 Constrained gateways only
                        |
                 Broker-approved external action
```

The controller, not the workload, holds cloud lifecycle authority. The broker, not the model, holds publication authority. The UI cannot bypass server-side decisions. Keep customer-side scanning and secret-bearing verification local to the customer’s environment by default; upload redacted findings and minimal state only. Do not weaken an existing encryption model or claim end-to-end encryption for processing that actually exposes plaintext to a hosted service.

## Monetization

**Payer:** Teams needing managed exposure scans, shared approvals/audit, hosted isolated workers, or OpenStack deployment support.

**Core:** Preserve the repository’s existing open-source license and existing contractual product entitlements. Local/static inspection and self-managed enforcement must not require a payment merely to continue protecting an already configured system. No new license restrictions are proposed here.

**Paid value:** Hosted worker execution, managed scheduling, team policy/audit operations, longer evidence retention, and optional enterprise support. Reuse the existing ThreatCrush entitlement and CoinPayPortal billing paths after verifying their implementation. This is product billing, not authority for an agent to buy services.

**Pricing decision:** No new dollar price is approved by this draft. Pricing and any resource markup require a separately approved price configuration before paid checkout is enabled. Pilot access can be free with explicit resource caps; do not publish fictional prices or silently charge an operator-provided OpenStack account through ThreatCrush.

**Usage accounting:** Meter hosted worker time and any explicitly priced scan unit once per job. Display the configured rate, estimate, and maximum authorized spend before starting. Provider-native OpenStack resource costs are shown only when a configured tariff supplies them; quotas alone are not monetary amounts. Reconcile failed/uncertain jobs under a documented refund/charge policy. Payment webhooks require signature verification and idempotency.

**Safety:** Exhausted credits prevent new billable hosted jobs; they never remove local policy enforcement, prevent an operator from containing a session, or trigger an unauthorized recharge. A job cannot expand its own runtime or spend budget.

## Success Metrics

These are proposed release and pilot targets, not measurements of today’s product.

| Metric | Target and measurement |
| --- | --- |
| Requirement coverage | Every P0 requirement maps to at least one automated test or documented integration verification; all release-gating tests pass |
| Fixture detection | All defined positive build/cache fixtures are detected with correct evidence class; no confirmed leak on the negative/public-content controls |
| Target safety | No request outside approved target/path/redirect scope in the adversarial authorization suite |
| Approval safety | All replay, self-approval, tenant-confusion, stale-policy, and changed-artifact fixtures are denied |
| Enforcement honesty | Every protected session has a successful isolation preflight and fresh health evidence; degraded runners never retain a green protected state |
| Containment | On the declared healthy test environment, new broker actions stop within 2 seconds and controlled process/network shutdown is observed within 10 seconds; provider-delayed cases remain unresolved/degraded until verified |
| Decision latency | Local cached nonsensitive policy decisions p95 under 50 ms; online broker authorization p95 under 250 ms excluding human approval and external publication, on the documented test setup |
| Discovery performance | A declared 10,000-file/100 MiB fixture completes within 60 seconds on a 4-vCPU/8-GiB reference worker; larger/unsupported inputs report budgets rather than hanging |
| Lifecycle cleanup | Expired owned workers/resources are removed within 10 minutes when provider APIs and permissions are healthy; outages create alerts and reconciliation backlog |
| Retry correctness | Fault injection produces no duplicate accepted action, lost durable approval decision, or duplicate usage charge; uncertain remote outcomes are surfaced |
| Evidence hygiene | No synthetic credential sentinel appears in ordinary logs, alerts, exported reports, or PWA caches |
| Operational usefulness | During the pilot, at least 80% of confirmed high-severity findings are rated actionable by a human reviewer; report sample size and the remainder’s cause |
| Adoption | Track properties with completed inspections, guarded jobs, requested/approved/denied actions, and completed retests; do not use raw alert volume as a success proxy |

Benchmark definitions, worker images, network topology, fixture revisions, sample counts, and coverage exclusions must accompany results. Passing a finite suite is not a guarantee of zero real-world errors.

## Risks & Open Questions

### Decisions required before acceptance

| Decision | Default in this draft | Owner / release effect |
| --- | --- | --- |
| Meaning of OpenStack | OpenStack IaaS deployment and isolated-worker support, not a new application framework | Product owner confirms during review; application stack remains explicit |
| Shared-CDN policy conflict | Narrowly amend PRD 0016 for verified, exact customer-hostname synthetic tests with provider permission | Product/security review; CDN tests remain disabled until accepted |
| Exact OpenStack compatibility target | One operator-selected cloud/version/image/network-driver combination first | Platform owner; publish supported API/capability matrix before v1 |
| Existing product auth/storage | Preserve existing identity/tenancy; new shared operational tables use self-hosted PostgreSQL | Engineering audit; no silent global migration |
| Agent integration details | Implement moshcode/Chovy session/action contracts at their real execution boundary | Inspect their code before assigning file paths or claiming working adapters |
| Hosted pricing | No new price or automatic charge without approved configuration | Product owner; paid checkout blocked, capped pilot allowed |
| PRD number | `0017` based on the inspected index | Recheck before repository insertion; no number reservation or automatic commit |

### Residual risks and operational limitations

**Enforcement is only as strong as the boundary.** A root-controlled workload on the supervisor host, broad cloud-management access, a bypass network route, or a compromised trusted broker invalidates the model. Refuse enforced status in those configurations. Dedicated VM isolation reduces the shared-kernel boundary for hosted jobs but does not eliminate hypervisor or operator risk.

**Allowed outputs can still carry sensitive information.** An approved PR, model request, artifact, or log channel can expose information a job can read. Reduce readable data, scope outputs, and inspect artifacts; do not claim that destination restrictions alone stop all exfiltration.

**Cache tests can mislead.** A missing gzip branch, a cache-busting parameter, different edge location, rate limit, or unrepresentative synthetic route can conceal a flaw. Surface coverage and route equivalence explicitly. Never convert “not reproduced” into global safety.

**Active tests have residual side effects.** Even read-looking routes may generate tokens, consume quotas, trigger lockouts, or write audit records. Start in staging with synthetic accounts and prove route semantics before production opt-in.

**Cloud controls vary.** API versions, role policy, credential access rules, networking drivers, stateful flows, and operator defaults differ. Verify the actual environment. A security-group update or VM stop request may not be immediate; display actual observed containment and failure states.

**Supply-chain scanners can become execution paths.** Parse hostile inputs in constrained workers, pin analyzer versions, avoid runtime project imports, and gate module changes. Updating a security module is a trusted operation, not something an analyzed package can request implicitly.

**Resource costs can outlive jobs.** Orphaned VMs/volumes and repeated provisioning retries can consume money. Durable ownership records, quotas, reconciliation, deletion alerts, and explicit spend caps are required; no promise of exact cloud charges without provider billing data.

**Source and repository limits.** This draft is based on inspected documentation and selected implementation context, not a complete code or production audit. The original Reddit discussion and earlier incident-attribution claims are not treated as verified implementation evidence. The independently accessible cache advisory is cited only for its documented failure mode.

### Repository handoff

Place this file under `prd/` with the next available ID, retain `Draft` until reviewed, link R# requirements to implementation work, and regenerate the index using the existing tooling:

```bash
logicsrc prd index --write
logicsrc prd validate --strict
```

Validate against this document’s declared `0.3` standard. Do not force older `0.2` documents to migrate. If full-collection strict validation finds pre-existing errors, report and resolve those explicitly rather than claiming this one document proves the collection clean. The intended lifecycle is `Draft → Review → Accepted → Final`; `Final` requires shipped implementation and passing acceptance evidence. [S10][S11]

### Sources and provenance

All references were inspected on September 12, 2026 unless noted. Repository documents describe their respective state and may lag implementation. They are not instructions to execute untrusted repository content.

- **[S1] ThreatCrush monorepo structure:** [MONOREPO.md](https://github.com/profullstack/threatcrush/blob/master/MONOREPO.md). File blob SHA inspected: `1176db762093adab5d83ba86376545daf8cc7246`.
- **[S2] Scanner contract and limitations:** [docs/SCANNING.md](https://github.com/profullstack/threatcrush/blob/master/docs/SCANNING.md). File blob SHA inspected: `805bedd243676a3f342482d8296c84d8ff2832fc`.
- **[S3] Existing proposal index:** [prd/README.md](https://github.com/profullstack/threatcrush/blob/master/prd/README.md). File blob SHA inspected: `e3ddcc2ccde7ac87cbd2c41b9454383338195609`; indexed proposals `0001`–`0016`.
- **[S4] Authorized active-testing proposal and CDN restriction:** [PRD 0016](https://github.com/profullstack/threatcrush/blob/master/prd/0016-attack-your-own-infrastructure-safely-and-only-your-own.md). Draft; file blob SHA inspected: `87f4e2f0c426f31e79fa9f374c8ea403aebf4c7b`.
- **[S5] Independently documented cache/compression failure:** [RubyGems security advisory: possible leak of legacy API keys via improper cache configuration](https://blog.rubygems.org/2026/07/22/security-advisory-legacy-api-key-leak.html). Used for the technical cache-isolation motivation, not attribution of a separate campaign.
- **[S6] Project-scoped cloud credentials and service-dependent access rules:** [OpenStack Keystone application credentials](https://docs.openstack.org/keystone/latest/user/application_credentials.html).
- **[S7] Effective networking and additive security groups:** [OpenStack Neutron networking concepts](https://docs.openstack.org/neutron/latest/admin/intro-os-networking.html).
- **[S8] Resource quotas:** [OpenStack Nova quotas](https://docs.openstack.org/nova/latest/user/quotas.html).
- **[S9] Catalog-discovered compute endpoints and API capabilities:** [OpenStack Compute API](https://docs.openstack.org/api-ref/compute/).
- **[S10] Document standard:** [LogicSRC OpenPRD 0.3 specification](https://github.com/profullstack/logicsrc/blob/master/docs/openprd.md). File blob SHA inspected: `74d5d0b1df4ccc8e9990acc470ad07ecda1a93f6`.
- **[S11] Manifest schema:** [openprd-prd.schema.json](https://github.com/profullstack/logicsrc/blob/master/packages/schemas/schemas/openprd-prd.schema.json). File blob SHA inspected: `51a44594b6f6a2d2a6b5d5e61b5d61e0c924ae0e`.
