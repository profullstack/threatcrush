---
name: code-auditor
description: Extreme business logic and source code auditing methodology. Maps architecture, trust boundaries, authorization consistency, race conditions, and data flow from source to sink.
---

# CODE-AUDITOR — Enterprise Source Code & Logic Analysis

High-rigor static code analysis and business logic auditing framework. Built for complete repository archaeology, data-flow tracing, and zero-hallucination vulnerability verification.

---

## Phase 1: Repository Archaeology & Context Mapping

Never read source lines in isolation before mapping the full system context:

```
ARCHAEOLOGY WORKFLOW:
1. Directory Structure: Map monorepo workspaces, domain modules, API controllers, and background workers.
2. Tech Stack Identification: Verify exact frameworks, ORM engines, auth mechanisms, and third-party SDKs.
3. Changelog & Commit Audit: Review recent commits (`git log -30`) and hotfixes to locate untested surface.
4. Asset Identification: Locate high-value models (PII, tokens, payments, credentials, system permissions).
```

---

## Phase 2: High-Risk Code Auditing Targets

### 1. Database & Row-Level Security (RLS) Auditing
- **UPDATE Policy Inspection:** Verify every RLS `UPDATE` policy includes a strict `WITH CHECK` clause. Ensure sensitive columns (e.g. `is_admin`, `role`, `balance`, `tenant_id`) cannot be modified by user-scoped tokens.
- **Column Permission Gaps:** Check for PostgREST or ORM endpoints exposing mass assignment / over-posting vulnerabilities on user profile models.

### 2. Authorization & Multi-Tenancy Boundaries
- **Endpoint Authorization Matrix:** Compare authorization checks across all API routes. Identify endpoints where middleware or session guards were omitted.
- **Role Hierarchy Flaws:** Verify admin/owner privilege boundaries. Ensure lower roles cannot promote accounts or assign forbidden permissions.
- **Cross-Tenant Scoping:** Verify database queries filter explicitly by `org_id` / `tenant_id` to prevent cross-tenant data leaks.

### 3. Source-to-Sink Data Flow Tracing
- **Dynamic Execution:** Trace untrusted input to dynamic imports (`import()`), `eval()`, or process spawns (`exec()`, `execSync()`). Ensure package/module loaders enforce cryptographic signatures (e.g. Ed25519).
- **Unsanitized Rendering:** Trace user-controlled inputs to raw HTML renderers (`dangerouslySetInnerHTML`, unescaped Markdown components) and unvalidated link URI protocols (`javascript:`).
- **SSRF & Network Sinks:** Identify server-side HTTP calls (`fetch`, `axios`) accepting external URLs. Verify strict IP validation against RFC-1918, loopback, and cloud metadata (`169.254.169.254`).

### 4. Concurrency & Race Conditions
- **State Mutex Gaps:** Inspect non-atomic read-modify-write patterns in balances, OTP verification codes, and module download counters.
- **Lease & Job Locking:** Verify background job workers use lease timeouts to prevent job freezing on worker failure.

---

## Phase 3: Verification & Reporting Protocol

Every identified finding must follow the strict verification chain:

```
FINDING SPECIFICATION FORMAT:
- ID: TC-XX
- SEVERITY: Critical | High | Medium | Low (CVSS v3.1 evaluated)
- FILE & LINES: path/to/file.ts:LXX-LYY
- SOURCE -> SINK: Exact data path from user input to vulnerable execution
- IMPACT: Technical and business risk evaluation
- CLEAN FIX: Minimal, production-ready remediation without technical debt
```
