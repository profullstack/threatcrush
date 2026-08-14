---
name: web-hunter
description: Comprehensive web security assessment methodology. Threat-model-first parameter discovery, business logic exploitation, WAF evasion techniques, and vulnerability chain execution.
---

# WEB-HUNTER — Web Application Security Assessment Framework

Advanced web security assessment engine. Designed to systematically identify, test, and exploit business logic vulnerabilities, access control bypasses, and complex injection vectors.

---

## Phase 1: Threat-Model-First Reconnaissance

Before testing endpoints, build a target operational profile:

```
TARGET PROFILE:
- Business Function: Core revenue model and asset locations (PII, tokens, payments).
- Tech Stack: Frameworks, web servers, ORM, API paradigm (REST, GraphQL, gRPC).
- Trust Boundaries: Public endpoints, authenticated roles, admin interfaces, background hooks.
```

### Discovery & Surface Mapping
1. **Subdomain & Asset Enumeration:** Harvest active subdomains and origin IPs behind CDNs/WAFs using passive certificates, DNS records, and direct port scans.
2. **Endpoint & Parameter Extraction:** Extract hidden routes, API paths, and dynamic parameters from JS bundles, sitemaps, and historical archives (`katana`, `arjun`, `x8`).
3. **Authentication Analysis:** Map session handling (JWT, cookies, OAuth flows), password reset tokens, and multi-factor verification steps.

---

## Phase 2: Feature-First Exploitation Hierarchy

Focus attack execution on application features before testing generic input fuzzing:

### 1. Business Logic & Workflow Abuses
- **State Manipulation:** Alter pricing, quantities, or step sequences in multi-step workflows (e.g. checkout, registration).
- **Referral & Bonus Loops:** Test race conditions and parameter reuse in coupon, referral, and rewards programs.
- **Idempotency Gaps:** Replay payment, withdrawal, or action webhooks to trigger duplicate side effects.

### 2. Access Control & Privilege Boundaries (IDOR)
- **Horizontal Escalation:** Swap resource identifiers (`id`, `uuid`, `user_id`) in API endpoints using lower-privileged accounts.
- **Vertical Escalation:** Attempt role elevation by submitting forbidden role attributes (e.g. `role: "admin"`, `is_admin: true`) in registration or profile update payloads.
- **Cross-Tenant References:** Reference resources belonging to Organization A while authenticated as a user in Organization B.

### 3. High-Impact Injections & SSRF
- **Server-Side Request Forgery (SSRF):** Inject internal IP ranges (`127.0.0.1`, `[::1]`, `169.254.169.254`) into URL-fetching parameters (e.g. preview generators, metadata fetchers, webhooks).
- **Cross-Site Scripting (XSS):** Inject HTML/JS payloads into stored fields rendered in user dashboards or admin panels (`dangerouslySetInnerHTML`, unescaped Markdown, URI schemes like `javascript:`).
- **Command & Template Injections:** Test parameters passed to system commands, template engines (SSTI), or dynamic loaders.

---

## Phase 3: WAF Evasion & Obstacle Hierarchy

When a security control or WAF blocks a vector:
1. **Content-Type Switching:** Convert `application/json` to `application/x-www-form-urlencoded`, `multipart/form-data`, or XML.
2. **Encoding Bypass:** Use double URL encoding, Unicode normalization, or payload splitting.
3. **Header Manipulation:** Inject proxy/forwarding headers (`X-Forwarded-For: 127.0.0.1`, `X-Original-URL`).
4. **Endpoint Pivoting:** Attempt the same operation via legacy API versions (`/api/v1/` vs `/api/v2/`), GraphQL resolvers, or mobile-specific endpoints.

---

## Anti-Hallucination & Verification Protocol
- Every reported vulnerability must be backed by empirical evidence (exact HTTP request/response pairs, status codes, or reproducible proof-of-concept).
- Never report theoretical risks without verifying the underlying application behavior.
