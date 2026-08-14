---
name: threat-modeler
description: Systematic attack surface enumeration and attack chain planning methodology. Maps vectors across 12 application categories and builds evidence-based remediation roadmaps.
---

# THREAT-MODELER — Attack Surface & Adversarial Threat Modeling

Enterprise threat modeling and attack surface enumeration framework. Designed to systematically map threat vectors, model adversary capabilities, and construct multi-stage exploitation chains.

---

## Phase 1: System Archaeology & Asset Identification

Before modeling threats, establish complete system visibility:

1. **System Boundaries:** Map public web applications, API gateways, background workers, IPC Unix sockets, desktop clients, and browser extensions.
2. **High-Value Assets:** Identify critical target assets (admin privileges, session keys, user PII, payment integration tokens, root OS access).
3. **Adversary Capability Profiles:** Model threats based on actor access levels:
   - *External Unauthenticated Attacker* (Internet-facing endpoints, webhooks, auth forms).
   - *Authenticated Regular User* (RLS policies, tenant isolation, IDOR vectors).
   - *Organization Admin* (Privilege escalation to Owner/Superadmin).
   - *Local User / Process* (IPC socket access, group permissions, system daemons).

---

## Phase 2: Category Attack Surface Checklist

Systematically evaluate attack surface across core security domains:

### 1. Authentication & Identity Management
- Passkey, OAuth, and password reset workflows.
- Phone and email verification logic (SMS bombing, verification hijacking, OTP reuse).
- Session storage security (`httpOnly` cookies vs. `localStorage` exposure).

### 2. Authorization & Multi-Tenancy
- Row-Level Security (RLS) policies and PostgREST column permissions.
- Organization member management (Admin-to-Owner escalation, orphan org risks).
- Cross-tenant data isolation across API endpoints and background tasks.

### 3. Input Validation & Injection Surface
- Server-Side Request Forgery (SSRF) in link preview and metadata fetchers.
- Stored and Reflected XSS in Markdown, JSON-LD, and user profile fields.
- Command injection in background workers, CLI tools, and module loaders.

### 4. IPC & Operating System Security
- Unix Domain Socket permissions (`0660`, group ownership like `adm`).
- Unsigned dynamic module loading in system daemons running as `root`.
- Electron desktop process isolation (`sandbox: false` vs `sandbox: true`, IPC renderer proxies).

### 5. Integrations & Payment Infrastructure
- HMAC signature verification on incoming payment webhooks (CoinPay, Stripe).
- Webhook idempotency handling and replay protections.
- Rate limiting on financial invoice generation and authentication endpoints.

---

## Phase 3: Attack Chain Construction & Prioritization

Combine discrete findings into end-to-end attack chains:

```
EXAMPLE ATTACK CHAIN:
[Info Leak (TC-02)] -> [Phone Takeover (TC-05)] -> [RLS Admin Escalation (TC-01)] -> [Root RCE via CLI (TC-32)]
```

### Remediation Roadmap Matrix
Group all identified risks into actionable, non-disruptive remediation tiers:
- **P0 (Immediate Blockers):** Flaws allowing unauthenticated RCE, total DB escalation, or account takeover.
- **P1 (High Priority):** Stored XSS, SSRF to internal networks, unauthenticated SMS abuse, and IPC shutdown DoS.
- **P2 (Hardening):** Rate limiting, CSP headers, session storage migration, and code cleanup.
