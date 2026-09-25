import type { DetectionRule, RuleMatch } from './engine.js';

/**
 * The web-attack rules match the structured CRS verdict log-watcher puts in
 * `details` (`attack_type`), not message text: the wording is for people and
 * already differs between `threatcrush monitor` and the daemon, which is how
 * these rules came to match nothing the daemon emitted.
 *
 * `attack_type` is also set on requests that scored below the CRS anomaly
 * threshold (a `low` "Suspicious …" or "Client error …" event), so each rule
 * also requires the severity log-watcher gives a request at the threshold
 * (`high`) or twice it (`critical`). The rules are `high`, not `critical`: a
 * rule must not escalate one matching CRS rule past what `min_severity =
 * "critical"` is documented to require (two).
 */
const AT_CRS_THRESHOLD: RuleMatch = { field: 'severity', operator: 'regex', value: '^(high|critical)$' };

export const DEFAULT_RULES: DetectionRule[] = [
  {
    id: 'ssh-brute-force',
    title: 'SSH Brute Force Detected',
    description: 'Multiple failed SSH login attempts from the same source',
    version: '1.0.0',
    category: 'auth',
    severity: 'high',
    source_types: ['ssh-guard', 'auth'],
    match: {
      field: 'message',
      operator: 'regex',
      value: 'failed ssh login|invalid ssh user',
    },
    threshold: 5,
    window_seconds: 300,
    cooldown_seconds: 600,
    tags: ['ssh', 'brute-force', 'credential-stuffing'],
    remediation: {
      action: 'block',
      ttl_seconds: 3600,
      description: 'Block source IP for 1 hour',
    },
    enabled: true,
  },
  {
    id: 'ssh-success-after-failures',
    title: 'SSH Login Accepted',
    // Honest description: this rule does NOT correlate with earlier failures —
    // it matches any accepted login. It is an alert, and it declares no
    // remediation precisely because banning the person who just logged in is
    // never the right response.
    description: 'Successful SSH login (alert only — never grounds for a ban)',
    version: '1.0.0',
    category: 'auth',
    severity: 'critical',
    source_types: ['ssh-guard', 'auth'],
    match: {
      field: 'message',
      operator: 'contains',
      value: 'SSH login accepted',
    },
    threshold: 1,
    window_seconds: 60,
    cooldown_seconds: 300,
    tags: ['ssh', 'compromise-indicator'],
    enabled: true,
  },
  {
    id: 'ssh-root-login',
    title: 'Root SSH Login Attempt',
    description: 'Direct root login via SSH detected',
    version: '1.0.0',
    category: 'auth',
    severity: 'high',
    source_types: ['ssh-guard', 'auth'],
    match: {
      field: 'message',
      operator: 'regex',
      // Attempts only. Matching `accepted` here meant a successful root login
      // banned the administrator who had just made it.
      value: 'failed.*\\broot\\b',
    },
    threshold: 1,
    window_seconds: 60,
    cooldown_seconds: 300,
    tags: ['ssh', 'root-access'],
    remediation: {
      action: 'block',
      ttl_seconds: 7200,
      description: 'Block source IP attempting root login',
    },
    enabled: true,
  },
  {
    id: 'ssh-user-enumeration',
    title: 'SSH User Enumeration',
    description: 'Multiple SSH attempts with different usernames from same source',
    version: '1.0.0',
    category: 'auth',
    severity: 'high',
    source_types: ['ssh-guard', 'auth'],
    match: {
      field: 'message',
      operator: 'contains',
      value: 'Invalid SSH user',
    },
    threshold: 3,
    window_seconds: 120,
    cooldown_seconds: 600,
    tags: ['ssh', 'enumeration', 'reconnaissance'],
    remediation: {
      action: 'block',
      ttl_seconds: 3600,
      description: 'Block source IP performing user enumeration',
    },
    enabled: true,
  },
  {
    id: 'sudo-abuse',
    title: 'Sudo Authentication Failure',
    description: 'Repeated sudo authentication failures',
    version: '1.0.0',
    category: 'auth',
    severity: 'high',
    source_types: ['user-journal', 'system'],
    match: {
      field: 'message',
      operator: 'regex',
      value: 'sudo.*authentication failure|sudo.*incorrect password|sudo.*FAILED',
    },
    threshold: 3,
    window_seconds: 300,
    cooldown_seconds: 600,
    tags: ['sudo', 'privilege-escalation'],
    enabled: true,
  },
  {
    id: 'web-sqli-attack',
    title: 'SQL Injection Attack Detected',
    description: 'HTTP request with SQL injection patterns',
    version: '1.0.0',
    category: 'web',
    severity: 'high',
    source_types: ['log-watcher', 'web'],
    match: { field: 'attack_type', operator: 'equals', value: 'sqli', and: [AT_CRS_THRESHOLD] },
    threshold: 1,
    window_seconds: 60,
    cooldown_seconds: 300,
    tags: ['web', 'sqli', 'injection'],
    remediation: {
      action: 'block',
      ttl_seconds: 3600,
      description: 'Block source IP performing SQL injection',
    },
    enabled: true,
  },
  {
    id: 'web-path-traversal',
    title: 'Path Traversal Attack Detected',
    description: 'HTTP request with path traversal patterns',
    version: '1.0.0',
    category: 'web',
    severity: 'high',
    source_types: ['log-watcher', 'web'],
    match: { field: 'attack_type', operator: 'equals', value: 'path_traversal', and: [AT_CRS_THRESHOLD] },
    threshold: 1,
    window_seconds: 60,
    cooldown_seconds: 300,
    tags: ['web', 'path-traversal', 'lfi'],
    remediation: {
      action: 'block',
      ttl_seconds: 3600,
      description: 'Block source IP performing path traversal',
    },
    enabled: true,
  },
  {
    id: 'web-xss-attack',
    title: 'XSS Attack Detected',
    description: 'HTTP request with cross-site scripting patterns',
    version: '1.0.0',
    category: 'web',
    severity: 'high',
    source_types: ['log-watcher', 'web'],
    match: { field: 'attack_type', operator: 'equals', value: 'xss', and: [AT_CRS_THRESHOLD] },
    threshold: 1,
    window_seconds: 60,
    cooldown_seconds: 300,
    tags: ['web', 'xss', 'injection'],
    remediation: {
      action: 'block',
      ttl_seconds: 3600,
      description: 'Block source IP performing XSS attack',
    },
    enabled: true,
  },
  {
    id: 'web-scanner-detection',
    title: 'Web Vulnerability Scanner Detected',
    description: 'High volume of 4xx errors suggesting automated scanning',
    version: '1.0.0',
    category: 'web',
    severity: 'medium',
    source_types: ['log-watcher', 'web'],
    match: {
      field: 'message',
      operator: 'regex',
      value: 'Client error 4\\d{2}:',
    },
    threshold: 20,
    window_seconds: 60,
    cooldown_seconds: 600,
    tags: ['web', 'scanner', 'reconnaissance'],
    remediation: {
      action: 'block',
      ttl_seconds: 1800,
      description: 'Block automated scanner',
    },
    enabled: true,
  },
  {
    // A 402 is a paywall saying "pay first". A caller that means to pay gets
    // one and pays; a podcast app polling a paid feed gets a handful an hour.
    // Thirty in a minute from one address is a scraper that ignores the answer
    // and keeps walking URLs: GoogleOther did ~40/min per IP against r4ck's
    // /api/v1/search on dev2, 2026-09-25. `web-scanner-detection` saw it too,
    // but it is `medium`, and auto-defence bans at `high` and above, so it fired
    // every minute and never banned. This one is `high` on purpose.
    //
    // It cannot see a proxy swarm that asks once per address; nothing per-IP can.
    id: 'paywall-hammering',
    title: 'Paywall Hammering',
    description: 'Repeated 402 Payment Required responses to the same source',
    version: '1.0.0',
    category: 'web',
    severity: 'high',
    source_types: ['log-watcher', 'web'],
    match: {
      field: 'message',
      operator: 'regex',
      value: 'Client error 402:',
    },
    threshold: 30,
    window_seconds: 60,
    cooldown_seconds: 600,
    tags: ['web', 'scraper', 'x402', 'paywall'],
    remediation: {
      action: 'block',
      description: 'Block a scraper that keeps walking a paywall without paying',
    },
    enabled: true,
  },
  {
    // The distributed twin of paywall-hammering. A proxy swarm asks once per
    // address — 189k 402s across 111k IPs, ~1.7 each, observed on dev2's
    // r4ck.dev/rssamplifier paywalls 2026-09-25 — so nothing per-IP ever trips,
    // and the busiest single address (which was real Googlebot) barely moved.
    // Group by endpoint instead: the paywalled path lights up even though every
    // caller is unique. It fires an ALERT, not a block — you cannot ban 100k
    // one-shot IPs, and half of them are crawlers you want. The real mitigation
    // is an nginx limit_req on the named endpoint; this is what tells you which
    // endpoint and how hard. Tune the threshold to sit above the endpoint's
    // legitimate 402 rate (a handful an hour per real client).
    id: 'paywall-scrape-distributed',
    title: 'Distributed Paywall Scrape',
    description: 'A paywalled endpoint is taking 402s from many addresses at once',
    version: '1.0.0',
    category: 'web',
    severity: 'high',
    source_types: ['log-watcher', 'web'],
    match: {
      field: 'message',
      operator: 'regex',
      value: 'Client error 402:',
    },
    group_by: 'endpoint',
    threshold: 120,
    window_seconds: 60,
    cooldown_seconds: 600,
    tags: ['web', 'scraper', 'x402', 'paywall', 'distributed'],
    remediation: {
      action: 'alert',
      description: 'Rate-limit this endpoint at the edge (nginx limit_req); per-IP bans cannot touch a swarm this wide',
    },
    enabled: true,
  },
  {
    id: 'port-scan-indicator',
    title: 'Port Scan Indicators',
    description: 'Connection attempts to many ports from a single source',
    version: '1.0.0',
    category: 'network',
    severity: 'medium',
    source_types: ['network-monitor', 'network'],
    match: {
      field: 'message',
      operator: 'contains',
      value: 'port scan',
    },
    threshold: 1,
    window_seconds: 60,
    cooldown_seconds: 300,
    tags: ['network', 'port-scan', 'reconnaissance'],
    remediation: {
      action: 'block',
      ttl_seconds: 3600,
      description: 'Block port scanner',
    },
    enabled: true,
  },
  {
    id: 'system-critical-error',
    title: 'Critical System Error',
    description: 'Critical or emergency level system log message',
    version: '1.0.0',
    category: 'system',
    severity: 'critical',
    source_types: ['user-journal', 'system'],
    match: {
      field: 'severity',
      operator: 'equals',
      value: 'critical',
    },
    threshold: 1,
    window_seconds: 60,
    cooldown_seconds: 300,
    tags: ['system', 'critical'],
    enabled: true,
  },
  {
    id: 'exploit-probe-pattern',
    title: 'Exploit Probe Pattern',
    description: 'HTTP requests matching common exploit probe patterns',
    version: '1.0.0',
    category: 'web',
    severity: 'high',
    source_types: ['log-watcher', 'web'],
    // CRS files command injection under `rce`. There is no XXE type: an
    // access log never shows the request body an XXE payload lives in.
    match: {
      field: 'attack_type',
      operator: 'regex',
      value: '^(rce|ssrf|rfi|php_injection|ssti)$',
      and: [AT_CRS_THRESHOLD],
    },
    threshold: 1,
    window_seconds: 60,
    cooldown_seconds: 300,
    tags: ['web', 'exploit', 'probe'],
    remediation: {
      action: 'block',
      ttl_seconds: 7200,
      description: 'Block source IP performing exploit probes',
    },
    enabled: true,
  },
];
