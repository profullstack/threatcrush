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
 *
 * Every attack type the ported CRS table can emit is claimed by exactly one of
 * them. `attack_type` is never null on a `high`/`critical` event: every ported
 * rule credits a type, so a request that scores at all has one. CRS's
 * `attack-injection-generic` maps to `injection`, but every rule tagged with it
 * is tagged `attack-rce` or `attack-ssti` first and credits that instead.
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
      description: 'Block source IP',
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
      description: 'Block source IP performing XSS attack',
    },
    enabled: true,
  },
  {
    // CRS 913100: the User-Agent names a security scanner or attack tool
    // (sqlmap, nikto, nuclei, …). One request is enough, like the rules above;
    // `web-scanner-detection` is the volume rule for scanners that hide theirs.
    id: 'web-scanner-user-agent',
    title: 'Attack Tool User-Agent Detected',
    description: 'HTTP request from a known vulnerability scanner or attack tool',
    version: '1.0.0',
    category: 'web',
    severity: 'high',
    source_types: ['log-watcher', 'web'],
    match: { field: 'attack_type', operator: 'equals', value: 'scanner', and: [AT_CRS_THRESHOLD] },
    threshold: 1,
    window_seconds: 60,
    cooldown_seconds: 300,
    tags: ['web', 'scanner', 'reconnaissance'],
    remediation: {
      action: 'block',
      description: 'Block source IP running a known attack tool',
    },
    enabled: true,
  },
  {
    // A rule that declares `block` must be at the severity auto-defence bans
    // at, or it fires and is ignored: this one was `medium`, and on dev1 it
    // detected scanners 25 times and banned none of them.
    id: 'web-scanner-detection',
    title: 'Web Vulnerability Scanner Detected',
    description: 'High volume of 4xx errors suggesting automated scanning',
    version: '1.0.0',
    category: 'web',
    severity: 'high',
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
    // every minute and never banned (it is `high` now too). This one is `high` on purpose.
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
    // The slow twin of paywall-hammering. A caller that paces itself under 30 a
    // minute never trips that rule, yet twenty 402s in ten minutes from one
    // address is not a reader deciding whether to pay: it has been told the
    // price twenty times and kept walking. DataForSeoBot took ~21k pages a day
    // from ONE address on watchnews.now (2026-10-19), about 15 a minute.
    //
    // A podcast app polling a paid feed, or a person who hit the free limit and
    // clicks a few more links, stays far under this. FCrDNS-verified search
    // crawlers are spared by remediation whatever they trip, and every ban
    // follows the ladder, so a first offence is minutes, not days.
    id: 'paywall-ignored',
    title: 'Paywall Ignored',
    description: 'One source kept requesting after twenty 402 Payment Required answers in ten minutes',
    version: '1.0.0',
    category: 'web',
    severity: 'high',
    source_types: ['log-watcher', 'web'],
    match: {
      field: 'message',
      operator: 'regex',
      value: 'Client error 402:',
    },
    threshold: 20,
    window_seconds: 600,
    cooldown_seconds: 600,
    tags: ['web', 'scraper', 'x402', 'paywall'],
    remediation: {
      action: 'block',
      description: 'Block a caller that keeps requesting after being told the price',
    },
    enabled: true,
  },
  {
    // A crawler that names itself as a scraper (a headless browser, an SEO
    // reseller) and is refused with a 402 has its answer; a fifth one inside five
    // minutes from the same address means it is ignoring it. The gateway charges
    // these by name (x402-gateway 0.8: HEADLESS_AGENTS + SCRAPER_AGENTS) and the
    // resellers are refused in robots.txt too, so nothing welcome matches here.
    // Search crawlers (Googlebot, bingbot, Applebot) are deliberately absent.
    id: 'paywall-declared-scraper',
    title: 'Declared Scraper Ignoring the Paywall',
    description: 'A self-declared scraper or headless browser keeps requesting after 402 answers',
    version: '1.0.0',
    category: 'web',
    severity: 'high',
    source_types: ['log-watcher', 'web'],
    match: {
      field: 'message',
      operator: 'regex',
      value: 'Client error 402:',
      and: [
        {
          field: 'ua',
          operator: 'regex',
          value:
            '(Lightpanda|HeadlessChrome|PhantomJS|AhrefsBot|SemrushBot|MJ12bot|DataForSeoBot|DotBot|BLEXBot|serpstatbot|Barkrowler)',
        },
      ],
    },
    threshold: 5,
    window_seconds: 300,
    cooldown_seconds: 600,
    tags: ['web', 'scraper', 'x402', 'paywall', 'headless'],
    remediation: {
      action: 'block',
      description: 'Block a declared scraper that keeps requesting after being told the price',
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
    // `high` for the same reason as web-scanner-detection: as `medium` it fired
    // 21 times on dev1 without a single ban. It also matches network-monitor's
    // "Possible port scan" notice (5+ of our LISTENING ports from one address),
    // so that is now banned on first sight as well.
    id: 'port-scan-indicator',
    title: 'Port Scan Indicators',
    description: 'Connection attempts to many ports from a single source',
    version: '1.0.0',
    category: 'network',
    severity: 'high',
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
      description: 'Block source IP performing exploit probes',
    },
    enabled: true,
  },
  {
    // A real network card entering promiscuous mode can mean someone is
    // sniffing traffic on the host. The kernel also logs this constantly for
    // container veth/bridge interfaces, which is normal (a bridge port must be
    // promiscuous to forward frames), so the negative lookahead excludes every
    // virtual interface kind and only a physical/primary NIC trips this.
    id: 'nic-promiscuous-mode',
    title: 'Network Interface Entered Promiscuous Mode',
    description: 'A non-virtual network interface entered promiscuous mode, which can indicate packet sniffing',
    version: '1.0.0',
    category: 'system',
    severity: 'medium',
    source_types: ['user-journal', 'system'],
    match: {
      field: 'message',
      operator: 'regex',
      // "[kernel] enp11s0: entered promiscuous mode" trips; veth*, docker*,
      // br-*, bridge, lo, tap*, vxlan*, cni*, cali*, flannel*, virbr*, kube*
      // and tailscale* do not.
      value: '\\b(?!veth|docker|br-|bridge|lo:|lo\\b|tap|vxlan|cni|cali|flannel|virbr|kube|tailscale)[A-Za-z][\\w.-]*: entered promiscuous mode',
    },
    threshold: 1,
    window_seconds: 60,
    // A legitimate tcpdump flaps it; do not re-alert for an hour.
    cooldown_seconds: 3600,
    tags: ['system', 'network', 'sniffing', 'host-integrity'],
    remediation: {
      // Host integrity, no attacker address to ban — surface it, do not block.
      action: 'alert',
      description: 'Confirm whether a capture tool or new bridge is expected on this host',
    },
    enabled: true,
  },
  {
    id: 'agentdb-auth-failure-burst',
    title: 'AgentDB Authentication Failure Burst',
    description: 'Repeated rejected credentials against the AgentDB API',
    version: '1.0.0',
    category: 'auth',
    severity: 'high',
    source_types: ['log-watcher'],
    match: {
      field: 'service',
      operator: 'equals',
      value: 'agentdb',
      and: [{ field: 'status', operator: 'regex', value: '^(401|403)$' }],
    },
    threshold: 5,
    window_seconds: 60,
    cooldown_seconds: 300,
    tags: ['agentdb', 'auth', 'credential-abuse'],
    remediation: { action: 'alert', description: 'Review the source and rotate any credential that may have leaked' },
    enabled: true,
  },
  {
    id: 'agentdb-query-burst',
    title: 'AgentDB Query Burst',
    description: 'An unusually large number of database reads reached the service',
    version: '1.0.0',
    category: 'web',
    severity: 'high',
    source_types: ['log-watcher'],
    match: {
      field: 'service',
      operator: 'equals',
      value: 'agentdb',
      and: [
        { field: 'path', operator: 'equals', value: '/v1/query_readonly' },
        { field: 'status', operator: 'regex', value: '^2[0-9][0-9]$' },
      ],
    },
    threshold: 60,
    window_seconds: 60,
    cooldown_seconds: 300,
    group_by: 'endpoint',
    tags: ['agentdb', 'data-access', 'possible-exfiltration'],
    remediation: { action: 'alert', description: 'Check the token owner and audit query volume before revoking credentials' },
    enabled: true,
  },
  {
    id: 'agentdb-token-creation-burst',
    title: 'AgentDB Credential Creation Burst',
    description: 'An operator credential created several service tokens in a short period',
    version: '1.0.0',
    category: 'auth',
    severity: 'high',
    source_types: ['log-watcher'],
    match: {
      field: 'service',
      operator: 'equals',
      value: 'agentdb',
      and: [
        { field: 'path', operator: 'equals', value: '/v1/tokens' },
        { field: 'status', operator: 'regex', value: '^2[0-9][0-9]$' },
      ],
    },
    threshold: 3,
    window_seconds: 60,
    cooldown_seconds: 600,
    group_by: 'endpoint',
    tags: ['agentdb', 'credentials', 'persistence'],
    remediation: { action: 'alert', description: 'Check operator access and identify any newly issued token' },
    enabled: true,
  },
  {
    id: 'agentdb-large-query-exports',
    title: 'Repeated Large AgentDB Query Responses',
    description: 'Several large read-only query responses were served in a short period',
    version: '1.0.0',
    category: 'web',
    severity: 'high',
    source_types: ['log-watcher'],
    match: {
      field: 'service',
      operator: 'equals',
      value: 'agentdb',
      and: [
        { field: 'path', operator: 'equals', value: '/v1/query_readonly' },
        { field: 'status', operator: 'regex', value: '^2[0-9][0-9]$' },
        { field: 'response_bytes', operator: 'regex', value: '^[1-9][0-9]{6,}$' },
      ],
    },
    threshold: 3,
    window_seconds: 600,
    cooldown_seconds: 600,
    group_by: 'endpoint',
    tags: ['agentdb', 'data-access', 'large-export'],
    remediation: { action: 'alert', description: 'Review the source and revoke the token if this export was not expected' },
    enabled: true,
  },
  {
    id: 'agentdb-query-throttled',
    title: 'AgentDB Read Limit Triggered',
    description: 'AgentDB rejected a query because the client reached a service limit',
    version: '1.0.0',
    category: 'web',
    severity: 'medium',
    source_types: ['log-watcher'],
    match: {
      field: 'service',
      operator: 'equals',
      value: 'agentdb',
      and: [
        { field: 'path', operator: 'equals', value: '/v1/query_readonly' },
        { field: 'status', operator: 'equals', value: '429' },
      ],
    },
    threshold: 1,
    window_seconds: 60,
    cooldown_seconds: 300,
    tags: ['agentdb', 'rate-limit', 'data-access'],
    remediation: { action: 'alert', description: 'Review AgentDB audit metadata for the token and request pattern' },
    enabled: true,
  },
];
