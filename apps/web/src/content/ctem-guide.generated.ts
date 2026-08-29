// GENERATED FILE — do not edit by hand.
// Source: docs/whitepaper-ctem.md + docs/ctem-checklist.json
// Regenerate with: pnpm build:whitepaper

export type GuideSection = { id: string; title: string; html: string };

export type ChecklistItem = { id: string; title: string; detail: string };
export type ChecklistStage = {
  id: string;
  n: string;
  name: string;
  question: string;
  items: ChecklistItem[];
};
export type ChecklistBand = { min: number; max: number; label: string; summary: string };
export type Checklist = {
  slug: string;
  title: string;
  subtitle: string;
  intro: string;
  disclaimer: string;
  bands: ChecklistBand[];
  stages: ChecklistStage[];
};

export const GUIDE_WORD_COUNT = 3982;
export const GUIDE_READ_MINUTES = 18;

export const GUIDE_SECTIONS: GuideSection[] = [
  {
    "id": "top",
    "title": "Overview",
    "html": "<p><strong>A Practical Guide for Operators Who Are Tired of Drowning in Findings</strong></p>\n<p><em>A ThreatCrush whitepaper — published 2026</em></p>"
  },
  {
    "id": "tl-dr",
    "title": "TL;DR",
    "html": "<p>Vulnerability management as it has been practiced for the last fifteen years is broken. Scanners produce thousands of findings, prioritization is a wishlist, and remediation queues outlive the engineers who started them. Continuous Threat Exposure Management (CTEM) is the operational answer: a closed loop of <strong>scoping, discovery, prioritization, validation, and mobilization</strong> that runs continuously, not quarterly. This guide explains how to evolve from VM to CTEM without burning down what already works, and how ThreatCrush — a single agent plus a marketplace of security modules — gives small and mid-sized teams the pieces they need to run a real CTEM program without buying nine tools.</p>"
  },
  {
    "id": "the-problem-with-vulnerability-management",
    "title": "1. The problem with vulnerability management",
    "html": "<p>The classical VM playbook — periodic scan, ticket-everything, chase a patch SLA — was designed for a world where:</p>\n<ul><li>Attack surface was mostly internal and inventoried.</li><li>Exploits typically lagged disclosure by weeks or months.</li><li>The bottleneck was scanning, not deciding what to do with the output.</li></ul>\n<p>None of that is true anymore. Modern attack surfaces include cloud workloads, third-party SaaS, leaked credentials in public repos, abandoned subdomains, exposed admin panels, and supply-chain dependencies updated by people you have never met. The mean time from CVE publication to in-the-wild exploitation is now measured in <strong>days</strong>, sometimes hours. And the bottleneck is no longer scanning — it is the unbearable signal-to-noise ratio of the scanners themselves.</p>\n<p>A typical mid-sized environment will produce tens of thousands of \"findings\" per quarter. The vast majority of them:</p>\n<ul><li>Are not exploitable in context.</li><li>Are not on assets that matter.</li><li>Are duplicates of findings already triaged.</li><li>Are CVSS-prioritized in a way that bears little relationship to actual business risk.</li></ul>\n<p>The team triages a fraction, patches a fraction of that, and never closes the backlog. The CISO reports a \"patch percentage\" that goes up and to the right while the actual exposure window stays open.</p>\n<p><strong>This is the gap CTEM is meant to close.</strong></p>"
  },
  {
    "id": "what-ctem-actually-is",
    "title": "2. What CTEM actually is",
    "html": "<p>Continuous Threat Exposure Management was named and structured by Gartner, but the underlying idea is older: stop treating security exposures as a list of tickets, and start treating them as a continuously updated picture of where an attacker could plausibly get in <strong>today</strong>.</p>\n<p>CTEM is not a product category. It is a five-stage operational loop that any team can run, given the right tooling:</p>\n<ol><li><strong>Scoping</strong> — agree on what you are protecting and which exposures matter.</li><li><strong>Discovery</strong> — continuously enumerate assets, services, identities, and weaknesses across that scope.</li><li><strong>Prioritization</strong> — rank findings by exploitability, attacker reachability, and business impact, not raw CVSS.</li><li><strong>Validation</strong> — confirm that the exposures you think exist actually do, and that the controls you think are working actually are.</li><li><strong>Mobilization</strong> — get fixes shipped: tickets, owners, runbooks, automated mitigations, and follow-up.</li></ol>\n<p>The loop runs forever. There is no \"done.\" Each cycle should improve the inputs to the next: a validated finding makes prioritization smarter; a remediated class of bug makes discovery more focused.</p>"
  },
  {
    "id": "the-five-stages-in-operator-language",
    "title": "3. The five stages, in operator language",
    "html": "<h3>3.1 Scoping</h3>\n<p>Scoping fails most often because security teams scope by tool (\"everything the EDR sees\") rather than by <strong>business outcome</strong> (\"everything that, if compromised, costs us money or trust\"). Tool-defined scope has the property that a vendor-renewed scanner suddenly halves your scope without anyone deciding that.</p>\n<p><strong>A useful scoping exercise:</strong></p>\n<ul><li>List the top five things an attacker could do to your business that would actually hurt — exfiltrate customer data, ransomware the production database, take over the CEO's email, drain the wallet, ship malicious code to customers.</li><li>Trace each one back to the systems and identities that would have to be compromised first.</li><li>That trace <strong>is</strong> your scope. Everything else is secondary.</li></ul>\n<p>If your VM tool has 40,000 findings on assets that don't appear in the trace above, those findings are noise until proven otherwise.</p>\n<h3>3.2 Discovery</h3>\n<p>Discovery in CTEM is broader than vulnerability scanning. It includes:</p>\n<ul><li>Active scanning of your declared attack surface (web apps, APIs, network services).</li><li>Passive monitoring of inbound traffic — every port, every protocol — for things you forgot you exposed.</li><li>External attack surface management (ASM): subdomains, S3 buckets, exposed dashboards, leaked credentials in public dumps.</li><li>Code-side discovery: secrets in repos, vulnerable dependencies, dangerous configurations.</li><li>Identity discovery: dormant accounts, over-privileged service principals, MFA gaps.</li></ul>\n<p>The trap here is buying five different \"discovery\" tools and never reconciling their outputs. CTEM works only if discovery feeds a <strong>single normalized inventory of exposures</strong>, where the same finding from three sources is one entry, not three.</p>\n<h3>3.3 Prioritization</h3>\n<p>CVSS is a starting point, not an answer. A CVSS 9.8 on a server with no inbound network reachability is less urgent than a CVSS 6.5 on a customer-facing API behind no WAF. Prioritization in CTEM uses, in roughly this order:</p>\n<ol><li><strong>Exploitability</strong> — is there a working exploit in the wild? KEV catalog, EPSS score, exploit-DB hits.</li><li><strong>Reachability</strong> — can the exposure be reached from where attackers actually are (the public internet, a partner network, a phished employee laptop)?</li><li><strong>Blast radius</strong> — if exploited, what does the attacker reach next? Lateral movement potential, credential access, data exposure.</li><li><strong>Business impact</strong> — does the affected asset map to one of the top-five outcomes from scoping?</li><li><strong>Compensating controls</strong> — is there already a mitigation in place that meaningfully reduces risk?</li></ol>\n<p>The output of prioritization is not a CVSS score; it is a small, ordered list of exposures the team should actually work on this week.</p>\n<h3>3.4 Validation</h3>\n<p>Validation is where most VM programs quietly die. Without validation, the team has no idea whether a finding is real, whether a fix worked, or whether a control is providing the protection it claims to. CTEM treats validation as a first-class stage:</p>\n<ul><li><strong>Exploit validation</strong> — for top-priority findings, attempt the exploit in a controlled way. Does it actually work in your environment, or is the prerequisite path missing?</li><li><strong>Control validation</strong> — is the WAF blocking what you think it's blocking? Is the EDR catching the things it claims to catch? Run the test, don't trust the dashboard.</li><li><strong>Fix validation</strong> — when a fix is shipped, re-run the exact check that surfaced the original finding. Don't close tickets on faith.</li></ul>\n<p>Automated, continuous validation is what separates CTEM from \"VM with extra steps.\"</p>\n<h3>3.5 Mobilization</h3>\n<p>Mobilization is the unsexy stage that makes the rest of CTEM real. It is the work of:</p>\n<ul><li>Routing the right finding to the right owner with enough context to act on it.</li><li>Providing concrete remediation guidance, not \"upgrade to the latest version.\"</li><li>Tracking SLAs that are tied to risk, not to severity letters.</li><li>Triggering automated responses where the risk is high and the remediation is mechanical (rotate the credential, kill the session, block the IP, add the header).</li><li>Closing the loop by re-running validation after the fix.</li></ul>\n<p>A CTEM program that nails stages 1–4 and skips mobilization is just a more expensive VM program.</p>"
  },
  {
    "id": "why-traditional-tools-struggle-to-deliver-ctem",
    "title": "4. Why traditional tools struggle to deliver CTEM",
    "html": "<p>Most tools in the market today were built for one stage of the loop and bolted into a \"platform\" by acquisition. The result is:</p>\n<ul><li>A scanner that produces findings but cannot validate them.</li><li>An ASM product that finds exposures but doesn't talk to ticketing.</li><li>An EDR that has telemetry but no view of external exposure.</li><li>A SOAR that can automate responses but has no view of underlying weakness.</li><li>A \"risk score\" dashboard that aggregates everything and explains nothing.</li></ul>\n<p>The integration tax is enormous. Most teams under 200 engineers cannot afford to operate this stack, let alone run a real CTEM loop on top of it.</p>"
  },
  {
    "id": "the-threatcrush-approach",
    "title": "5. The ThreatCrush approach",
    "html": "<p>ThreatCrush is built around two ideas:</p>\n<ol><li><strong>One agent per server, doing the boring parts well.</strong> A single Linux daemon that handles inbound monitoring on every port, code scanning, automated pentesting against your URLs and APIs, and active defense (tar pits, honeypots, deception). Operators get CLI, TUI, desktop, and mobile clients that all talk to the same agent over an end-to-end-encrypted channel.</li></ol>\n<ol><li><strong>A marketplace for everything else.</strong> Discovery sources, prioritization signals, validation checks, and mobilization integrations are modules. Some are first-party. Many are community-published. You install only what your environment needs, and you can publish your own.</li></ol>\n<p>This shape is deliberate. CTEM rewards organizations that can compose specific capabilities for their specific scope — not organizations that bought the biggest platform.</p>\n<h3>5.1 How ThreatCrush maps to the CTEM stages</h3>\n<table><thead><tr><th>CTEM Stage</th><th>ThreatCrush Capability</th></tr></thead><tbody><tr><td>Scoping</td><td>Asset inventory from the agent + module-defined scope tags; you declare which servers and properties matter.</td></tr><tr><td>Discovery</td><td>Built-in network monitor (every port, every protocol), code scanner, pentest engine, plus marketplace modules for ASM, identity, and supply-chain discovery.</td></tr><tr><td>Prioritization</td><td>Findings are normalized and tagged with module-driven severity hints; KEV/EPSS modules layer in exploitability data.</td></tr><tr><td>Validation</td><td>Pentest engine re-runs checks on demand; active-defense modules confirm controls by attempting to defeat them.</td></tr><tr><td>Mobilization</td><td>Real-time alerts (email, SMS, Slack, Discord, webhook), automated active-defense responses, and an API surface for SOAR/ticketing integrations.</td></tr></tbody></table>\n<h3>5.2 What is different about it</h3>\n<ul><li><strong>One agent, not nine.</strong> The daemon is the unit of deployment. Modules extend it without adding sidecars.</li><li><strong>Marketplace economics.</strong> Authors get paid for modules, which means the long tail of niche detectors, parsers, and integrations actually exists.</li><li><strong>Active defense is first-class.</strong> Detecting an attacker is the floor, not the ceiling. Tar pits, honeypots, deception, and automated abuse reports turn detection into cost imposition.</li><li><strong>Operator-first surfaces.</strong> CLI for muscle-memory work, TUI for live ops, desktop for triage, mobile for \"is the building on fire\" alerts.</li><li><strong>Lifetime licensing on the core, usage-based pricing on AI modules.</strong> No subscription treadmill on the parts that don't need one. Pay for AI inference only when you use it.</li></ul>"
  },
  {
    "id": "a-90-day-implementation-playbook",
    "title": "6. A 90-day implementation playbook",
    "html": "<p>This is the path most teams should follow to evolve from VM to CTEM. Calendar weeks, not sprints.</p>\n<h3>Weeks 1–2: Scope honestly</h3>\n<ul><li>Run the top-five-outcomes exercise from Section 3.1 with security, engineering, and at least one business stakeholder in the room.</li><li>Produce a one-page document: critical outcomes, the systems and identities that protect them, and the \"everything else\" bucket.</li><li>Stop pretending the \"everything else\" bucket has the same priority as the scoped systems.</li></ul>\n<h3>Weeks 3–4: Consolidate discovery</h3>\n<ul><li>Inventory every discovery tool currently producing findings. Note overlap.</li><li>Pick a normalization layer — ThreatCrush, a SIEM, or a homegrown table — that will hold one row per exposure regardless of source.</li><li>Wire your top two or three discovery sources into it. Resist the urge to wire all of them on day one.</li></ul>\n<h3>Weeks 5–6: Build a real prioritization function</h3>\n<ul><li>Document the prioritization formula your team will actually use. Inputs: exploitability, reachability, blast radius, business impact, compensating controls.</li><li>Apply it to the existing backlog. Most of the backlog will drop in priority. Some unexpected items will rise. That is the point.</li><li>Publish the new top-20 list. Get sign-off from engineering on who owns each.</li></ul>\n<h3>Weeks 7–8: Add validation</h3>\n<ul><li>For every item on the top-20, define a validation check: a script, a pentest module, a control test. Schedule it weekly.</li><li>Wire validation results back into the same normalized exposure store.</li><li>Begin closing tickets only when validation confirms the fix.</li></ul>\n<h3>Weeks 9–12: Automate mobilization</h3>\n<ul><li>Pick the three highest-frequency remediation actions in your environment (rotate credential, block IP, add security header, etc.). Automate them.</li><li>Wire alerts to the channels operators actually read — Slack/Discord/SMS, not a dashboard nobody opens.</li><li>Schedule a monthly CTEM review: how many cycles closed, what stages are slowest, what the next quarter's scope adjustment should be.</li></ul>\n<p>By day 90 you will not have a \"perfect\" CTEM program. You will have a working loop, which is infinitely more valuable than a perfect plan.</p>"
  },
  {
    "id": "metrics-that-matter",
    "title": "7. Metrics that matter",
    "html": "<p>Most VM dashboards optimize for the wrong number. CTEM metrics should reflect the loop, not the queue.</p>\n<ul><li><strong>Mean time to discover (MTTD).</strong> From an exposure existing to your tooling knowing about it. Trend it down.</li><li><strong>Mean time to validate (MTTV).</strong> From discovery to a confirmed real-or-false-positive determination. Trend it down.</li><li><strong>Mean time to mobilize (MTTM).</strong> From validated finding to remediated and re-validated. Trend it down.</li><li><strong>Exposure window for top-tier findings.</strong> The interval during which a critical, validated, reachable exposure is open. This is the number that should keep you up at night.</li><li><strong>Validation coverage.</strong> Percentage of \"open\" findings that have been actively validated in the last 30 days. Anything below 50% means the queue is fiction.</li><li><strong>Cycle close rate.</strong> Number of CTEM cycles completed per quarter on a given scope.</li></ul>\n<p>Notably absent: total finding count, patch percentage, CVSS-weighted backlog. Those numbers reward activity, not outcomes.</p>"
  },
  {
    "id": "common-failure-modes",
    "title": "8. Common failure modes",
    "html": "<p>After watching dozens of teams attempt this, a few patterns repeat:</p>\n<ul><li><strong>Scope creep on day one.</strong> \"Everything is in scope\" means nothing is in scope. Start narrow.</li><li><strong>Discovery without normalization.</strong> Adding a sixth discovery tool without a single exposure store just multiplies noise.</li><li><strong>Prioritization by committee.</strong> Every stakeholder wants their pet finding on top. Codify the formula and let it run.</li><li><strong>Validation by dashboard.</strong> If the only validation is \"the green light is on,\" the program will quietly rot.</li><li><strong>Mobilization without owners.</strong> Automated remediation is great; humans still need to own classes of risk.</li><li><strong>Tooling without a loop.</strong> Buying CTEM-branded products does not give you CTEM. Running the loop does.</li></ul>"
  },
  {
    "id": "how-ctem-relates-to-siem-edr-and-soc",
    "title": "9. How CTEM relates to SIEM, EDR, and SOC",
    "html": "<p>A common point of confusion: if I have a SIEM, an EDR, and a SOC, do I still need CTEM? And vice versa — if I run a CTEM program, do I still need detection and response?</p>\n<p>The answer is yes to both, because they operate on different sides of the incident timeline.</p>\n<table><thead><tr><th>Layer</th><th>Question it answers</th><th>When it acts</th></tr></thead><tbody><tr><td>CTEM</td><td>Where could an attacker plausibly get in today?</td><td><strong>Before</strong> anything happens.</td></tr><tr><td>SIEM</td><td>Across all my logs, is anything suspicious correlating right now?</td><td><strong>During</strong> suspicious activity.</td></tr><tr><td>EDR</td><td>On this individual endpoint, is something malicious executing right now?</td><td><strong>During</strong> an attack on a host.</td></tr><tr><td>SOC</td><td>What just tripped, and what should we do about it?</td><td><strong>During and after</strong> an incident.</td></tr></tbody></table>\n<p>A useful one-line mental model:</p>\n<p>> <strong>CTEM</strong> = find and reduce exposures before they become incidents. <strong>SIEM / EDR / SOC</strong> = detect and respond when suspicious activity or attacks are happening.</p>\n<h3>9.1 What each layer does, in one sentence</h3>\n<ul><li><strong>SIEM</strong> (Security Information and Event Management): the central log brain. Pulls in events from servers, apps, identity, cloud, and network gear and correlates patterns — for example, a user fails 50 logins, then succeeds from a new country.</li><li><strong>EDR</strong> (Endpoint Detection and Response): the security camera plus kill switch on each machine. Watches processes, files, network connections, command execution; can kill processes, quarantine devices, and roll back malicious changes.</li><li><strong>SOC</strong> (Security Operations Center): the people and processes that monitor those tools, investigate the alerts, and run incident response. Internal team, outsourced MDR, or some hybrid.</li></ul>\n<h3>9.2 Why the layers need each other</h3>\n<p>A CTEM program with no detection layer is a list of risks that you may or may not catch when someone exploits one. A detection-and-response stack with no CTEM is a perpetual game of catch-up against exposures you could have closed in advance. The two layers feed each other:</p>\n<ul><li>CTEM findings sharpen detection rules — if you know an exposure is reachable, the SIEM should treat traffic to it differently.</li><li>SOC incidents sharpen CTEM scope — if the same class of exposure keeps producing incidents, that class moves up the prioritization queue.</li><li>EDR telemetry validates CTEM assumptions — if reachability tests say a host is unreachable but EDR sees it taking inbound shell commands, your map is wrong.</li></ul>\n<h3>9.3 Where ThreatCrush sits</h3>\n<p>ThreatCrush is built to operate in both layers from a single agent:</p>\n<ul><li><strong>CTEM-side capabilities:</strong> code scanner, pentest engine, marketplace ASM modules, exposure normalization, prioritization, validation re-runs.</li><li><strong>Detect-and-respond capabilities:</strong> inbound monitoring on every port and protocol (SIEM-style log + event collection), the daemon as an EDR-style on-host agent, real-time alerts (SOC-style notification), and active-defense modules (tar pits, honeypots, deception, automated abuse reports) for EDR-style response.</li></ul>\n<p>This is deliberate. Most teams under 200 engineers cannot afford the full nine-tool stack, and bolting CTEM onto an existing SIEM+EDR is its own integration project. ThreatCrush gives small and mid-sized teams a single substrate that does the obvious detect-and-respond work and runs the CTEM loop on top, with marketplace modules filling in the long tail.</p>\n<p>It does <strong>not</strong> replace a mature enterprise SIEM or EDR — it coexists with them, feeding telemetry up and pulling exposure context down.</p>"
  },
  {
    "id": "the-open-standards-a-serious-platform-should-speak",
    "title": "10. The open standards a serious platform should speak",
    "html": "<p>CTEM is one taxonomy. The detection-and-response side of the world has its own — older, deeper, and largely open. A platform that takes itself seriously aligns with these standards rather than reinventing them, because it lets your team, your tooling, and your peers all use the same vocabulary.</p>\n<p>The short version of the landscape:</p>\n<table><thead><tr><th>Standard</th><th>What it is</th><th>Where it fits</th></tr></thead><tbody><tr><td><strong>MITRE ATT&CK</strong></td><td>Knowledge base of adversary tactics, techniques, and procedures.</td><td>Universal language for SIEM/EDR/SOC.</td></tr><tr><td><strong>MITRE D3FEND</strong></td><td>Knowledge graph of defensive countermeasures, mapped against ATT&CK.</td><td>The \"what to do about it\" side.</td></tr><tr><td><strong>Sigma</strong></td><td>Portable, vendor-neutral format for SIEM detection rules.</td><td>Detection rules that travel.</td></tr><tr><td><strong>YARA</strong></td><td>Pattern-matching language for files, malware families, and binary content.</td><td>File and payload detection.</td></tr><tr><td><strong>osquery</strong></td><td>SQL interface to endpoint state — processes, sockets, packages, users.</td><td>Open endpoint telemetry / EDR-style queries.</td></tr><tr><td><strong>OCSF / ECS / OSSEM</strong></td><td>Open schemas for normalizing security events.</td><td>Making logs from twelve sources look like one source.</td></tr><tr><td><strong>CTEM (ctem.org)</strong></td><td>Open taxonomy of exposures and exposure-management vocabulary.</td><td>The CTEM side of the stack.</td></tr><tr><td><strong>NIST CSF</strong></td><td>Five-function framework: Identify, Protect, Detect, Respond, Recover.</td><td>Governance, maturity, executive reporting.</td></tr><tr><td><strong>CIS Controls</strong></td><td>Concrete, prioritized list of practical security controls.</td><td>The \"what should we actually do\" checklist.</td></tr></tbody></table>\n<h3>10.1 Why this matters more than logos</h3>\n<p>It is easy to slap a row of standards logos on a marketing page. The harder, more useful question is: <strong>what does each standard actually contribute to a working platform?</strong></p>\n<ul><li><strong>ATT&CK</strong> gives every alert and finding a stable identifier (e.g. <code>T1003.001 – LSASS Memory</code>). That identifier travels: into your SIEM, into your SOC's runbooks, into the EDR's response, into your post-incident report. A platform that doesn't tag findings with ATT&CK technique IDs forces operators to translate.</li><li><strong>D3FEND</strong> gives the response side the same treatment. If ATT&CK tells you what an attacker did, D3FEND tells you which defensive techniques counter it. That mapping is what turns a detection into a playbook.</li><li><strong>Sigma</strong> gives detection rules portability. Modules that ship Sigma rules can be consumed by any SIEM-style processor — yours, ours, or someone else's. No vendor lock-in.</li><li><strong>YARA</strong> does the same for content patterns. A malware family signature in YARA is reusable across scanners, EDRs, and incident response tools.</li><li><strong>osquery</strong> gives you a uniform way to ask any host \"what is going on right now?\" — without writing a custom collector. ThreatCrush's daemon can dispatch osquery questions to itself and feed the answers back into the loop.</li><li><strong>OCSF / ECS / OSSEM</strong> are the schemas that keep your event store sane. Without them, every source is a dialect, and correlation becomes glue code.</li><li><strong>NIST CSF</strong> and <strong>CIS Controls</strong> are the language your CISO and your auditor speak. A platform that maps cleanly to them shortens your compliance conversations.</li></ul>\n<h3>10.2 The minimum viable open-standards stack</h3>\n<p>For a real-time detection-and-response layer, the core foundation is roughly:</p>\n<p>> <strong>ATT&CK + Sigma + D3FEND</strong> for the detection-and-response vocabulary, with <strong>OCSF / ECS</strong> to keep the event store coherent, and <strong>NIST CSF + CIS Controls</strong> for governance.</p>\n<p>Add <strong>YARA</strong> when you care about file/payload detection, and <strong>osquery</strong> when you want open endpoint telemetry without a heavy proprietary EDR.</p>\n<h3>10.3 How ThreatCrush aligns</h3>\n<p>ThreatCrush is built so the open vocabulary is the default, not an afterthought:</p>\n<ul><li><strong>Findings and detections carry ATT&CK technique IDs</strong> wherever the underlying signal supports them. Your SOC sees <code>T1110.003 – Password Spraying</code>, not <code>Module 47 alert</code>.</li><li><strong>Response modules reference D3FEND techniques</strong> so that the action ThreatCrush takes (tar pit, kill, isolate, rotate) maps to a documented countermeasure family.</li><li><strong>Detection logic ships as Sigma rules where applicable</strong>, so a rule written for ThreatCrush can be exported to a corporate SIEM, and a Sigma rule written for a SIEM can be imported as a ThreatCrush module.</li><li><strong>Events are emitted in an OCSF-compatible shape</strong> (with ECS field aliases) so that a downstream SIEM, data lake, or BI tool can consume them without bespoke parsing.</li><li><strong>Scope and control mappings reference NIST CSF functions and CIS Controls</strong> so that the same event can roll up into a CTEM dashboard, a SOC investigation, and a compliance report without three different translations.</li></ul>\n<p>The point is not to claim ThreatCrush \"supports\" these standards. The point is that the standards are the substrate the platform is built on — so your team, your auditors, and your peers can read its output without a glossary.</p>"
  },
  {
    "id": "where-threatcrush-fits-in-your-stack",
    "title": "11. Where ThreatCrush fits in your stack",
    "html": "<p>ThreatCrush is not a replacement for everything. It is a replacement for the parts that no longer earn their keep:</p>\n<ul><li>The legacy network IDS that only sees north-south traffic on port 80.</li><li>The web vulnerability scanner that produces a PDF nobody reads.</li><li>The \"pentest as a service\" subscription that runs once a year.</li><li>The seven Python scripts your senior engineer wrote to glue the above together.</li></ul>\n<p>ThreatCrush replaces those with a single agent, a marketplace of modules, and an operator-first set of clients. It coexists happily with EDR, cloud-native security tools, SIEM, and SOAR — and it is designed to be the substrate on which a small team can run a real CTEM loop without needing a SOC of twelve people.</p>"
  },
  {
    "id": "next-steps",
    "title": "12. Next steps",
    "html": "<p>If this resonates and you want to try it:</p>\n<ul><li>Install the agent on a non-production server: <code>curl -fsSL https://threatcrush.com/install.sh | sh</code></li><li>Browse the <a href=\"https://threatcrush.com/store\">Module Store</a> to see what discovery, validation, and mobilization modules already exist.</li><li>Read the <a href=\"https://threatcrush.com/docs/modules\">Module Store HTTP API reference</a> if you plan to publish your own.</li><li>For air-gapped, FedRAMP-ready, or on-prem hardware appliance deployments, talk to us directly.</li></ul>\n<p>If you want to stay in the loop without committing to a deployment, <a href=\"https://threatcrush.com\">join the waitlist</a> — we send the next-stage releases and major module updates to the list first.</p>\n<h3>About ThreatCrush</h3>\n<p>ThreatCrush is an all-in-one threat exposure platform for Linux servers, plus a marketplace of security modules. It is built and maintained by Profullstack and a community of module authors. The core platform is licensed for lifetime use; AI-enhanced modules are billed on usage.</p>\n<p>Questions, feedback, or war stories: <strong>hello@threatcrush.com</strong>.</p>\n<p>— <em>The ThreatCrush team</em></p>"
  }
];

export const CHECKLIST: Checklist = {
  "slug": "ctem-readiness",
  "title": "CTEM Readiness Checklist",
  "subtitle": "Do you actually run the loop, or do you run a queue?",
  "intro": "A CTEM program is five stages that repeat forever: scope, discover, prioritize, validate, mobilize. Most teams do two of them well and call it a program. Tick every control you can honestly say is running today — not planned, not purchased, running. The score at the end tells you which stage is starving the rest.",
  "disclaimer": "Any actions taken need to be tailored to your own environment. This checklist is a diagnostic, not a compliance standard, and we take no responsibility for outcomes.",
  "bands": [
    {
      "min": 0,
      "max": 29,
      "label": "Reactive",
      "summary": "You have tools, not a loop. Findings arrive, get triaged by whoever is free, and the backlog only grows. Start at scoping — everything downstream is noise until scope is real."
    },
    {
      "min": 30,
      "max": 54,
      "label": "Emerging",
      "summary": "Discovery works and somebody owns the queue, but nothing closes the loop. Validation is almost certainly your bottleneck: you cannot tell a fixed finding from a stale one."
    },
    {
      "min": 55,
      "max": 79,
      "label": "Operating",
      "summary": "The loop turns. The work now is latency — shrinking the exposure window between discovery and re-validated fix, and automating the three remediations you do most often."
    },
    {
      "min": 80,
      "max": 100,
      "label": "Optimizing",
      "summary": "You run a real CTEM program. The remaining gains are in scope adjustment and cost imposition: making attacks expensive rather than merely detected."
    }
  ],
  "stages": [
    {
      "id": "scope",
      "n": "01",
      "name": "Scope",
      "question": "Do you know what you are actually protecting?",
      "items": [
        {
          "id": "scope-outcomes",
          "title": "Scope is defined by business outcomes, not tool coverage",
          "detail": "You can name the top five things an attacker could do that would genuinely hurt the business, and trace each one back to the systems and identities that would have to fall first. If your scope is \"everything the EDR sees,\" a vendor renewal can silently halve it."
        },
        {
          "id": "scope-inventory",
          "title": "A live asset inventory exists and is not a spreadsheet",
          "detail": "Servers, services, domains, cloud accounts, and third-party SaaS are enumerated automatically and refreshed. An inventory a human maintains by hand is out of date the week it is written."
        },
        {
          "id": "scope-identity",
          "title": "Identities are in scope alongside machines",
          "detail": "Dormant accounts, over-privileged service principals, and MFA gaps are tracked as exposures. Most modern intrusions arrive through a credential, not a CVE."
        },
        {
          "id": "scope-owners",
          "title": "Every in-scope system has a named human owner",
          "detail": "Not a team alias. When a validated finding lands, there is one person whose job it is to close it. Unowned findings are the ones that outlive the engineer who filed them."
        },
        {
          "id": "scope-review",
          "title": "Scope is revisited on a schedule, not after an incident",
          "detail": "A quarterly review that adds and, crucially, removes things. Scope that only ever grows becomes scope nobody believes."
        }
      ]
    },
    {
      "id": "discover",
      "n": "02",
      "name": "Discover",
      "question": "Would you find out, or would someone tell you?",
      "items": [
        {
          "id": "discover-external",
          "title": "External attack surface is enumerated continuously",
          "detail": "Subdomains, exposed dashboards, forgotten storage buckets, and stale DNS records. The exposures that get exploited are usually the ones nobody remembered deploying."
        },
        {
          "id": "discover-inbound",
          "title": "Inbound traffic is monitored on every port, not just the ones you expect",
          "detail": "Passive monitoring catches the service you forgot you exposed. Scanning only your declared surface finds only what you already knew about."
        },
        {
          "id": "discover-code",
          "title": "Code-side discovery runs on every commit",
          "detail": "Hardcoded secrets, vulnerable and malicious dependencies, and dangerous configuration land in the same exposure store as infrastructure findings — before they reach production, not after."
        },
        {
          "id": "discover-supplychain",
          "title": "Dependency and supply-chain risk is tracked, including transitive packages",
          "detail": "Your build pulls code from people you have never met. A direct-dependency-only view misses the layer where compromises actually happen."
        },
        {
          "id": "discover-normalized",
          "title": "All discovery sources feed one normalized exposure store",
          "detail": "The same finding from three tools is one row, not three. Adding a sixth discovery tool without normalization multiplies noise instead of coverage."
        },
        {
          "id": "discover-creds",
          "title": "Leaked credentials are monitored outside your perimeter",
          "detail": "Public repos, paste sites, and breach dumps. Learning about a breach when the stolen credential is used is late, but it beats not learning at all."
        }
      ]
    },
    {
      "id": "prioritize",
      "n": "03",
      "name": "Prioritize",
      "question": "Does your ranking survive contact with an attacker?",
      "items": [
        {
          "id": "prioritize-formula",
          "title": "A written prioritization formula exists and is applied mechanically",
          "detail": "Inputs: exploitability, attacker reachability, blast radius, business impact, compensating controls. Written down, so it runs the same way whether or not the loudest stakeholder is in the room."
        },
        {
          "id": "prioritize-notcvss",
          "title": "Ranking is not primarily CVSS",
          "detail": "CVSS describes a vulnerability in the abstract. It knows nothing about whether the affected host is reachable, whether the service is running, or whether the data behind it matters."
        },
        {
          "id": "prioritize-exploit",
          "title": "Real-world exploitation data feeds the ranking",
          "detail": "Known-exploited catalogues and exploit-prediction scoring separate the thousands of theoretical findings from the handful being used this week."
        },
        {
          "id": "prioritize-reachability",
          "title": "Reachability is evaluated, not assumed",
          "detail": "A critical vulnerability in a code path that never executes, on a host no route reaches, is not a critical exposure. Treating it as one is how backlogs become fiction."
        },
        {
          "id": "prioritize-topn",
          "title": "A published top-20 list exists with sign-off from engineering",
          "detail": "Short enough to actually finish, owned by the people who will do the work, and refreshed each cycle."
        }
      ]
    },
    {
      "id": "validate",
      "n": "04",
      "name": "Validate",
      "question": "Do you confirm, or do you trust the dashboard?",
      "items": [
        {
          "id": "validate-check",
          "title": "Every top-tier finding has a defined validation check",
          "detail": "A script, a pentest module, or a control test that answers \"is this real?\" — scheduled, not run once during triage."
        },
        {
          "id": "validate-close",
          "title": "Tickets close on validated fixes, not on claimed fixes",
          "detail": "\"Patched\" and \"no longer exploitable\" are different statements. Only one of them is evidence."
        },
        {
          "id": "validate-controls",
          "title": "Controls are tested by trying to defeat them",
          "detail": "The green light on a console means the agent is reporting, not that the control works. Attack your own infrastructure — safely, and only your own."
        },
        {
          "id": "validate-fp",
          "title": "False positives are measured and fed back into tuning",
          "detail": "A scanner nobody trusts is a scanner nobody reads. If you cannot state your false-positive rate, your team has already started ignoring the output."
        },
        {
          "id": "validate-coverage",
          "title": "Validation coverage is tracked as a metric",
          "detail": "The share of open findings actively validated in the last 30 days. Below 50%, the queue is a work of imagination."
        }
      ]
    },
    {
      "id": "mobilize",
      "n": "05",
      "name": "Mobilize",
      "question": "Do fixes ship, or do they get assigned?",
      "items": [
        {
          "id": "mobilize-auto",
          "title": "Your three most frequent remediations are automated",
          "detail": "Rotate the credential, block the address, add the header. The repetitive fixes should not consume senior engineering time."
        },
        {
          "id": "mobilize-alerts",
          "title": "Alerts route to channels operators actually read",
          "detail": "Chat, SMS, or phone — not a dashboard someone opens on Mondays. An alert nobody sees is an outage nobody is fixing."
        },
        {
          "id": "mobilize-ticketing",
          "title": "Findings become tickets in the system engineering already lives in",
          "detail": "Work that requires logging into the security tool is work that competes with the sprint board and loses."
        },
        {
          "id": "mobilize-ir",
          "title": "An incident response plan exists and has been rehearsed this year",
          "detail": "Who to call, who decides, who talks to customers. A plan that has never survived a tabletop is a document, not a capability."
        },
        {
          "id": "mobilize-backups",
          "title": "Backups are restored on a schedule, not merely taken",
          "detail": "An untested backup is a hypothesis. Restore drills are the only thing that converts it into a recovery capability."
        },
        {
          "id": "mobilize-review",
          "title": "A recurring review asks which stage is slowest",
          "detail": "Cycles closed, stage latency, next quarter's scope adjustment. Without it the loop degrades back into a queue and nobody notices for two quarters."
        }
      ]
    }
  ]
};

export const CHECKLIST_TOTAL = 27;
