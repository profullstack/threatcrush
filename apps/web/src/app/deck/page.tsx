'use client';

import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import './deck.css';

type Slide = {
  id: string;
  label: string;
  bg?: 'ink' | 'paper' | 'accent';
  dotgrid?: boolean;
  scanlines?: boolean;
  gridlines?: boolean;
  render: (meta: { num: string; total: number }) => ReactNode;
};

const Chrome = ({ num, label }: { num: string; label: string }) => (
  <div className="chrome">
    <div className="brand">
      <span className="brand-dot" />
      <span>threatcrush</span>
    </div>
    <div className="meta">
      <div className="num">{num}</div>
      <div>{label}</div>
    </div>
  </div>
);

const slides: Slide[] = [
  {
    id: 'title',
    label: 'Investor Deck · 2026',
    gridlines: true,
    scanlines: true,
    render: ({ num, total }) => (
      <>
        <Chrome num={`${num} / ${total}`} label="Investor Deck · 2026" />
        <div
          className="glow-orb"
          style={{ top: '15%', left: '10%', width: 420, height: 420, background: 'rgba(0, 255, 65, 0.18)' }}
        />
        <div
          className="glow-orb"
          style={{ bottom: '5%', right: '5%', width: 320, height: 320, background: 'rgba(0, 255, 65, 0.10)' }}
        />
        <div className="content" style={{ justifyContent: 'space-between' }}>
          <div>
            <span className="eyebrow">Profullstack, Inc. · Seed round · 2026</span>
          </div>
          <div>
            <h1 className="title-xxl" style={{ marginBottom: '1.5rem' }}>
              threatcrush<span className="accent-text">.</span>
            </h1>
            <p
              className="body-lg"
              style={{
                fontFamily: 'var(--font-display)',
                maxWidth: '70ch',
                fontSize: 'clamp(1.4rem, 2.5vw, 2.5rem)',
                lineHeight: 1.25,
                letterSpacing: '-0.02em',
              }}
            >
              <span>Detect.</span>{' '}
              <span style={{ color: 'var(--ink-4)' }}>Reduce.</span>{' '}
              <span style={{ color: 'var(--ink-4)' }}>Respond.</span>{' '}
              <span style={{ color: 'var(--ink-4)' }}>
                Strike back<span className="cursor" style={{ background: 'var(--accent)' }} />
              </span>
            </p>
            <div className="pill-row">
              <span className="pill">
                <span className="pill-dot" />
                Lifetime $499 · pay once
              </span>
              <span className="pill">MIT-licensed core</span>
              <span className="pill">CTEM + SIEM/EDR/SOC</span>
              <span className="pill">MITRE · D3FEND · Sigma · OCSF</span>
            </div>
          </div>
        </div>
      </>
    ),
  },
  {
    id: 'premise',
    label: 'The premise',
    render: ({ num, total }) => (
      <>
        <Chrome num={`${num} / ${total}`} label="The premise" />
        <div className="content" style={{ justifyContent: 'center' }}>
          <span className="eyebrow">The premise</span>
          <h2 className="title-xl" style={{ maxWidth: '24ch' }}>
            <span className="strike">Patch management</span> is no longer the bottleneck.
            <br />
            <span className="accent-text">Continuous exposure</span> is.
          </h2>
          <div className="era-row">
            <div>
              <div className="era-year">2014</div>
              <p className="body-lg">
                A SOC analyst triaged a quarterly vuln report. The hard part was prioritizing CVEs.
              </p>
            </div>
            <div className="era-divider" aria-hidden />
            <div>
              <div className="era-year accent-text">2026</div>
              <p className="body-lg">
                AI agents probe your perimeter every hour — and your team{' '}
                <span style={{ color: 'var(--warn)' }}>finds out three weeks later</span> from a
                stale dashboard.
              </p>
            </div>
          </div>
        </div>
      </>
    ),
  },
  {
    id: 'problem',
    label: 'Problem',
    render: ({ num, total }) => (
      <>
        <Chrome num={`${num} / ${total}`} label="Problem" />
        <div className="content">
          <div
            className="row"
            style={{ alignItems: 'flex-end', justifyContent: 'space-between', gap: '2rem', marginBottom: '2rem' }}
          >
            <div>
              <span className="eyebrow">Problem</span>
              <h2 className="title-lg">
                Defense means stitching
                <br />
                <span className="accent-text">30+ tools.</span>
              </h2>
            </div>
            <p className="body" style={{ maxWidth: '42ch', textAlign: 'right' }}>
              Each one has its own agent, schema, license, and quirks. Each one can silently miss
              the attack that finally lands.
            </p>
          </div>
          <div className="chip-grid">
            {[
              'Vuln scanners',
              'EDR agents',
              'SIEM',
              'SOAR',
              'XDR',
              'Attack-surface',
              'CSPM',
              'CWPP',
              'CIEM',
              'WAF',
              'IDS / IPS',
              'NDR',
              'DNS firewalls',
              'Honeypots',
              'Deception',
              'Threat intel',
              'SAST',
              'DAST',
              'IAST',
              'SCA',
              'Secrets scanners',
              'Container scanners',
              'K8s admission',
              'Cloud audit',
              'Pentest tooling',
              'Bug bounty triage',
              'Phishing sims',
              'Email security',
              'MDM',
              'PAM',
              'IAM',
              'Compliance · SOC2 · PCI',
              'Log shippers',
              'Ticketing · Jira',
              'PagerDuty',
              'Audit trails',
            ].map((t) => (
              <div key={t} className="chip-cell">
                <span className="bullet" />
                {t}
              </div>
            ))}
            <div className="chip-cell is-dashed">
              <span className="bullet" />
              …and 12 more
            </div>
          </div>
          <div className="problem-footer">
            <span className="arrow">→</span>
            <span>
              A stack that costs a <span style={{ color: 'var(--ink)' }}>Fortune-500 team millions</span>{' '}
              is a wall that stops <span style={{ color: 'var(--ink)' }}>every indie ops team</span>{' '}
              from getting started at all.
            </span>
          </div>
        </div>
      </>
    ),
  },
  {
    id: 'why-now',
    label: 'Why now',
    bg: 'paper',
    dotgrid: true,
    render: ({ num, total }) => (
      <>
        <Chrome num={`${num} / ${total}`} label="Why now" />
        <div className="content why-now" style={{ justifyContent: 'center' }}>
          <div className="why-now-head">
            <span className="eyebrow">Why now</span>
            <span className="why-now-stamp">
              <span className="why-now-stamp-dot" />
              Q2 · 2026
            </span>
          </div>
          <h2 className="title-xl why-now-headline">
            Attackers ship at <span className="serif">100×</span>
            <br />
            human velocity. Defenders run at{' '}
            <span className="mono why-now-zero">1×</span>.
          </h2>
          <hr className="why-now-rule" aria-hidden />
          <div className="metric-row why-now-metrics">
            <div className="metric">
              <div className="why-now-tag">Audience</div>
              <div className="n">28M</div>
              <div className="l">Linux servers running on the public internet</div>
            </div>
            <div className="metric">
              <div className="why-now-tag">Gap</div>
              <div className="n">~0</div>
              <div className="l">Single agents covering CTEM + SIEM in one binary</div>
            </div>
            <div className="metric">
              <div className="why-now-tag">Market</div>
              <div className="n">$215B</div>
              <div className="l">Global cybersecurity spend, 2026 (Gartner)</div>
            </div>
          </div>
          <p className="why-now-quote mono">
            <span className="why-now-quote-mark">//</span> whoever owns the agent on the box owns the{' '}
            <span className="why-now-quote-hi">detection layer</span> for the next ten years.
          </p>
        </div>
      </>
    ),
  },
  {
    id: 'solution',
    label: 'Solution',
    render: ({ num, total }) => (
      <>
        <Chrome num={`${num} / ${total}`} label="Solution" />
        <div className="content">
          <span className="eyebrow">Solution</span>
          <h2 className="title-lg" style={{ marginBottom: '2.5rem' }}>
            One agent. <span className="accent-text">Two layers.</span>
          </h2>
          <div className="solution-row">
            <div className="term">
              <div className="term-header">
                <div className="lights">
                  <span />
                  <span />
                  <span />
                </div>
                <div className="title">root@edge-01 — threatcrush v1.0</div>
                <div style={{ width: 56 }} />
              </div>
              <div className="term-body">
                <div className="line">
                  <span className="prompt">
                    <span className="user">root</span>
                    <span className="sep">@</span>edge-01 <span className="sep">:~#</span>
                  </span>{' '}
                  <span className="cmd">
                    <span className="kw">threatcrush</span> <span className="arg">monitor</span>
                  </span>
                </div>
                <div className="line out out-ok">
                  watching all ports · nginx · sshd · postgres · loaded 1,247 sigs
                </div>
                <div className="line out out-warn">
                  SQLi attempt — :443 185.43.21.8 → /api/users?id=1 OR 1=1
                </div>
                <div className="line out out-warn">
                  SSH brute force — :22 91.232.105.3 → 47 failed attempts
                </div>
                <div className="line out out-ok">
                  ssh-guard banned 91.232.105.3 · tar-pit engaged
                </div>
                <div className="spacer" />
                <div className="line">
                  <span className="prompt">
                    <span className="user">root</span>
                    <span className="sep">@</span>edge-01 <span className="sep">:~#</span>
                  </span>{' '}
                  <span className="cmd">
                    <span className="kw">threatcrush</span> <span className="arg">scan</span> ./src
                  </span>
                </div>
                <div className="line out out-ok">
                  3 secrets · 7 CVEs (2 critical) · 4 misconfigs · sigma rules emitted
                </div>
                <div className="spacer" />
                <div className="line">
                  <span className="prompt">
                    <span className="user">root</span>
                    <span className="sep">@</span>edge-01 <span className="sep">:~#</span>
                  </span>{' '}
                  <span className="cmd">
                    <span className="kw">threatcrush</span> <span className="arg">pentest</span>{' '}
                    https://api.acme.io
                  </span>
                </div>
                <div className="line out out-pending">
                  fuzzing endpoints… mapping ATT&amp;CK techniques · proposing fix #1 of 3
                </div>
                <div>
                  <span className="cursor" />
                </div>
              </div>
            </div>
            <div className="verb-stack">
              <div className="verb-card">
                <div className="verb-tag">01 — detect</div>
                <div className="verb-label">Every port. Every protocol. Live signatures.</div>
              </div>
              <div className="verb-card">
                <div className="verb-tag">02 — reduce</div>
                <div className="verb-label">Code, deps, config — fix exposure before it ships.</div>
              </div>
              <div className="verb-card">
                <div className="verb-tag">03 — respond</div>
                <div className="verb-label">Slack · webhook · auto-ban · honeypot · tar-pit.</div>
              </div>
              <div className="verb-card">
                <div className="verb-tag">04 — strike back</div>
                <div className="verb-label">Deception, abuse reports, attacker-cost economics.</div>
              </div>
            </div>
          </div>
        </div>
      </>
    ),
  },
  {
    id: 'architecture',
    label: 'Architecture',
    render: ({ num, total }) => (
      <>
        <Chrome num={`${num} / ${total}`} label="Architecture" />
        <div className="content">
          <span className="eyebrow">Architecture</span>
          <h2 className="title-lg" style={{ marginBottom: '3rem' }}>
            One daemon. <span className="accent-text">Pluggable modules.</span>
          </h2>
          <svg viewBox="0 0 1600 560" className="arch-svg" preserveAspectRatio="xMidYMid meet">
            <defs>
              <marker
                id="arr"
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="8"
                markerHeight="8"
                orient="auto-start-reverse"
              >
                <path d="M0,0 L10,5 L0,10 z" fill="#00ff41" />
              </marker>
            </defs>
            <g transform="translate(40, 180)">
              <rect x="0" y="0" width="260" height="200" rx="14" fill="#0d1117" stroke="#1a2332" />
              <text x="20" y="36" fontFamily="inherit" fontSize="13" fill="#8b949e" letterSpacing="1">
                THREATCRUSHD.CONF
              </text>
              <text x="20" y="78" fontFamily="inherit" fontSize="16" fill="#e6edf3">
                modules: <tspan fill="#00ff41">all</tspan>
              </text>
              <text x="20" y="104" fontFamily="inherit" fontSize="16" fill="#e6edf3">
                alerts: <tspan fill="#00ff41">slack,sms</tspan>
              </text>
              <text x="20" y="130" fontFamily="inherit" fontSize="16" fill="#e6edf3">
                api: <tspan fill="#7dd3fc">127.0.0.1</tspan>
              </text>
              <text x="20" y="156" fontFamily="inherit" fontSize="16" fill="#e6edf3">
                license: <tspan fill="#00ff41">lifetime</tspan>
              </text>
              <text x="20" y="182" fontFamily="inherit" fontSize="16" fill="#e6edf3">
                strike-back: <tspan fill="#ff5555">on</tspan>
              </text>
            </g>
            <g transform="translate(420, 140)">
              <rect x="0" y="0" width="760" height="280" rx="16" fill="#0a0e14" stroke="#1a2332" />
              <text x="30" y="34" fontFamily="inherit" fontSize="13" fill="#8b949e" letterSpacing="1">
                THREATCRUSHD CORE
              </text>
              {[
                { x: 30, n: '01', v: 'detect', b: ['• network-monitor', '• log-watcher', '• ssh-guard'] },
                { x: 210, n: '02', v: 'reduce', b: ['• code-scanner', '• pentest-engine', '• dns-monitor'] },
                { x: 390, n: '03', v: 'respond', b: ['• firewall-rules', '• alert-system', '• tar-pit'] },
                { x: 570, n: '04', v: 'strike', b: ['• honeypot', '• deception', '• abuse-reporter'] },
              ].map((c) => (
                <g key={c.n} transform={`translate(${c.x}, 60)`}>
                  <rect x="0" y="0" width="160" height="180" rx="10" fill="#0d1117" stroke="#14202f" />
                  <text x="16" y="32" fontFamily="inherit" fontSize="12" fill="#00ff41" letterSpacing="1">
                    {c.n}
                  </text>
                  <text x="16" y="60" fontFamily="inherit" fontSize="22" fill="#e6edf3" fontWeight="500">
                    {c.v}
                  </text>
                  {c.b.map((b, i) => (
                    <text key={b} x="16" y={90 + i * 20} fontFamily="inherit" fontSize="11" fill="#8b949e">
                      {b}
                    </text>
                  ))}
                </g>
              ))}
            </g>
            <g transform="translate(1260, 40)">
              <text x="0" y="20" fontFamily="inherit" fontSize="13" fill="#8b949e" letterSpacing="1">
                CLIENTS
              </text>
              {[
                { y: 36, label: '▸ CLI · TUI dashboard' },
                { y: 78, label: '▸ Desktop · Linux/Mac/Win' },
                { y: 120, label: '▸ Mobile · iOS / Android' },
                { y: 162, label: '▸ Browser extension' },
                { y: 204, label: '▸ HTTPS API · webhooks' },
              ].map((r) => (
                <g key={r.y}>
                  <rect x="0" y={r.y} width="300" height="34" rx="8" fill="#0d1117" stroke="#1a2332" />
                  <text x="16" y={r.y + 22} fontFamily="inherit" fontSize="15" fill="#e6edf3">
                    {r.label}
                  </text>
                </g>
              ))}
              <rect x="0" y="246" width="300" height="34" rx="8" fill="#00ff41" stroke="#00ff41" />
              <text x="16" y="268" fontFamily="inherit" fontSize="15" fill="#050505" fontWeight="500">
                ∑ 5 surfaces · 1 daemon
              </text>
            </g>
            <line x1="300" y1="280" x2="420" y2="280" stroke="#00ff41" strokeWidth="2" markerEnd="url(#arr)" />
            {[76, 136, 196, 256, 316, 376].map((y) => (
              <line
                key={y}
                x1="1180"
                y1="280"
                x2="1260"
                y2={y}
                stroke="#00ff41"
                strokeWidth="2"
                markerEnd="url(#arr)"
              />
            ))}
            <path
              d="M 1180 420 C 1180 520, 420 520, 420 420"
              fill="none"
              stroke="#7dd3fc"
              strokeWidth="2"
              strokeDasharray="6 6"
              markerEnd="url(#arr)"
              opacity="0.7"
            />
            <text x="730" y="540" fontFamily="inherit" fontSize="14" fill="#7dd3fc" letterSpacing="1">
              telemetry → cloud → smarter signatures → next push
            </text>
          </svg>
        </div>
      </>
    ),
  },
  {
    id: 'surfaces',
    label: 'Coverage',
    render: ({ num, total }) => (
      <>
        <Chrome num={`${num} / ${total}`} label="Coverage" />
        <div className="content">
          <div className="surface-head">
            <div>
              <span className="eyebrow">Coverage</span>
              <h2 className="title-lg">
                12 core modules. 5 clients.
                <br />
                <span style={{ color: 'var(--ink-4)' }}>One license unlocks all.</span>
              </h2>
            </div>
            <div>
              <div className="surface-count-n">12</div>
              <div className="surface-count-l">core modules</div>
            </div>
          </div>
          <div className="surface-grid">
            <div className="surface-col">
              <div className="surface-col-h">Detect</div>
              {[
                ['done', 'network-monitor'],
                ['done', 'log-watcher'],
                ['done', 'ssh-guard'],
                ['done', 'dns-monitor'],
                ['live', 'firewall-rules'],
                ['', 'k8s-watcher'],
                ['', 'docker-monitor'],
              ].map(([s, t]) => (
                <div
                  key={t}
                  className={`chip-cell ${s === 'done' ? 'is-done' : s === 'live' ? 'is-live' : ''}`}
                >
                  <span className="bullet" />
                  {t}
                </div>
              ))}
            </div>
            <div className="surface-col">
              <div className="surface-col-h">Reduce</div>
              {[
                ['done', 'code-scanner'],
                ['done', 'secrets-scanner'],
                ['done', 'pentest-engine'],
                ['live', 'dependency-cves'],
                ['live', 'compliance-reporter'],
                ['', 'cloud-audit'],
                ['', 'wordpress-scanner'],
              ].map(([s, t]) => (
                <div
                  key={t}
                  className={`chip-cell ${s === 'done' ? 'is-done' : s === 'live' ? 'is-live' : ''}`}
                >
                  <span className="bullet" />
                  {t}
                </div>
              ))}
            </div>
            <div className="surface-col">
              <div className="surface-col-h">Respond · Strike</div>
              {[
                ['done', 'alert-system'],
                ['done', 'tar-pit'],
                ['done', 'honeypot'],
                ['live', 'deception'],
                ['live', 'abuse-reporter'],
                ['', 'rate-limiter'],
                ['', 'geo-blocker'],
              ].map(([s, t]) => (
                <div
                  key={t}
                  className={`chip-cell ${s === 'done' ? 'is-done' : s === 'live' ? 'is-live' : ''}`}
                >
                  <span className="bullet" />
                  {t}
                </div>
              ))}
            </div>
            <div className="surface-col">
              <div className="surface-col-h">Clients · channels</div>
              {[
                ['done', 'CLI'],
                ['done', 'TUI dashboard'],
                ['done', 'Desktop app'],
                ['done', 'Mobile · iOS / Android'],
                ['live', 'Browser extension'],
                ['live', 'HTTPS API · webhooks'],
                ['live', 'Slack · Discord · email · SMS'],
              ].map(([s, t]) => (
                <div
                  key={t}
                  className={`chip-cell ${s === 'done' ? 'is-done' : s === 'live' ? 'is-live' : ''}`}
                >
                  <span className="bullet" />
                  {t}
                </div>
              ))}
            </div>
          </div>
          <div className="legend">
            <span>
              <span className="dot dot-live" /> shipping
            </span>
            <span>
              <span className="dot dot-beta" /> beta
            </span>
            <span>
              <span className="dot dot-roadmap" /> roadmap Q3
            </span>
          </div>
        </div>
      </>
    ),
  },
  {
    id: 'wedge',
    label: 'Wedge',
    bg: 'accent',
    render: ({ num, total }) => (
      <>
        <Chrome num={`${num} / ${total}`} label="Wedge" />
        <div className="content" style={{ justifyContent: 'center' }}>
          <span className="eyebrow">Our wedge</span>
          <h2 className="title-xl" style={{ color: '#050505', maxWidth: '20ch' }}>
            <span className="serif" style={{ fontWeight: 400 }}>
              One curl
            </span>
            ,<br />
            zero dashboards.
          </h2>
          <p
            className="body-lg"
            style={{
              marginTop: '2rem',
              color: 'rgba(0,0,0,0.8)',
              fontFamily: 'var(--font-display)',
              maxWidth: '60ch',
            }}
          >
            <span className="strong-pen">curl -fsSL threatcrush.com/install.sh | sh</span> drops a
            full SOC on a Linux box in under 60 seconds — daemon, modules, alerts, dashboard.
            Indie-friendly. Enterprise-ready.
          </p>
          <div className="wedge-row">
            <div className="wedge-step">
              <div className="wedge-day">Minute 0</div>
              <div className="wedge-title">curl install</div>
              <div className="wedge-cmd">$ threatcrush init</div>
            </div>
            <div className="wedge-arrow" aria-hidden>
              →
            </div>
            <div className="wedge-step">
              <div className="wedge-day">Minute 1</div>
              <div className="wedge-title">Daemon live</div>
              <div className="wedge-cmd">systemd · all ports · all sigs</div>
            </div>
            <div className="wedge-arrow" aria-hidden>
              →
            </div>
            <div className="wedge-step">
              <div className="wedge-day">Hour 1</div>
              <div className="wedge-title">First attack caught</div>
              <div className="wedge-cmd">SSH brute force · auto-ban · alert</div>
            </div>
            <div className="wedge-arrow" aria-hidden>
              →
            </div>
            <div className="wedge-step wedge-step-accent">
              <div className="wedge-day">Day 7</div>
              <div className="wedge-title">Replaces the stack.</div>
              <div className="wedge-cmd">cancels Snyk, Datadog, CrowdStrike trials</div>
            </div>
          </div>
          <p
            className="mono"
            style={{
              marginTop: 'clamp(2rem, 4vw, 4rem)',
              color: 'rgba(0,0,0,0.65)',
              fontSize: 'clamp(0.8rem, 1vw, 1rem)',
            }}
          >
            // we ran this on ourselves — every threatcrush.com server runs threatcrush.
          </p>
        </div>
      </>
    ),
  },
  {
    id: 'business-model',
    label: 'Business model',
    render: ({ num, total }) => (
      <>
        <Chrome num={`${num} / ${total}`} label="Business model" />
        <div className="content">
          <span className="eyebrow">Business model</span>
          <h2 className="title-lg" style={{ marginBottom: '2rem' }}>
            Lifetime license. <span style={{ color: 'var(--ink-4)' }}>Open-core forever.</span>
          </h2>
          <div className="price-row">
            <div className="price-card">
              <div>
                <div className="price-tag">Open-core</div>
                <div className="price-num">$0</div>
                <div className="price-sub">MIT license · top-of-funnel · trust w/ ops devs</div>
              </div>
              <hr className="price-divider" />
              <ul className="price-bullets">
                <li>→ daemon + core modules</li>
                <li>→ self-host forever</li>
                <li>→ upgrade path to lifetime</li>
              </ul>
            </div>
            <div className="price-card featured">
              <div>
                <div className="price-tag">Lifetime · indie + smb</div>
                <div className="price-num">
                  $499<span className="unit"> / once</span>
                </div>
                <div className="price-sub">$399 with referral · pay once · all updates</div>
              </div>
              <hr className="price-divider" />
              <ul className="price-bullets">
                <li>→ all core modules + future</li>
                <li>→ priority support</li>
                <li>→ private module store</li>
              </ul>
            </div>
            <div className="price-card">
              <div>
                <div className="price-tag">Enterprise · gov</div>
                <div className="price-num">$$$</div>
                <div className="price-sub">contract · air-gap · FedRAMP · ITAR · GSA</div>
              </div>
              <hr className="price-divider" />
              <ul className="price-bullets">
                <li>→ on-prem appliances</li>
                <li>→ FIPS 140-2 build</li>
                <li>→ custom modules · SLAs</li>
              </ul>
            </div>
          </div>
          <div
            className="row gap-xl"
            style={{
              marginTop: '2rem',
              paddingTop: '1.5rem',
              borderTop: '1px solid var(--line)',
              flexWrap: 'wrap',
            }}
          >
            <div className="fill" style={{ minWidth: 280 }}>
              <div
                className="mono"
                style={{
                  fontSize: 'clamp(0.65rem, 0.8vw, 0.8rem)',
                  color: 'var(--ink-4)',
                  letterSpacing: '0.12em',
                  textTransform: 'uppercase',
                  marginBottom: '0.5rem',
                }}
              >
                Recurring revenue
              </div>
              <div className="body" style={{ color: 'var(--ink)' }}>
                AI-enhanced modules are usage-metered — anomaly detection, classification, smart
                alerting. Module marketplace pays a 70/30 split to authors.
              </div>
            </div>
            <div className="fill" style={{ minWidth: 280 }}>
              <div
                className="mono"
                style={{
                  fontSize: 'clamp(0.65rem, 0.8vw, 0.8rem)',
                  color: 'var(--ink-4)',
                  letterSpacing: '0.12em',
                  textTransform: 'uppercase',
                  marginBottom: '0.5rem',
                }}
              >
                Expansion
              </div>
              <div className="body" style={{ color: 'var(--ink)' }}>
                Per-host metering, team plans, gov / defense contracts — no per-seat tax that
                punishes growth, no per-event fee that punishes visibility.
              </div>
            </div>
          </div>
        </div>
      </>
    ),
  },
  {
    id: 'moat',
    label: 'Moat',
    render: ({ num, total }) => (
      <>
        <Chrome num={`${num} / ${total}`} label="Moat" />
        <div className="content">
          <span className="eyebrow">Why we win</span>
          <h2 className="title-lg">Why the moat compounds.</h2>
          <ul className="moat-list">
            <li>
              <strong>Open-core distribution.</strong> Every install on a public server is a passive
              telemetry node — signatures sharpen as the deployed base grows. Closed competitors
              can't replicate this without buying it.
            </li>
            <li>
              <strong>Standards-native.</strong> MITRE ATT&amp;CK, D3FEND, Sigma, OCSF, NIST CSF
              speak directly into the same SOC pipelines incumbents already buy. We integrate where
              they refuse to.
            </li>
            <li>
              <strong>Modules marketplace.</strong> Anyone can ship a paid module — WordPress
              scanners, K8s admission, cloud-audit, compliance reports. We collect 30% on every sale
              and own the standard interface.
            </li>
            <li>
              <strong>Linux-first.</strong> 28M public Linux servers, no Windows EDR vendor really
              wants them. We do. As the default agent on indie+SMB Linux fleets, we earn the right
              to expand into containers, k8s, and cloud.
            </li>
          </ul>
        </div>
      </>
    ),
  },
  {
    id: 'roadmap',
    label: 'Roadmap',
    render: ({ num, total }) => (
      <>
        <Chrome num={`${num} / ${total}`} label="Roadmap" />
        <div className="content">
          <span className="eyebrow">Roadmap</span>
          <h2 className="title-lg">The next 12 months.</h2>
          <div className="timeline">
            <div className="timeline-item">
              <div className="q-tag">Phase 1</div>
              <div>
                <strong>MVP — shipping.</strong> CLI + daemon, log-watcher, ssh-guard, alert system,
                systemd, waitlist + referral live at threatcrush.com.
              </div>
            </div>
            <div className="timeline-item">
              <div className="q-tag">Phase 2</div>
              <div>
                <strong>Beta — Q3 2026.</strong> network-monitor (pcap), code-scanner,
                pentest-engine, module store + publish, license activation. First 100 paying
                lifetime customers.
              </div>
            </div>
            <div className="timeline-item">
              <div className="q-tag">Phase 3</div>
              <div>
                <strong>Launch — Q4 2026.</strong> dns-monitor, firewall-rules, dashboard web UI,
                cloud sync, AI-enhanced modules generally available.
              </div>
            </div>
            <div className="timeline-item">
              <div className="q-tag">Phase 4</div>
              <div>
                <strong>Enterprise + gov — 2027.</strong> air-gap appliances, FedRAMP, FIPS 140-2,
                GSA Schedule pricing — the security stack the SLED + DoD market keeps asking for.
              </div>
            </div>
          </div>
        </div>
      </>
    ),
  },
  {
    id: 'ask',
    label: 'The ask',
    render: ({ num, total }) => (
      <>
        <Chrome num={`${num} / ${total}`} label="The ask" />
        <div className="content">
          <div className="ask-row">
            <div className="stack">
              <span className="eyebrow">The ask</span>
              <h2 className="title-xl" style={{ marginBottom: '1.5rem' }}>
                Raising
                <br />
                <span className="accent-text">$100k</span> seed.
              </h2>
              <p className="body-lg" style={{ maxWidth: '42ch' }}>
                Live crowd-fund at threatcrush.com/investors — credit card or crypto via CoinPay.
                12 months of runway to lock the default detection agent on Linux before incumbents
                notice.
              </p>
              <div className="uof">
                <div className="uof-head">Use of funds</div>
                <div className="uof-row">
                  <span className="uof-pct">55%</span>
                  <span>Engineering — module SDK, pcap stack, pentest engine, dashboard</span>
                </div>
                <div className="uof-row">
                  <span className="uof-pct">20%</span>
                  <span>AI R&amp;D — anomaly detection, smart alerting, threat classification</span>
                </div>
                <div className="uof-row">
                  <span className="uof-pct">15%</span>
                  <span>Compliance — FedRAMP / FIPS / SOC2 prep, security audits</span>
                </div>
                <div className="uof-row">
                  <span className="uof-pct">10%</span>
                  <span>GTM — devrel, content, launch, community modules program</span>
                </div>
              </div>
            </div>
            <div className="stack gap-m">
              <div
                className="mono"
                style={{
                  fontSize: 'clamp(0.65rem, 0.8vw, 0.8rem)',
                  color: 'var(--ink-4)',
                  letterSpacing: '0.12em',
                  textTransform: 'uppercase',
                }}
              >
                Traction · in-flight
              </div>
              <div className="traction-grid">
                <div className="traction-card">
                  <div className="traction-n accent-text">Live</div>
                  <div className="traction-l">Crowd-fund @ threatcrush.com/investors</div>
                </div>
                <div className="traction-card">
                  <div className="traction-n accent-text">Open</div>
                  <div className="traction-l">Waitlist + referral program</div>
                </div>
                <div className="traction-card">
                  <div className="traction-n">12</div>
                  <div className="traction-l">Core modules scaffolded</div>
                </div>
                <div className="traction-card">
                  <div className="traction-n">MIT</div>
                  <div className="traction-l">Core open at profullstack/threatcrush</div>
                </div>
              </div>
              <div className="traction-note">
                <span className="accent-text">$</span> threatcrush metrics — live
                <br />
                <span style={{ color: 'var(--ink-5)' }}>—</span> CC + crypto rails open · backers
                live · we will{' '}
                <span style={{ color: 'var(--ink)' }}>not fabricate numbers</span>.
              </div>
              <a
                href="mailto:invest@threatcrush.com"
                className="mono"
                style={{
                  alignSelf: 'flex-start',
                  marginTop: '1rem',
                  padding: '0.9rem 1.5rem',
                  background: 'var(--accent)',
                  color: '#050505',
                  borderRadius: 10,
                  fontWeight: 500,
                  fontSize: 'clamp(0.9rem, 1.1vw, 1.1rem)',
                  textDecoration: 'none',
                  letterSpacing: '-0.01em',
                  boxShadow: '0 0 30px -5px rgba(0, 255, 65, 0.5)',
                }}
              >
                invest@threatcrush.com →
              </a>
            </div>
          </div>
        </div>
      </>
    ),
  },
  {
    id: 'close',
    label: 'Thank you',
    gridlines: true,
    scanlines: true,
    render: ({ num, total }) => (
      <>
        <Chrome num={`${num} / ${total}`} label="Thank you" />
        <div
          className="glow-orb"
          style={{ top: '20%', right: '15%', width: 380, height: 380, background: 'rgba(0, 255, 65, 0.15)' }}
        />
        <div className="content" style={{ justifyContent: 'space-between' }}>
          <div>
            <span className="eyebrow">Profullstack, Inc. · 2026</span>
          </div>
          <div>
            <h2
              className="title-xxl"
              style={{ fontSize: 'clamp(2.75rem, 7vw, 7rem)', lineHeight: 0.96 }}
            >
              Crush every threat
              <br />
              before it crushes
              <br />
              <span className="accent-text">you.</span>
            </h2>
            <div className="close-contacts">
              <div>
                <div className="close-label">Contact</div>
                <div className="close-val">invest@threatcrush.com</div>
              </div>
              <div>
                <div className="close-label">Source</div>
                <div className="close-val">github.com/profullstack/threatcrush</div>
              </div>
              <div>
                <div className="close-label">Back us</div>
                <div className="close-val">threatcrush.com/investors</div>
              </div>
              <div>
                <div className="close-label">Try it</div>
                <div className="close-val accent-text">
                  $ curl threatcrush.com/install.sh | sh
                  <span className="cursor" />
                </div>
              </div>
            </div>
          </div>
        </div>
      </>
    ),
  },
];

export default function Deck() {
  const [index, setIndex] = useState(0);
  const [isPrint, setIsPrint] = useState(false);
  const total = slides.length;
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    setIsPrint(new URLSearchParams(window.location.search).get('print') === '1');
  }, []);

  const go = useCallback(
    (next: number) => {
      setIndex(Math.max(0, Math.min(total - 1, next)));
    },
    [total]
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown' || e.key === 'PageDown' || e.key === ' ') {
        e.preventDefault();
        go(index + 1);
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp' || e.key === 'PageUp') {
        e.preventDefault();
        go(index - 1);
      } else if (e.key === 'Home') {
        e.preventDefault();
        go(0);
      } else if (e.key === 'End') {
        e.preventDefault();
        go(total - 1);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [index, go, total]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const hash = parseInt(window.location.hash.replace('#', ''), 10);
    if (!Number.isNaN(hash) && hash >= 1 && hash <= total) {
      setIndex(hash - 1);
    }
  }, [total]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    history.replaceState(null, '', `#${index + 1}`);
  }, [index]);

  if (isPrint) {
    return (
      <div className="deck-print">
        {slides.map((slide, i) => {
          const pad = (n: number) => String(n).padStart(2, '0');
          const num = `${pad(i + 1)} / ${pad(total)}`;
          return (
            <div key={slide.id} className="deck-print-page">
              <div className={`slide bg-${slide.bg ?? 'ink'}`}>
                {slide.gridlines && <div className="gridlines" />}
                {slide.scanlines && <div className="scanlines" />}
                {slide.dotgrid && <div className="dotgrid" />}
                {slide.render({ num: num.split(' / ')[0], total })}
              </div>
            </div>
          );
        })}
      </div>
    );
  }

  return (
    <div className="deck-root" ref={containerRef}>
      <div className="deck-progress" aria-hidden>
        <div className="deck-progress-bar" style={{ width: `${((index + 1) / total) * 100}%` }} />
      </div>

      <div className="deck-stage">
        {slides.map((slide, i) => {
          const pad = (n: number) => String(n).padStart(2, '0');
          const num = `${pad(i + 1)} / ${pad(total)}`;
          return (
            <div
              key={slide.id}
              className={`deck-slide ${i === index ? 'is-active' : ''}`}
              aria-hidden={i !== index}
            >
              <div className={`slide bg-${slide.bg ?? 'ink'}`}>
                {slide.gridlines && <div className="gridlines" />}
                {slide.scanlines && <div className="scanlines" />}
                {slide.dotgrid && <div className="dotgrid" />}
                {slide.render({ num: num.split(' / ')[0], total })}
              </div>
            </div>
          );
        })}
      </div>

      <div className="deck-click-left" onClick={() => go(index - 1)} aria-label="Previous slide" />
      <div className="deck-click-right" onClick={() => go(index + 1)} aria-label="Next slide" />

      <div className="deck-controls">
        <button
          type="button"
          className="deck-btn"
          onClick={() => go(index - 1)}
          disabled={index === 0}
          aria-label="Previous"
        >
          ◀
        </button>
        <div className="deck-counter">
          {String(index + 1).padStart(2, '0')} / {String(total).padStart(2, '0')}
        </div>
        <button
          type="button"
          className="deck-btn"
          onClick={() => go(index + 1)}
          disabled={index === total - 1}
          aria-label="Next"
        >
          ▶
        </button>
        <a className="deck-pdf" href="/threatcrush-deck.pdf" target="_blank" rel="noreferrer">
          ↓ PDF
        </a>
        <a className="deck-exit" href="/">
          ← back to site
        </a>
      </div>
    </div>
  );
}
