# ThreatCrush — Future Plans

## Hardware Appliance: ThreatCrush Box

### Vision

A plug-and-play hardware security appliance. Plug it into your network via USB-C or Ethernet — instant enterprise-grade threat monitoring with zero configuration.

No cloud dependency. No data leaving your network. Everything runs on-prem.

---

### Form Factors

#### 1. ThreatCrush Stick (USB-C)
- **Size:** USB flash drive form factor
- **Hardware:** ARM SoC (Raspberry Pi Zero 2W class), 512MB RAM, 8GB eMMC
- **Connection:** USB-C (power + data), optional Wi-Fi
- **Use case:** Plug into any server's USB port. Monitors that host's traffic + logs.
- **Price target:** $99-$149

#### 2. ThreatCrush Mini (Inline Appliance)
- **Size:** Raspberry Pi-sized box
- **Hardware:** Raspberry Pi 5 / Orange Pi 5, 4-8GB RAM, 32-64GB eMMC, dual Ethernet
- **Connection:** Inline between router and network (transparent bridge)
- **Use case:** Monitors ALL network traffic for a small office / homelab
- **Features:** Hardware packet inspection, IDS/IPS, DNS filtering
- **Price target:** $249-$399

#### 3. ThreatCrush Rack (1U Server)
- **Size:** Standard 1U rack mount
- **Hardware:** x86_64, 16-64GB RAM, NVMe SSD, 4x 10GbE
- **Connection:** Rack-mounted, inline or SPAN/mirror port
- **Use case:** Data center / enterprise network monitoring
- **Features:** Full IDS/IPS, DPI, 10Gbps throughput, HA clustering
- **Price target:** $2,499-$9,999

---

### How It Works

```
Internet → [Router] → [ThreatCrush Box] → [Your Network]
                              │
                              ├── Inspects all packets
                              ├── Detects threats in real-time
                              ├── Blocks malicious traffic
                              ├── Logs everything locally
                              └── Alerts via email/SMS/webhook
```

#### Stick Mode (passive)
```
[Server] ──USB-C──→ [ThreatCrush Stick]
                          │
                          ├── Reads server logs
                          ├── Monitors network interfaces
                          ├── Runs threatcrushd daemon
                          └── Reports to desktop/mobile app
```

#### Inline Mode (active)
```
[Router] ──ETH1──→ [ThreatCrush Mini] ──ETH2──→ [Switch/Network]
                          │
                          ├── Transparent bridge
                          ├── Deep packet inspection
                          ├── Block/allow rules
                          └── Zero latency (<1ms added)
```

---

### Software Stack

The hardware runs the same ThreatCrush software:

- **OS:** Custom Linux (based on Alpine or Buildroot)
- **Daemon:** `threatcrushd` with all core modules
- **Modules:** Same module system — install from marketplace
- **Updates:** OTA updates via `threatcrush update` or auto-update
- **Config:** Web UI at `http://threatcrush.local:9393` or via `threatcrush tui`
- **Management:** Same desktop/mobile apps connect via E2E encryption
- **API:** Same REST API as cloud version

### Custom Hardware Modules

The hardware enables modules that software-only can't do:

| Module | What it does |
|--------|-------------|
| `packet-inspector` | Deep packet inspection on all traffic (requires inline mode) |
| `traffic-shaper` | QoS and bandwidth management |
| `dns-sinkhole` | Block malicious domains at DNS level (like Pi-hole + threat intel) |
| `vpn-gateway` | Built-in WireGuard VPN for remote access |
| `wifi-monitor` | Detect rogue access points, deauth attacks (requires Wi-Fi adapter) |
| `bluetooth-scanner` | Detect unauthorized Bluetooth devices in range |
| `usb-guard` | Monitor and block unauthorized USB devices on the host |
| `arp-watcher` | Detect ARP spoofing / MITM on local network |
| `ssl-inspector` | TLS interception for internal traffic analysis (BYOCA) |

---

### Hardware + Software Pricing

| Product | Price | Includes |
|---------|-------|----------|
| ThreatCrush Stick | $99-$149 | Hardware + lifetime software license |
| ThreatCrush Mini | $249-$399 | Hardware + lifetime license + all core modules |
| ThreatCrush Rack | $2,499-$9,999 | Hardware + enterprise license + priority support |
| Replacement/Upgrade | At cost | Trade in old hardware for new |

All hardware includes lifetime software updates. No subscriptions. Same module marketplace — buy additional modules if you want them.

---

### Manufacturing Plan

#### Phase 1: Proof of Concept
- Flash ThreatCrush onto Raspberry Pi 5
- Test inline bridge mode with dual Ethernet HAT
- Validate packet inspection performance
- Sell as DIY kit: "Bring your own Pi" ($49 software license)

#### Phase 2: Custom PCB
- Design custom PCB with:
  - ARM Cortex-A76 (or RISC-V)
  - Dual Ethernet (with hardware offload)
  - USB-C for power + management
  - eMMC for storage
  - TPM 2.0 for secure boot
- Partner with PCB manufacturer (PCBWay, JLCPCB)
- Small batch: 100-500 units

#### Phase 3: Mass Production
- Injection-molded enclosure (matte black, green LED accent)
- FCC/CE certification
- Amazon/direct sales
- Enterprise sales team

---

### Branding

- **Color:** Matte black with matrix green (#00ff41) LED strip
- **Logo:** Embossed ThreatCrush shield on top
- **LED indicators:**
  - Green: Secure, monitoring active
  - Yellow: Warnings detected
  - Red: Active threats
  - Blue: Updating / booting
- **Packaging:** Black box, green accent, "Plug in. Stay safe." tagline

---

### Competitive Landscape

| Product | Price | Our Advantage |
|---------|-------|--------------|
| Firewalla | $228-$519 | We're open source, modular, cheaper entry |
| Ubiquiti Dream Machine | $379+ | We focus on security, not routing |
| Snort/Suricata (DIY) | Free (complex) | We're plug-and-play, they're configure-everything |
| CrowdStrike Falcon | $$$$/yr subscription | We're one-time purchase, on-prem, no cloud dependency |
| Palo Alto | $$$$$ | Enterprise pricing vs our $249 entry point |

---

### Timeline

| Phase | Timeline | Milestone |
|-------|----------|-----------|
| Software MVP | Q3 2026 | CLI + daemon + core modules working |
| Pi DIY Kit | Q4 2026 | "Bring your own Pi" bundle |
| Stick prototype | Q1 2027 | USB-C stick hardware prototype |
| Mini prototype | Q2 2027 | Inline appliance prototype |
| Kickstarter/pre-order | Q3 2027 | Fund manufacturing run |
| First shipments | Q4 2027 | Ship Stick + Mini to early backers |
| Rack unit | 2028 | Enterprise hardware |

---

### Revenue Model

```
Software: $499 lifetime license (current)
    ↓
Hardware bundles: $99-$9,999 (includes lifetime license)
    ↓
Module marketplace: Community modules (free + paid)
    ↓
AI usage billing: Metered via CoinPayPortal
    ↓
Enterprise: Custom hardware + support contracts
    ↓
Hardware refresh: Trade-in program for upgrades
```

---

*This document is a living roadmap. Updated as hardware prototyping progresses.*
