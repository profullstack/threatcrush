# Shields — firewall port-exposure self-test

`threatcrush shields` probes the TCP ports of a connection from the outside and
reports each as **Open**, **Closed** or **Stealth** — the same firewall self-test
popularised by GRC's ShieldsUP!. This is an independent re-implementation of that
idea; "ShieldsUP!" is a trademark of Gibson Research Corporation, and ThreatCrush
is not affiliated with or endorsed by GRC.

## Safety

Shields only tests **your own** connection, or a host you are authorized to test.
- With no argument it resolves your machine's public IPv4 (via `my.ip.pit.world`,
  then ipify) and tests that.
- The hosted web version at `/shields` (threatcrush.com) only ever scans the IP
  you are connecting from. It never accepts a target address — you cannot point
  it at anyone else.

## The three states

| State | Meaning |
|-------|---------|
| **Open** | The host accepted the TCP connection — the port is reachable and something is listening. |
| **Closed** | The host actively refused (RST / `ECONNREFUSED`) — reachable, nothing listening. Your machine is *visible* to the Internet. |
| **Stealth** | No answer before the timeout — a firewall silently dropped the packet. The port (ideally the whole machine) is invisible. |

Perfect stealth is every port silent. A wall of "closed" still means your machine
is announcing itself; for full stealth, configure your firewall to **DROP** rather
than **REJECT** unsolicited packets.

## Tests

```sh
threatcrush shields                 # Common Ports against your own public IP
threatcrush shields --file-sharing  # NetBIOS/SMB only (135–139, 445)
threatcrush shields --all           # All service ports 0–1055 (1056 ports)
threatcrush shields 203.0.113.10    # A host you own / are authorized to test
threatcrush shields --ports 22,80,443,8000-8010
threatcrush shields --json          # machine-readable
```

Flags: `--timeout <ms>` (per-port, default 3000), `--concurrency <n>` (default 64).

High-risk services (Telnet, file sharing, RDP, VNC, MySQL/Postgres/MSSQL) are
graded **high** when open; other open ports are **medium**.

> Note: scanning your own public IP from the *same* machine can hairpin through
> your router and under-report. A cloud/VPS box reflects its real exposure; for a
> home connection, use the hosted web test for a true outside view.
