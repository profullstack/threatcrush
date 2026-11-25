/**
 * Real TCP port prober built on Node sockets. Isolated here so the scoring
 * engine (scan.ts / report.ts) stays free of `node:` imports and portable.
 *
 * Classification follows the classic firewall self-test:
 *  - connection established            → open
 *  - actively refused (RST)            → closed
 *  - no answer before the timeout      → stealth
 */

import net from 'node:net';
import type { PortProber, PortState } from './scan.js';

export const tcpProber: PortProber = (host: string, port: number, timeoutMs: number) =>
  new Promise<PortState>((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (state: PortState) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(state);
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish('open'));
    socket.once('timeout', () => finish('stealth'));
    socket.once('error', (err: NodeJS.ErrnoException) => {
      // ECONNREFUSED = the host sent a RST: reachable but nothing listening.
      // Anything else (host unreachable, reset, etc.) we treat as stealth —
      // no clean "this port is closed" signal came back.
      finish(err.code === 'ECONNREFUSED' ? 'closed' : 'stealth');
    });

    try {
      socket.connect(port, host);
    } catch {
      finish('stealth');
    }
  });
