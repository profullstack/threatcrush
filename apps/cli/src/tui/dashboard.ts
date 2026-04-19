import blessed from 'blessed';
import React from 'react';
import { render } from 'react-blessed';
import { App } from './app.js';
import { IpcClient } from '../core/ipc-client.js';
import { findRunningDaemon } from '../daemon/pidfile.js';
import { closeDB } from '../core/state.js';

export async function startDashboard(): Promise<void> {
  const screen = blessed.screen({
    smartCSR: true,
    fullUnicode: true,
    title: 'ThreatCrush TUI Dashboard',
  });

  let client: IpcClient | null = null;
  if (findRunningDaemon()) {
    client = new IpcClient();
    try {
      await client.connect();
    } catch {
      client = null;
    }
  }

  const exit = () => {
    try { client?.close(); } catch {}
    try { closeDB(); } catch {}
    screen.destroy();
    process.exit(0);
  };

  render(React.createElement(App, { client, onExit: exit }), screen);

  screen.key(['C-c', 'q', 'escape'], exit);
}
