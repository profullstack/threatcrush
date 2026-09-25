import { createApp } from '@profullstack/hqtui';
import { IpcClient } from '../core/ipc-client.js';
import { PATHS } from '../daemon/paths.js';
import type { ThreatEvent } from '../types/events.js';
import { reducer, initialState, isBanned, selectedIp, type Action, type State } from './state.js';
import { formatDuration } from '../daemon/firewall/backoff.js';
import { threatcrushTheme } from './theme.js';
import { renderDashboard } from './view.js';
import { demoEvent } from './demo.js';

export interface DashboardOptions {
  /** Replay canned events instead of connecting. Never entered by accident. */
  demo?: boolean;
}

const RECONNECT_MS = 2000;
const POLL_MS = 2000;

export async function startDashboard(options: DashboardOptions = {}): Promise<void> {
  const app = await createApp({
    theme: threatcrushTheme,
    title: 'ThreatCrush — Live Security Dashboard',
    mouse: true,
    fps: 30,
    // We own quitting so the IPC socket is closed before the process goes.
    quitKeys: [],
  });

  let state: State = initialState();
  const dispatch = (action: Action): void => {
    state = reducer(state, action);
    app.invalidate();
  };

  let client: IpcClient | null = null;
  let stopped = false;
  const timers: NodeJS.Timeout[] = [];
  // Assigned when a live connection exists; a no-op in demo mode.
  let refreshBans: () => Promise<void> = async () => {};

  const every = (ms: number, fn: () => void): void => {
    const t = setInterval(fn, ms);
    t.unref?.();
    timers.push(t);
  };

  const teardown = (): void => {
    stopped = true;
    for (const t of timers) clearInterval(t);
    timers.length = 0;
    try { client?.close(); } catch { /* already gone */ }
    client = null;
  };

  // ---------------------------------------------------------------- demo

  if (options.demo) {
    dispatch({ type: 'connection_lost', label: 'demo mode — canned events, no daemon' });
    let i = 0;
    every(900, () => dispatch({ type: 'event', event: demoEvent(i++) }));
  } else {
    // ------------------------------------------------------------ live
    //
    // The old dashboard probed for a daemon exactly once, at startup, and
    // silently showed fake data forever if it missed. This keeps looking, so
    // `threatcrush start` in another pane brings the screen to life on its own.

    const onEvent = (event: ThreatEvent): void => {
      if (!stopped) dispatch({ type: 'event', event });
      // A ban the daemon decided on by itself shows up as an event; pull the
      // list straight away so the row is marked before the next poll.
      if (!stopped && event.module === 'firewall-rules') void refreshBans();
    };

    refreshBans = async (): Promise<void> => {
      if (!client || stopped) return;
      try {
        const reply = await client.blocklist();
        dispatch({ type: 'blocklist', reply });
      } catch {
        // An older daemon has no `blocklist` method. The rest of the screen
        // keeps working; the BANNED panel just stays empty.
      }
    };

    const poll = async (): Promise<void> => {
      if (!client || stopped) return;
      try {
        // `status` carries the daemon's own in-memory tally and module list.
        // The `counters` method reads SQLite, which returns zeroes whenever the
        // state DB failed to open — that is why the header used to read 0
        // events while the feed was visibly streaming.
        const status = await client.status();
        dispatch({ type: 'connected', label: `daemon pid ${status.pid}`, status });

        // Source ranking is the one panel that genuinely needs the DB. Let it
        // fail on its own rather than taking the connection down with it.
        const top = await client.topSources(8).catch(() => []);
        dispatch({ type: 'top', top });

        // The ban list comes from the daemon's own memory, not SQLite, so it
        // survives a state DB that never opened.
        await refreshBans();
      } catch {
        try { client?.close(); } catch { /* already gone */ }
        client = null;
        dispatch({ type: 'connection_lost', label: 'daemon went away — retrying' });
      }
    };

    const connect = async (): Promise<void> => {
      if (client || stopped) return;
      if (!IpcClient.isDaemonRunning()) {
        if (state.connection !== 'lost') {
          dispatch({ type: 'connection_lost', label: `no daemon at ${PATHS.socket}` });
        }
        return;
      }

      dispatch({ type: 'searching', label: 'connecting to threatcrushd...' });
      const next = new IpcClient({ onEvent });
      try {
        await next.connect();
        const status = await next.status();
        await next.subscribe(['event', 'module']).catch(() => { /* pushes are optional */ });
        client = next;
        dispatch({ type: 'connected', label: `daemon pid ${status.pid}`, status });

        // Backfill so the feed is not empty on a daemon that has been up for
        // hours. Best-effort: it reads SQLite, which may be unavailable.
        try {
          const recent = await next.recentEvents(100);
          for (const event of recent) {
            dispatch({ type: 'event', event: { ...event, timestamp: new Date(event.timestamp) } });
          }
        } catch { /* no history is fine */ }

        await poll();
      } catch (err) {
        try { next.close(); } catch { /* already gone */ }
        dispatch({ type: 'connection_lost', label: `daemon unreachable: ${(err as Error).message}` });
      }
    };

    void connect();
    every(RECONNECT_MS, () => { if (!client) void connect(); });
    every(POLL_MS, () => { void poll(); });
  }

  // Drives the events/sec graph. One slot per second, always.
  every(1000, () => dispatch({ type: 'tick' }));

  // --------------------------------------------------------------- input

  const quit = (): void => {
    teardown();
    app.stop();
  };

  /**
   * Ban or unban whatever is selected. Both go through the daemon rather than
   * shelling out here: it owns the firewall backend, the protected set and the
   * escalation ladder, and a dashboard writing its own rules would be a second
   * source of truth for what is blocked.
   */
  const banSelected = async (): Promise<void> => {
    const ip = selectedIp(state);
    if (state.busy) return;
    if (!ip) {
      dispatch({ type: 'notice', text: 'select a source first (tab)', tone: 'error' });
      return;
    }
    if (!client) {
      dispatch({ type: 'notice', text: 'no daemon — cannot ban', tone: 'error' });
      return;
    }
    if (isBanned(state, ip)) {
      dispatch({ type: 'notice', text: `${ip} is already banned`, tone: 'error' });
      return;
    }

    dispatch({ type: 'busy', busy: true });
    try {
      const entry = await client.block(ip, 'banned from dashboard');
      const ttl = formatDuration(Math.round((entry.expires_at - Date.now()) / 1000));
      dispatch({ type: 'notice', text: `banned ${ip} for ${ttl} (#${entry.strikes})`, tone: 'ok' });
    } catch (err) {
      dispatch({ type: 'notice', text: `ban failed: ${(err as Error).message}`, tone: 'error' });
    } finally {
      dispatch({ type: 'busy', busy: false });
      await refreshBans();
    }
  };

  const unbanSelected = async (): Promise<void> => {
    const ip = selectedIp(state);
    if (state.busy) return;
    if (!ip) {
      dispatch({ type: 'notice', text: 'select a source first (tab)', tone: 'error' });
      return;
    }
    if (!client) {
      dispatch({ type: 'notice', text: 'no daemon — cannot unban', tone: 'error' });
      return;
    }

    dispatch({ type: 'busy', busy: true });
    try {
      await client.unblock(ip);
      dispatch({ type: 'notice', text: `unbanned ${ip}`, tone: 'ok' });
    } catch (err) {
      dispatch({ type: 'notice', text: `unban failed: ${(err as Error).message}`, tone: 'error' });
    } finally {
      dispatch({ type: 'busy', busy: false });
      await refreshBans();
    }
  };

  app.on('key', (event) => {
    switch (event.key) {
      case 'q':
      case 'escape':
      case 'ctrl+c':
        quit();
        break;
      case 'p':
      case 'space':
        dispatch({ type: 'pause' });
        break;
      case 'r':
        dispatch({ type: 'reset' });
        break;
      case 'tab':
        dispatch({ type: 'focus_next' });
        break;
      case 'b':
        void banSelected();
        break;
      case 'u':
        void unbanSelected();
        break;
      case 'up':
      case 'k':
        // The arrows drive whichever panel has focus: the feed scrolls, the
        // two lists move their selection.
        if (state.focus === 'feed') dispatch({ type: 'scroll', delta: 1 });
        else dispatch({ type: 'select', delta: -1 });
        break;
      case 'down':
      case 'j':
        if (state.focus === 'feed') dispatch({ type: 'scroll', delta: -1 });
        else dispatch({ type: 'select', delta: 1 });
        break;
      case 'pageup':
        dispatch({ type: 'scroll', delta: 10 });
        break;
      case 'pagedown':
        dispatch({ type: 'scroll', delta: -10 });
        break;
      case 'end':
      case 'g':
        dispatch({ type: 'scroll_end' });
        break;
      default:
        break;
    }
  });

  app.render(({ ui, theme }) => {
    renderDashboard(ui, state, theme, {
      demo: options.demo,
      onFeedScroll: (delta) => dispatch({ type: 'scroll', delta: -delta }),
      // One click both focuses the panel and picks the row — the operator
      // should not have to click to focus and click again to select.
      onThreatSelect: (row) => {
        dispatch({ type: 'focus', focus: 'threats' });
        dispatch({ type: 'select_at', index: row });
      },
      onBanSelect: (row) => {
        dispatch({ type: 'focus', focus: 'bans' });
        dispatch({ type: 'select_at', index: row });
      },
    });
  });

  try {
    await app.start();
  } finally {
    teardown();
  }
}
