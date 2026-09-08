/**
 * Frames for the hqtui.com apps showcase.
 *
 * hqtui.com/apps captures screenshots of applications built on the library. The
 * capture script takes an application directory and imports this file, because
 * only the application knows what a good state looks like.
 *
 * The state is driven through the real reducer from a real connected status and
 * the real demo event script, rather than assembled by hand. A screenshot of a
 * state the reducer cannot actually produce is a picture of something that does
 * not exist, which is the one thing a showcase must never be.
 */
import { threatcrushTheme } from '../apps/cli/src/tui/theme.js';
import { renderDashboard } from '../apps/cli/src/tui/view.js';
import { initialState, reducer, type State } from '../apps/cli/src/tui/state.js';
import { demoEvent } from '../apps/cli/src/tui/demo.js';
import type { DaemonStatusReply } from '../apps/cli/src/daemon/ipc-protocol.js';

const STATUS: DaemonStatusReply = {
  pid: 4242,
  startedAt: '2026-08-30T08:00:00.000Z',
  uptimeSeconds: 14 * 86400 + 6 * 3600,
  version: '0.11.3',
  mode: 'user',
  paths: { config: '/c', log: '/l', state: '/s', socket: '/sock' },
  modules: [
    { name: 'network-monitor', status: 'running', events: 847 },
    { name: 'ssh-guard', status: 'running', events: 47 },
    { name: 'file-integrity', status: 'running', events: 219 },
    { name: 'code-scanner', status: 'stopped', events: 0 },
  ],
  counters: { events: 3891, threats: 4, alerts: 0 },
};

/**
 * The demo script's events, on a fixed clock.
 *
 * `demoEvent` stamps `new Date()`, which is right for a live demo and wrong
 * for a committed screenshot twice over: the image would differ on every
 * regeneration, and ten events sharing one second does not look like a feed.
 * The content still comes from the real script — only the clock is pinned.
 */
const FIRST = Date.parse('2026-09-08T15:12:04.000Z');

function connected(): State {
  let state = reducer(initialState(), {
    type: 'connected',
    label: 'daemon pid 4242',
    status: STATUS,
  });
  for (let i = 0; i < 10; i++) {
    state = reducer(state, {
      type: 'event',
      event: { ...demoEvent(i), timestamp: new Date(FIRST + i * 7000) },
    });
  }
  return reducer(state, {
    type: 'top',
    top: [
      { ip: '91.232.105.3', count: 47 },
      { ip: '45.33.32.156', count: 23 },
      { ip: '185.43.21.8', count: 12 },
      { ip: '103.97.202.44', count: 9 },
    ],
  });
}

const STATE = connected();

export const frames = [
  {
    name: 'threatcrush',
    width: 132,
    height: 36,
    theme: threatcrushTheme,
    draw: ({ ui, theme }: { ui: Parameters<typeof renderDashboard>[0]; theme: Parameters<typeof renderDashboard>[2] }) => {
      // `demo: false` on purpose. The badge it drives says whether the numbers
      // came from a live daemon, and a showcase that quietly flags itself as
      // demo data is advertising the wrong thing.
      renderDashboard(ui, STATE, theme, { demo: false });
    },
  },
];
