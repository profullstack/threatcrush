// Ambient module declarations — kept in a script (no imports) so TypeScript
// picks up `declare module` without treating the file as a module.

declare module 'react-blessed' {
  import type { ReactElement } from 'react';
  import type blessed from 'blessed';
  export function render(element: ReactElement, target: blessed.Widgets.Screen): unknown;
}

declare module 'react-blessed-contrib' {
  export const Grid: unknown;
  export const Donut: unknown;
  export const Sparkline: unknown;
  export const Table: unknown;
  export const Log: unknown;
}
