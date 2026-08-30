import { defineTheme, hex, themes, type Theme } from '@profullstack/hqtui';
import type { EventSeverity } from '../types/events.js';

/**
 * The palette from the product shot on threatcrush.com: terminal green on near
 * black, with severity carried by hue rather than by a label alone.
 */
export const threatcrushTheme: Theme = defineTheme(
  {
    name: 'threatcrush',
    background: hex('#0b0f0d'),
    surface: hex('#111714'),
    foreground: hex('#d7e3dc'),
    muted: hex('#6b7f75'),
    primary: hex('#22e56a'),
    secondary: hex('#3ddc84'),
    accent: hex('#5bd6ff'),
    success: hex('#22e56a'),
    warning: hex('#ffcb6b'),
    danger: hex('#ff5370'),
    info: hex('#5bd6ff'),
    border: hex('#1f2b25'),
    borderFocused: hex('#22e56a'),
    title: hex('#22e56a'),
    selection: hex('#16241d'),
    selectionText: hex('#d7e3dc'),
    graph: [hex('#22e56a'), hex('#5bd6ff'), hex('#ffcb6b'), hex('#ff5370'), hex('#c792ea')],
  },
  themes.dark,
);

export const severityColors: Record<EventSeverity, number> = {
  info: hex('#22e56a'),
  low: hex('#5bd6ff'),
  medium: hex('#ffcb6b'),
  high: hex('#ff5370'),
  critical: hex('#c792ea'),
};

/** Levels as the log widget keys them — uppercase, matching `LogEntry.level`. */
export const levelColors: Record<string, number> = {
  INFO: severityColors.info,
  LOW: severityColors.low,
  MEDIUM: severityColors.medium,
  HIGH: severityColors.high,
  CRITICAL: severityColors.critical,
};
