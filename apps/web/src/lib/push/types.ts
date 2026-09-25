/** What a push notification shows and where tapping it goes. */
export interface PushNotification {
  title: string;
  body: string;
  /** Absolute dashboard URL opened on click/tap. */
  url: string;
  /** Replaces an earlier notification with the same tag instead of stacking. */
  tag: string;
  /** Extra fields for native apps (Expo `data`). */
  data?: Record<string, string>;
}

export interface PushSendResult {
  sent: number;
  /** Human-readable reasons, one per failed message (or one for a whole failed batch). */
  failures: string[];
  /** Tokens/endpoints the push service says no longer exist; delete them. */
  dead: string[];
}
