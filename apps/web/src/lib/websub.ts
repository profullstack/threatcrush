// WebSub publisher mode.
//
// We're the publisher of /blog/rss.xml. The feed declares an external
// hub (Google's pubsubhubbub by default; override via WEBSUB_HUB), and
// after every new article we POST a publish notification so subscribed
// aggregators get the new post within seconds instead of waiting for
// their next poll.
//
// Hub role is intentionally *not* implemented here — running a hub
// means subscription storage, verification GET callbacks, fan-out
// queue, and retries. Most blogs don't need to own that.
//
// Spec: https://www.w3.org/TR/websub/

const DEFAULT_HUB = "https://pubsubhubbub.appspot.com/";

export function webSubHubUrl(): string {
  return process.env.WEBSUB_HUB?.trim() || DEFAULT_HUB;
}

const PING_TIMEOUT_MS = 5000;

// Fire-and-forget. The hub re-fetches the feed itself; a failed ping
// just means delayed delivery, not lost notifications.
export async function pingWebSubHub(feedUrl: string): Promise<void> {
  const hubUrl = webSubHubUrl();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PING_TIMEOUT_MS);
  try {
    const res = await fetch(hubUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        "hub.mode": "publish",
        "hub.url": feedUrl,
      }).toString(),
      signal: controller.signal,
    });
    if (!res.ok) {
      console.warn(
        `[websub] hub ${hubUrl} responded ${res.status} for ${feedUrl}`,
      );
    }
  } catch (err) {
    console.warn("[websub] hub ping failed:", err);
  } finally {
    clearTimeout(timer);
  }
}
