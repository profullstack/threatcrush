const SERVICE_WORKER_PATH = "/sw.js";
const CACHE_PREFIXES = ["tc-static-", "tc-data-"];

export type ServiceWorkerBridge = Pick<
  ServiceWorkerContainer,
  "controller" | "getRegistrations" | "register"
>;

export interface PwaCacheMessage {
  type: "CLEAR_CACHES" | "SET_CACHE_SCOPE";
  reason?: "logout" | "org-switch" | "startup";
  scope?: string;
}

export function isSecureServiceWorkerContext(location: Pick<Location, "protocol" | "hostname">) {
  return (
    location.protocol === "https:" ||
    location.hostname === "localhost" ||
    location.hostname === "127.0.0.1" ||
    location.hostname === "::1"
  );
}

export function buildPwaCacheMessage(
  type: PwaCacheMessage["type"],
  options: Omit<PwaCacheMessage, "type"> = {},
): PwaCacheMessage {
  return { type, ...options };
}

function getServiceWorkerBridge(): ServiceWorkerBridge | null {
  if (typeof window === "undefined") return null;
  if (!("serviceWorker" in navigator)) return null;
  if (!isSecureServiceWorkerContext(window.location)) return null;
  return navigator.serviceWorker;
}

function getCacheStorage(): CacheStorage | null {
  if (typeof window === "undefined") return null;
  return "caches" in window ? window.caches : null;
}

function postToRegistration(
  registration: Pick<ServiceWorkerRegistration, "active" | "installing" | "waiting">,
  message: PwaCacheMessage,
) {
  registration.active?.postMessage(message);
  registration.waiting?.postMessage(message);
  registration.installing?.postMessage(message);
}

export async function registerThreatCrushServiceWorker(
  bridge: ServiceWorkerBridge | null = getServiceWorkerBridge(),
) {
  if (!bridge) return null;
  return bridge.register(SERVICE_WORKER_PATH);
}

export async function postThreatCrushServiceWorkerMessage(
  message: PwaCacheMessage,
  bridge: ServiceWorkerBridge | null = getServiceWorkerBridge(),
) {
  if (!bridge) return;

  bridge.controller?.postMessage(message);

  const registrations = await bridge.getRegistrations();
  for (const registration of registrations) {
    postToRegistration(registration, message);
  }
}

export async function setThreatCrushServiceWorkerCacheScope(scope: string | null) {
  const normalizedScope = scope || "anonymous";
  await postThreatCrushServiceWorkerMessage(
    buildPwaCacheMessage("SET_CACHE_SCOPE", { scope: normalizedScope }),
  );
}

export async function clearThreatCrushServiceWorkerCaches(
  reason: PwaCacheMessage["reason"],
  cacheStorage: CacheStorage | null = getCacheStorage(),
) {
  await postThreatCrushServiceWorkerMessage(buildPwaCacheMessage("CLEAR_CACHES", { reason }));

  // Do a best-effort direct clear from the client as well. This covers the first
  // install/update window before a service worker controls the current page.
  if (!cacheStorage) return;
  const keys = await cacheStorage.keys();
  await Promise.all(
    keys
      .filter((key) => CACHE_PREFIXES.some((prefix) => key.startsWith(prefix)))
      .map((key) => cacheStorage.delete(key)),
  );
}

/** Browser Web Push needs a secure context, a service worker, PushManager and Notification. */
export function isBrowserPushSupported() {
  return (
    getServiceWorkerBridge() !== null && "PushManager" in window && "Notification" in window
  );
}

/** VAPID public keys are distributed as unpadded base64url; PushManager wants the raw bytes. */
export function vapidKeyToBytes(base64Url: string): Uint8Array<ArrayBuffer> {
  const base64 = (base64Url + "=".repeat((4 - (base64Url.length % 4)) % 4))
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const binary = atob(base64);
  const bytes = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function pushRegistration(): Promise<ServiceWorkerRegistration | null> {
  if (!isBrowserPushSupported()) return null;
  await registerThreatCrushServiceWorker();
  return navigator.serviceWorker.ready;
}

export async function getBrowserPushSubscription(): Promise<PushSubscription | null> {
  const registration = await pushRegistration();
  return registration ? registration.pushManager.getSubscription() : null;
}

/**
 * Subscribe this browser (prompting for notification permission if needed).
 * Reuses an existing subscription made with the same key.
 */
export async function subscribeBrowserPush(applicationServerKey: string): Promise<PushSubscription> {
  const registration = await pushRegistration();
  if (!registration) throw new Error("This browser does not support push notifications");
  return registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: vapidKeyToBytes(applicationServerKey),
  });
}

/**
 * Drop this browser's push subscription. Returns the endpoint that was removed
 * so the caller can tell the server, or null if there was none. Works without
 * a session: the push service then answers 410 and the server deletes its row
 * on the next alert.
 */
export async function unsubscribeBrowserPush(): Promise<string | null> {
  const subscription = await getBrowserPushSubscription();
  if (!subscription) return null;
  await subscription.unsubscribe();
  return subscription.endpoint;
}
