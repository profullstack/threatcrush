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
