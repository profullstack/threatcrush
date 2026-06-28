/**
 * ThreatCrush Service Worker (PRD 14)
 * Provides an installable offline shell, scoped runtime caching for dashboard
 * reads, push notification display, and cache invalidation hooks on logout/org
 * switch so cached data does not bleed between users or organizations.
 */

const STATIC_CACHE = 'tc-static-v2';
const DATA_CACHE_PREFIX = 'tc-data-v2';
const APP_SHELL = ['/', '/manifest.json'];
const CACHE_PREFIXES = ['tc-static-', 'tc-data-'];

let dataCacheName = `${DATA_CACHE_PREFIX}-anonymous`;

const DASHBOARD_READ_ROUTES = [
  /^\/api\/orgs\/[^/]+$/,
  /^\/api\/orgs\/[^/]+\/detections\/?$/,
  /^\/api\/orgs\/[^/]+\/remediations\/?$/,
  /^\/api\/orgs\/[^/]+\/servers\/?$/,
  /^\/api\/orgs\/[^/]+\/servers\/[^/]+\/?$/,
  /^\/api\/orgs\/[^/]+\/servers\/[^/]+\/detections\/?$/,
  /^\/api\/orgs\/[^/]+\/servers\/[^/]+\/findings\/?$/,
  /^\/api\/orgs\/[^/]+\/properties\/?$/,
  /^\/api\/orgs\/[^/]+\/properties\/[^/]+\/?$/,
];

function isDashboardRead(pathname) {
  return DASHBOARD_READ_ROUTES.some((pattern) => pattern.test(pathname));
}

function scopedCacheName(scope) {
  const safeScope = String(scope || 'anonymous').replace(/[^a-zA-Z0-9_-]/g, '-').slice(0, 80);
  return `${DATA_CACHE_PREFIX}-${safeScope || 'anonymous'}`;
}

async function deleteThreatCrushCaches() {
  const keys = await caches.keys();
  await Promise.all(
    keys
      .filter((key) => CACHE_PREFIXES.some((prefix) => key.startsWith(prefix)))
      .map((key) => caches.delete(key)),
  );
}

async function precacheShell() {
  const cache = await caches.open(STATIC_CACHE);
  await cache.addAll(APP_SHELL);
}

async function staleWhileRevalidate(request) {
  const cache = await caches.open(dataCacheName);
  const cached = await cache.match(request);

  const fetchPromise = fetch(request)
    .then((response) => {
      if (response.ok && response.type === 'basic') {
        void cache.put(request, response.clone());
      }
      return response;
    })
    .catch(() => cached);

  return cached || fetchPromise;
}

self.addEventListener('install', (event) => {
  event.waitUntil(precacheShell().then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys
          .filter((key) => CACHE_PREFIXES.some((prefix) => key.startsWith(prefix)) && key !== STATIC_CACHE && key !== dataCacheName)
          .map((key) => caches.delete(key)),
      ))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  if (event.request.method !== 'GET') return;
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/auth/')) return;

  // Runtime stale-while-revalidate for overview/detection/finding/remediation
  // reads only. Auth and non-dashboard APIs stay network-only to reduce the risk
  // of cross-user data leaks.
  if (url.pathname.startsWith('/api/')) {
    if (!isDashboardRead(url.pathname)) return;
    event.respondWith(staleWhileRevalidate(event.request));
    return;
  }

  if (url.pathname.startsWith('/_next/') || url.pathname.startsWith('/icons/')) {
    event.respondWith(
      caches.match(event.request).then((cached) => (
        cached || fetch(event.request).then((response) => {
          if (response.ok && response.type === 'basic') {
            const clone = response.clone();
            void caches.open(STATIC_CACHE).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
      )),
    );
    return;
  }

  if (event.request.mode === 'navigate') {
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response.ok && response.type === 'basic') {
            const clone = response.clone();
            void caches.open(STATIC_CACHE).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match(event.request).then((cached) => cached || caches.match('/'))),
    );
  }
});

self.addEventListener('push', (event) => {
  if (!event.data) return;

  let data;
  try {
    data = event.data.json();
  } catch {
    data = { title: 'ThreatCrush Alert', body: event.data.text() };
  }

  const options = {
    body: data.body || data.message || 'New security alert',
    icon: '/icons/icon-192x192.png',
    badge: '/icons/icon-192x192.png',
    tag: data.tag || 'threatcrush-alert',
    data: { url: data.url || '/dashboard' },
    actions: [
      { action: 'view', title: 'View' },
      { action: 'dismiss', title: 'Dismiss' },
    ],
  };

  event.waitUntil(
    self.registration.showNotification(data.title || 'ThreatCrush', options),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  if (event.action === 'dismiss') return;

  const url = event.notification.data?.url || '/dashboard';
  event.waitUntil(
    self.clients.matchAll({ type: 'window' }).then((clients) => {
      for (const client of clients) {
        if (client.url.includes(url) && 'focus' in client) {
          return client.focus();
        }
      }
      return self.clients.openWindow(url);
    }),
  );
});

self.addEventListener('message', (event) => {
  if (event.origin && event.origin !== self.location.origin) return;

  if (event.data?.type === 'SET_CACHE_SCOPE') {
    dataCacheName = scopedCacheName(event.data.scope);
    return;
  }

  if (event.data?.type === 'CLEAR_CACHES') {
    event.waitUntil(deleteThreatCrushCaches().then(precacheShell));
  }
});
