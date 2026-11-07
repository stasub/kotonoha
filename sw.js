/* ことのは帖 PWA オフライン起動用 Service Worker
   静的ファイルだけをキャッシュします。原稿・メモ・バックアップはキャッシュしません。
   アプリ更新時は CACHE_VERSION を変更してください。 */
const CACHE_VERSION = 'kotonoha-static-firebase-beta-2026-11-04-2';
const CACHE_PREFIX = 'kotonoha-static-';
const ROOT = new URL('./', self.registration.scope);
const ASSETS = [
  './',
  './index.html',
  './cloud-sync.js',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/apple-touch-icon.png',
  './icons/favicon-32.png'
].map(path => new URL(path, ROOT).href);

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_VERSION)
      .then(cache => cache.addAll(ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(key => key.startsWith(CACHE_PREFIX) && key !== CACHE_VERSION)
        .map(key => caches.delete(key))
    )).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const requestURL = new URL(request.url);
  if (requestURL.origin !== self.location.origin) return;
  if (!requestURL.pathname.startsWith(ROOT.pathname)) return;

  if (request.mode === 'navigate') {
    // オンラインなら最新版のHTMLを取得。ネット接続がないときは既存の画面へ。
    event.respondWith(
      fetch(request).then(response => {
        if (response.ok) {
          const copy = response.clone();
          event.waitUntil(caches.open(CACHE_VERSION).then(cache => cache.put(new URL('./index.html', ROOT), copy)));
        }
        return response;
      }).catch(async () => {
        return await caches.match(new URL('./index.html', ROOT))
            || await caches.match(new URL('./', ROOT))
            || Response.error();
      })
    );
    return;
  }

  // マニフェストとアイコンだけキャッシュ。将来のAPI応答はキャッシュしない。
  if (!ASSETS.includes(requestURL.href)) return;
  event.respondWith(caches.match(request).then(hit => hit || fetch(request)));
});
