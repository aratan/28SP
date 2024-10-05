const CACHE_NAME = 'pwa-cache-v1';
const urlsToCache = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icon-192x192.png'
];

// Instalación del Service Worker y cacheo de los recursos
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('Archivos cacheados');
        return cache.addAll(urlsToCache);
      })
  );
});

// Activar el Service Worker y limpiar cachés antiguas
self.addEventListener('activate', (event) => {
  const cacheWhitelist = [CACHE_NAME];
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheWhitelist.indexOf(cacheName) === -1) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// Interceptar las solicitudes de red y servir los archivos desde la caché
self.addEventListener('fetch', (event) => {
  console.log('Fetch request:', event.request);
  event.respondWith(
    caches.match(event.request)
      .then((response) => {
        if (response) {
          console.log('Devolviendo respuesta de la caché:', response);
          return response;
        }
        console.log('Haciendo fetch a la red:', event.request);
        return fetch(event.request);
      })
  );
});
