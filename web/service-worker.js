import { CACHE_NAME, urlsToCache } from "./cacheConfig";

// Función para almacenar en caché
const cacheResources = async () => {
  try {
    const cache = await caches.open(CACHE_NAME);
    console.log("Archivos cacheados");
    await cache.addAll(urlsToCache);
  } catch (error) {
    console.error("Error al cachear archivos:", error);
  }
};

// Función para limpiar cachés antiguas
const cleanOldCaches = async () => {
  try {
    const cacheNames = await caches.keys();
    const promises = cacheNames.map((cacheName) => {
      return cacheName !== CACHE_NAME ? caches.delete(cacheName) : null;
    });
    await Promise.all(promises);
    console.log("Cachés antiguas limpiadas");
  } catch (error) {
    console.error("Error al limpiar cachés antiguas:", error);
  }
};

// Función para limpiar la caché periódicamente
const startPeriodicCacheCleanup = () => {
  setInterval(() => {
    cleanOldCaches();
  }, 60000); // Limpia cada 60,000 ms (1 minuto)
};

// Instalación del Service Worker
self.addEventListener("install", (event) => {
  event.waitUntil(cacheResources());
});

// Activación del Service Worker
self.addEventListener("activate", (event) => {
  event.waitUntil(cleanOldCaches());
  startPeriodicCacheCleanup(); // Inicia la limpieza periódica
});

// Interceptar las solicitudes de red y servir los archivos desde la caché
self.addEventListener("fetch", (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      if (response) {
        // Devuelve la respuesta desde la caché
        return response;
      }
      // Si no está en caché, realizar la petición a la red
      return fetch(event.request).catch((error) => {
        console.error("Error en la solicitud de red:", error);
      });
    })
  );
});
