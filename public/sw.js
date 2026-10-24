const CACHE_NAME = "xiefy-mail-v1";

self.addEventListener("install", (event) => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("push", (event) => {
  let data = {};
  try {
    data = event.data ? event.data.json() : {};
  } catch (e) {
    data = { title: "新着メール", body: event.data ? event.data.text() : "" };
  }

  const title = data.title || "新着メール";
  const options = {
    body: data.body || "",
    icon: "/icon.svg",
    badge: "/icon.svg",
    data: { messageId: data.messageId, to: data.to, url: data.url },
    tag: data.messageId || "mail-notif",
    requireInteraction: false,
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  // only paths on this site, so a payload can never send the app elsewhere
  const raw = event.notification.data && event.notification.data.url;
  const target = typeof raw === "string" && /^\/[a-z]*$/.test(raw) ? raw : "/";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
      for (const c of clients) {
        if (c.url.includes(self.location.origin)) {
          if (target !== "/") c.postMessage({ type: "open", path: target });
          return c.focus();
        }
      }
      return self.clients.openWindow(target);
    })
  );
});
