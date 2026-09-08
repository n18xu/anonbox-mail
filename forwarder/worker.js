// Forwarder for the retired domain (xiefy.site).
//
// The domain lives on a different Cloudflare account than the mail service, and
// Email Routing can only hand a message to a Worker in its own account. So this
// tiny Worker takes delivery and posts the raw message to the live service's
// ingest endpoint, which stores it in the recipient's real mailbox.
//
// It holds no database and no keys beyond the shared ingest secret.

export default {
  async email(message, env, ctx) {
    if (!env.FORWARD_URL || !env.INGEST_KEY) {
      // fail loudly rather than silently dropping someone's mail
      throw new Error("forwarder is not configured");
    }

    const raw = await new Response(message.raw).arrayBuffer();
    const res = await fetch(env.FORWARD_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Ingest-Key": env.INGEST_KEY,
        "X-Ingest-To": message.to || "",
      },
      body: raw,
    });

    if (res.ok) return;

    if (res.status === 404) {
      message.setReject?.("address not in use");
      return;
    }

    // anything else is temporary as far as the sender is concerned: throwing
    // makes Cloudflare treat delivery as failed so the sender retries
    const detail = await res.text().catch(() => "");
    console.error("forward failed", res.status, detail.slice(0, 200));
    throw new Error("forward failed with status " + res.status);
  },

  // the old API is gone; tell anything still pointing here where to go
  async fetch() {
    return new Response(
      JSON.stringify({
        error: "moved",
        message: "This service now runs at https://anonbox.email",
        site: "https://anonbox.email",
      }),
      { status: 410, headers: { "Content-Type": "application/json" } }
    );
  },

  // the old schedule may still fire; do nothing rather than error
  async scheduled() {},
};
