import PostalMime from "postal-mime";

const DOMAIN = "anonbox.email";         // primary domain shown to users
const LEGACY_DOMAINS = ["xiefy.site"];  // old domains that keep receiving / logging in
const ALL_DOMAINS = [DOMAIN, ...LEGACY_DOMAINS];
const SESSION_TTL_MS = 100 * 365 * 24 * 3600 * 1000;
const PBKDF2_ITERATIONS = 100000;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });

const err = (msg, status = 400) => json({ error: msg }, status);

const bytesToHex = (bytes) =>
  Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
const hexToBytes = (hex) => {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
};
const b64uToBytes = (s) => {
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const bytesToB64u = (bytes) => {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
};
const b64ToBytes = (s) => {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const bytesToB64 = (bytes) => {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
};
const concatBytes = (...arrs) => {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
};

async function derive(password, saltBytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    key,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

async function hashPassword(password) {
  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(password, saltBytes);
  return { hash, salt: bytesToHex(saltBytes) };
}

async function verifyPassword(password, hash, saltHex) {
  const computed = await derive(password, hexToBytes(saltHex));
  if (computed.length !== hash.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) diff |= computed.charCodeAt(i) ^ hash.charCodeAt(i);
  return diff === 0;
}

const isValidInbox = (s) => /^[a-z0-9._-]{3,32}$/.test(s);
const isValidPassword = (s) => typeof s === "string" && s.length >= 8 && s.length <= 128;

const ALIAS_LOCAL_LENGTH = 15;
const isValidAliasLocal = (s) => /^[0-9]{15}$/.test(s);

function randomAliasLocal() {
  const bytes = crypto.getRandomValues(new Uint8Array(ALIAS_LOCAL_LENGTH));
  let out = "";
  for (let i = 0; i < ALIAS_LOCAL_LENGTH; i++) out += (bytes[i] % 10).toString();
  return out;
}

async function generateUniqueAliasLocal(env) {
  for (let attempt = 0; attempt < 10; attempt++) {
    const local = randomAliasLocal();
    const taken = await env.DB.prepare(
      `SELECT 1 FROM aliases WHERE address = ?
       UNION ALL
       SELECT 1 FROM accounts WHERE inbox = ?`
    )
      .bind(local, local)
      .first();
    if (!taken) return local;
  }
  throw new Error("failed to generate a unique alias");
}

const parseAddress = (full) => {
  if (typeof full !== "string") return null;
  const m = full.trim().toLowerCase().match(/^([a-z0-9._-]{3,32})@([a-z0-9.-]+)$/);
  if (!m) return null;
  if (!ALL_DOMAINS.includes(m[2])) return null;
  return { inbox: m[1], domain: m[2], address: `${m[1]}@${DOMAIN}` };
};

async function getAuthAccount(req, env) {
  const auth = req.headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const token = m[1].trim();
  const now = Date.now();
  const session = await env.DB.prepare(
    `SELECT s.account_id, a.address, a.inbox, a.created_at
     FROM sessions s JOIN accounts a ON a.id = s.account_id
     WHERE s.token = ? AND s.expires_at > ?`
  )
    .bind(token, now)
    .first();
  return session ? { ...session, token } : null;
}

async function createSession(env, accountId) {
  const token = crypto.randomUUID() + "." + crypto.randomUUID();
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO sessions (token, account_id, created_at, expires_at) VALUES (?, ?, ?, ?)`
  )
    .bind(token, accountId, now, now + SESSION_TTL_MS)
    .run();
  return { token, expires_at: now + SESSION_TTL_MS };
}

// ===== E2EE encryption (for incoming mail) =====

async function encryptMailForAccount(publicKeyB64, parsed, fromObj, toAddress) {
  const publicKey = await crypto.subtle.importKey(
    "spki",
    b64ToBytes(publicKeyB64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );

  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"]
  );
  const aesKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", aesKey));

  const encryptedAesKey = new Uint8Array(
    await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, aesKeyRaw)
  );

  const metaIv = crypto.getRandomValues(new Uint8Array(12));
  const metaPlain = JSON.stringify({
    from_addr: fromObj.address || null,
    from_name: fromObj.name || null,
    subject: parsed.subject || null,
    to_addr: toAddress || null,
  });
  const metaEncrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: metaIv },
      aesKey,
      new TextEncoder().encode(metaPlain)
    )
  );

  const bodyIv = crypto.getRandomValues(new Uint8Array(12));
  const bodyPlain = JSON.stringify({
    text: parsed.text || null,
    html: parsed.html || null,
  });
  const bodyEncrypted = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: bodyIv },
      aesKey,
      new TextEncoder().encode(bodyPlain)
    )
  );

  return {
    encrypted_aes_key: bytesToB64(encryptedAesKey),
    meta_iv: bytesToB64(metaIv),
    meta_encrypted: bytesToB64(metaEncrypted),
    body_iv: bytesToB64(bodyIv),
    body_encrypted: bytesToB64(bodyEncrypted),
  };
}

// ===== Web Push =====

async function signVapidJwt(audience, subject, privateKeyB64Pkcs8) {
  const header = { typ: "JWT", alg: "ES256" };
  const payload = {
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: subject,
  };
  const enc = (obj) => bytesToB64u(new TextEncoder().encode(JSON.stringify(obj)));
  const signingInput = `${enc(header)}.${enc(payload)}`;

  const privKeyBytes = b64ToBytes(privateKeyB64Pkcs8);
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    privKeyBytes,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );

  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    cryptoKey,
    new TextEncoder().encode(signingInput)
  );

  return `${signingInput}.${bytesToB64u(new Uint8Array(sig))}`;
}

async function hkdf(salt, ikm, info, length) {
  const key = await crypto.subtle.importKey("raw", ikm, { name: "HKDF" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info },
    key,
    length * 8
  );
  return new Uint8Array(bits);
}

async function encryptWebPushPayload(payload, p256dhB64u, authB64u) {
  const recipientPublicRaw = b64uToBytes(p256dhB64u);
  const authSecret = b64uToBytes(authB64u);

  const asKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"]
  );
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", asKeyPair.publicKey));

  const uaPublic = await crypto.subtle.importKey(
    "raw",
    recipientPublicRaw,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );

  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: uaPublic },
    asKeyPair.privateKey,
    256
  );
  const sharedSecret = new Uint8Array(sharedBits);

  const salt = crypto.getRandomValues(new Uint8Array(16));

  const keyInfo = concatBytes(
    new TextEncoder().encode("WebPush: info\0"),
    recipientPublicRaw,
    asPublic
  );
  const ikm = await hkdf(authSecret, sharedSecret, keyInfo, 32);

  const cek = await hkdf(
    salt,
    ikm,
    new TextEncoder().encode("Content-Encoding: aes128gcm\0"),
    16
  );
  const nonce = await hkdf(salt, ikm, new TextEncoder().encode("Content-Encoding: nonce\0"), 12);

  const plaintext = concatBytes(new TextEncoder().encode(payload), new Uint8Array([0x02]));

  const cekKey = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"]);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, cekKey, plaintext)
  );

  const recordSizeBuf = new ArrayBuffer(4);
  new DataView(recordSizeBuf).setUint32(0, 4096, false);

  const header = concatBytes(
    salt,
    new Uint8Array(recordSizeBuf),
    new Uint8Array([asPublic.length]),
    asPublic
  );

  return concatBytes(header, ciphertext);
}

async function sendPush(env, subscription, payloadObj) {
  const url = new URL(subscription.endpoint);
  const audience = `${url.protocol}//${url.host}`;
  const jwt = await signVapidJwt(audience, env.VAPID_SUBJECT, env.VAPID_PRIVATE_KEY);
  const body = await encryptWebPushPayload(
    JSON.stringify(payloadObj),
    subscription.p256dh,
    subscription.auth
  );
  return fetch(subscription.endpoint, {
    method: "POST",
    headers: {
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      TTL: "86400",
      Urgency: "normal",
      Authorization: `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`,
    },
    body,
  });
}

async function pushToAccount(env, accountId, payload) {
  const { results } = await env.DB.prepare(
    `SELECT id, endpoint, p256dh, auth FROM push_subscriptions WHERE account_id = ?`
  )
    .bind(accountId)
    .all();
  if (!results || results.length === 0) {
    console.log("push: account has no subscriptions");
    return;
  }

  await Promise.all(
    results.map(async (sub) => {
      const host = new URL(sub.endpoint).host;
      try {
        const res = await sendPush(env, sub, payload);
        if (!res.ok) {
          const body = await res.text().catch(() => "");
          console.error("push send failed", host, res.status, body.slice(0, 500));
        } else {
          console.log("push send ok", host, res.status);
        }
        if (res.status === 404 || res.status === 410) {
          await env.DB.prepare(`DELETE FROM push_subscriptions WHERE id = ?`).bind(sub.id).run();
        }
      } catch (e) {
        console.error("push send threw", host, e?.message || String(e));
      }
    })
  );
}

// ===== Worker =====

export default {
  async email(message, env, ctx) {
    const parts = (message.to || "").toLowerCase().split("@");
    if (parts.length !== 2) return;
    const inbox = parts[0];

    let account = await env.DB.prepare(
      `SELECT id, public_key FROM accounts WHERE inbox = ?`
    )
      .bind(inbox)
      .first();

    if (!account) {
      account = await env.DB.prepare(
        `SELECT acc.id as id, acc.public_key as public_key
         FROM aliases al JOIN accounts acc ON acc.id = al.account_id
         WHERE al.address = ?`
      )
        .bind(inbox)
        .first();
    }

    if (!account) {
      message.setReject?.("address not in use");
      return;
    }

    const buf = await new Response(message.raw).arrayBuffer();
    const parsed = await PostalMime.parse(buf);
    const from = parsed.from || {};
    const toAddress = `${inbox}@${parts[1]}`;

    const encrypted = await encryptMailForAccount(account.public_key, parsed, from, toAddress);

    const msgId = crypto.randomUUID();
    await env.DB.prepare(
      `INSERT INTO messages (id, account_id, encrypted_aes_key, meta_iv, meta_encrypted, body_iv, body_encrypted, received_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        msgId,
        account.id,
        encrypted.encrypted_aes_key,
        encrypted.meta_iv,
        encrypted.meta_encrypted,
        encrypted.body_iv,
        encrypted.body_encrypted,
        Date.now()
      )
      .run();

    ctx.waitUntil(
      pushToAccount(env, account.id, {
        title: "新着メール",
        body: "受信トレイをご確認ください",
        messageId: msgId,
      })
    );
  },

  async scheduled(event, env, ctx) {
    const hours = parseInt(env.RETENTION_HOURS || "168", 10);
    const cutoff = Date.now() - hours * 3600 * 1000;
    await env.DB.batch([
      env.DB.prepare(`DELETE FROM messages WHERE received_at < ?`).bind(cutoff),
      env.DB.prepare(`DELETE FROM sessions WHERE expires_at < ?`).bind(Date.now()),
    ]);
  },

  async fetch(req, env, ctx) {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

    const url = new URL(req.url);
    const path = url.pathname;

    try {
      if (path === "/api/health") return json({ ok: true });

      if (path === "/api/domains" && req.method === "GET") {
        return json({ domains: ALL_DOMAINS });
      }

      if (path === "/api/push/key" && req.method === "GET") {
        return json({ key: env.VAPID_PUBLIC_KEY });
      }

      if (path === "/api/accounts" && req.method === "POST") {
        const body = await req.json().catch(() => ({}));
        const parsed = parseAddress(body.address);
        if (!parsed) return err("invalid address (use name@" + DOMAIN + ", name=3-32 chars)");
        if (!isValidInbox(parsed.inbox)) return err("invalid inbox name");
        if (!isValidPassword(body.password)) return err("password must be 8-128 chars");
        if (
          typeof body.public_key !== "string" ||
          typeof body.encrypted_private_key !== "string" ||
          typeof body.pk_iv !== "string" ||
          typeof body.kdf_salt !== "string"
        ) {
          return err("missing crypto material");
        }

        const existing = await env.DB.prepare(`SELECT 1 FROM accounts WHERE inbox = ?`)
          .bind(parsed.inbox)
          .first();
        if (existing) return err("address already taken", 409);

        const { hash, salt } = await hashPassword(body.password);
        const id = crypto.randomUUID();
        const now = Date.now();
        await env.DB.prepare(
          `INSERT INTO accounts (id, address, inbox, password_hash, password_salt, public_key, encrypted_private_key, pk_iv, kdf_salt, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            id,
            parsed.address,
            parsed.inbox,
            hash,
            salt,
            body.public_key,
            body.encrypted_private_key,
            body.pk_iv,
            body.kdf_salt,
            now
          )
          .run();
        return json({ id, address: parsed.address, created_at: now }, 201);
      }

      if (path === "/api/token" && req.method === "POST") {
        const body = await req.json().catch(() => ({}));
        const parsed = parseAddress(body.address);
        if (!parsed || !isValidPassword(body.password)) return err("invalid credentials", 401);

        const account = await env.DB.prepare(
          `SELECT id, password_hash, password_salt, encrypted_private_key, pk_iv, kdf_salt FROM accounts WHERE inbox = ?`
        )
          .bind(parsed.inbox)
          .first();
        if (!account) return err("invalid credentials", 401);
        const ok = await verifyPassword(body.password, account.password_hash, account.password_salt);
        if (!ok) return err("invalid credentials", 401);

        const session = await createSession(env, account.id);
        return json({
          id: account.id,
          token: session.token,
          expires_at: session.expires_at,
          encrypted_private_key: account.encrypted_private_key,
          pk_iv: account.pk_iv,
          kdf_salt: account.kdf_salt,
        });
      }

      const me = await getAuthAccount(req, env);

      if (path === "/api/me") {
        if (!me) return err("unauthorized", 401);
        if (req.method === "GET") {
          const acc = await env.DB.prepare(
            `SELECT encrypted_private_key, pk_iv, kdf_salt FROM accounts WHERE id = ?`
          )
            .bind(me.account_id)
            .first();
          return json({
            id: me.account_id,
            address: me.address,
            created_at: me.created_at,
            encrypted_private_key: acc?.encrypted_private_key,
            pk_iv: acc?.pk_iv,
            kdf_salt: acc?.kdf_salt,
          });
        }
        if (req.method === "DELETE") {
          await env.DB.batch([
            env.DB.prepare(`DELETE FROM push_subscriptions WHERE account_id = ?`).bind(me.account_id),
            env.DB.prepare(`DELETE FROM aliases WHERE account_id = ?`).bind(me.account_id),
            env.DB.prepare(`DELETE FROM messages WHERE account_id = ?`).bind(me.account_id),
            env.DB.prepare(`DELETE FROM sessions WHERE account_id = ?`).bind(me.account_id),
            env.DB.prepare(`DELETE FROM accounts WHERE id = ?`).bind(me.account_id),
          ]);
          return json({ ok: true });
        }
      }

      if (path === "/api/logout" && req.method === "POST") {
        if (!me) return err("unauthorized", 401);
        await env.DB.prepare(`DELETE FROM sessions WHERE token = ?`).bind(me.token).run();
        return json({ ok: true });
      }

      if (path === "/api/password" && req.method === "POST") {
        if (!me) return err("unauthorized", 401);
        const body = await req.json().catch(() => ({}));
        if (!isValidPassword(body.current_password)) return err("invalid credentials", 401);
        if (!isValidPassword(body.new_password)) return err("password must be 8-128 chars");
        if (
          typeof body.encrypted_private_key !== "string" ||
          typeof body.pk_iv !== "string" ||
          typeof body.kdf_salt !== "string"
        ) {
          return err("missing crypto material");
        }

        const acc = await env.DB.prepare(
          `SELECT password_hash, password_salt FROM accounts WHERE id = ?`
        )
          .bind(me.account_id)
          .first();
        if (!acc) return err("unauthorized", 401);
        const ok = await verifyPassword(body.current_password, acc.password_hash, acc.password_salt);
        if (!ok) return err("current password is incorrect", 401);

        const { hash, salt } = await hashPassword(body.new_password);
        await env.DB.batch([
          env.DB.prepare(
            `UPDATE accounts SET password_hash = ?, password_salt = ?, encrypted_private_key = ?, pk_iv = ?, kdf_salt = ?
             WHERE id = ?`
          ).bind(hash, salt, body.encrypted_private_key, body.pk_iv, body.kdf_salt, me.account_id),
          env.DB.prepare(`DELETE FROM sessions WHERE account_id = ? AND token != ?`).bind(
            me.account_id,
            me.token
          ),
        ]);
        return json({ ok: true });
      }

      if (path === "/api/aliases" && req.method === "GET") {
        if (!me) return err("unauthorized", 401);
        const { results } = await env.DB.prepare(
          `SELECT address, created_at FROM aliases WHERE account_id = ? ORDER BY created_at DESC`
        )
          .bind(me.account_id)
          .all();
        return json({
          aliases: results.map((r) => ({
            address: `${r.address}@${DOMAIN}`,
            created_at: r.created_at,
          })),
        });
      }

      if (path === "/api/aliases" && req.method === "POST") {
        if (!me) return err("unauthorized", 401);
        const local = await generateUniqueAliasLocal(env);
        const now = Date.now();
        await env.DB.prepare(
          `INSERT INTO aliases (address, account_id, created_at) VALUES (?, ?, ?)`
        )
          .bind(local, me.account_id, now)
          .run();
        return json({ address: `${local}@${DOMAIN}`, created_at: now }, 201);
      }

      const aliasMatch = path.match(/^\/api\/aliases\/([^/]+)$/);
      if (aliasMatch && req.method === "DELETE") {
        if (!me) return err("unauthorized", 401);
        const aliasAddr = decodeURIComponent(aliasMatch[1]).toLowerCase();
        const parsedAlias = parseAddress(aliasAddr);
        if (!parsedAlias || !isValidAliasLocal(parsedAlias.inbox)) return err("invalid alias address");
        await env.DB.prepare(`DELETE FROM aliases WHERE address = ? AND account_id = ?`)
          .bind(parsedAlias.inbox, me.account_id)
          .run();
        return json({ ok: true });
      }

      if (path === "/api/messages" && req.method === "GET") {
        if (!me) return err("unauthorized", 401);
        const rawLimit = parseInt(url.searchParams.get("limit") || "100", 10);
        const limit = Math.min(Math.max(Number.isFinite(rawLimit) ? rawLimit : 100, 1), 500);
        const before = parseInt(url.searchParams.get("before") || "", 10);
        const paged = Number.isFinite(before);
        const stmt = paged
          ? env.DB.prepare(
              `SELECT id, encrypted_aes_key, meta_iv, meta_encrypted, received_at, seen
               FROM messages WHERE account_id = ? AND received_at < ?
               ORDER BY received_at DESC LIMIT ?`
            ).bind(me.account_id, before, limit)
          : env.DB.prepare(
              `SELECT id, encrypted_aes_key, meta_iv, meta_encrypted, received_at, seen
               FROM messages WHERE account_id = ?
               ORDER BY received_at DESC LIMIT ?`
            ).bind(me.account_id, limit);
        const { results } = await stmt.all();
        return json({ messages: results, has_more: results.length === limit });
      }

      if (path === "/api/messages/delete" && req.method === "POST") {
        if (!me) return err("unauthorized", 401);
        const body = await req.json().catch(() => ({}));
        const ids = Array.isArray(body.ids) ? body.ids : [];
        const valid = ids
          .filter((v) => typeof v === "string" && /^[a-f0-9-]{1,64}$/i.test(v))
          .slice(0, 200);
        if (valid.length === 0) return err("no valid message ids");
        const placeholders = valid.map(() => "?").join(",");
        const res = await env.DB.prepare(
          `DELETE FROM messages WHERE account_id = ? AND id IN (${placeholders})`
        )
          .bind(me.account_id, ...valid)
          .run();
        return json({ ok: true, deleted: res?.meta?.changes ?? valid.length });
      }

      const msgMatch = path.match(/^\/api\/messages\/([a-f0-9-]+)$/i);
      if (msgMatch) {
        if (!me) return err("unauthorized", 401);
        const id = msgMatch[1];

        if (req.method === "GET") {
          const row = await env.DB.prepare(
            `SELECT id, encrypted_aes_key, meta_iv, meta_encrypted, body_iv, body_encrypted, received_at, seen
             FROM messages WHERE id = ? AND account_id = ?`
          )
            .bind(id, me.account_id)
            .first();
          if (!row) return err("not found", 404);
          if (!row.seen) {
            await env.DB.prepare(`UPDATE messages SET seen = 1 WHERE id = ?`).bind(id).run();
          }
          return json(row);
        }

        if (req.method === "DELETE") {
          await env.DB.prepare(`DELETE FROM messages WHERE id = ? AND account_id = ?`)
            .bind(id, me.account_id)
            .run();
          return json({ ok: true });
        }
      }

      if (path === "/api/push/subscribe" && req.method === "POST") {
        if (!me) return err("unauthorized", 401);
        const body = await req.json().catch(() => ({}));
        const endpoint = body.endpoint;
        const p256dh = body.keys?.p256dh;
        const auth = body.keys?.auth;
        if (!endpoint || !p256dh || !auth) return err("missing subscription fields");

        await env.DB.prepare(
          `INSERT INTO push_subscriptions (id, account_id, endpoint, p256dh, auth, created_at)
           VALUES (?, ?, ?, ?, ?, ?)
           ON CONFLICT(endpoint) DO UPDATE SET account_id = excluded.account_id, p256dh = excluded.p256dh, auth = excluded.auth`
        )
          .bind(crypto.randomUUID(), me.account_id, endpoint, p256dh, auth, Date.now())
          .run();
        return json({ ok: true });
      }

      if (path === "/api/push/unsubscribe" && req.method === "POST") {
        if (!me) return err("unauthorized", 401);
        const body = await req.json().catch(() => ({}));
        if (!body.endpoint) return err("missing endpoint");
        await env.DB.prepare(
          `DELETE FROM push_subscriptions WHERE account_id = ? AND endpoint = ?`
        )
          .bind(me.account_id, body.endpoint)
          .run();
        return json({ ok: true });
      }

      return err("not found", 404);
    } catch (e) {
      return err("server error: " + (e.message || String(e)), 500);
    }
  },
};
