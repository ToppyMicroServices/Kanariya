import { KanariyaStore } from "./store.js";
export { KanariyaStore };

const TOKEN = /^[A-Za-z0-9_-]{1,512}$/;
const MANAGED_TOKEN = /^kr_[a-f0-9]{64}$/;
const headers = {
  "access-control-allow-origin": "*",
  "access-control-allow-headers": "authorization, content-type",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "cache-control": "no-store",
};
const quiet = () => new Response(null, { status: 204, headers });
const reply = (body, status = 200) => new Response(body, { status, headers });
const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { ...headers, "content-type": "application/json" },
});
const clip = (value, max = 512) => String(value || "").slice(0, max);
const number = (value, fallback) => value !== undefined && Number.isFinite(Number(value)) ? Number(value) : fallback;
const validToken = (token) => TOKEN.test(token);

function canonicalQuery(params) {
  return [...params].filter(([key]) => key !== "sig")
    .sort((a, b) => a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0]))
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`).join("&");
}
async function hmacHex(secret, value) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return [...new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value)))].map(b => b.toString(16).padStart(2, "0")).join("");
}
function randomId() {
  return [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, "0")).join("");
}
function duplicateParams(params) {
  const seen = new Set();
  for (const key of params.keys()) {
    if (seen.has(key)) return true;
    seen.add(key);
  }
  return false;
}
function store(env) {
  return env.KANARI_STORE.get(env.KANARI_STORE.idFromName("kanariya-v1"));
}
async function forward(request, env) {
  const response = await store(env).fetch(request);
  return new Response(response.body, { status: response.status, headers: { ...headers, "content-type": "application/json" } });
}
async function legacyEvents(env, token, limit) {
  if (!env.KANARI_KV) return { events: [], truncated: false };
  const keys = [];
  let cursor;
  let more = false;
  do {
    const result = await env.KANARI_KV.list({ prefix: `event:${token}:`, cursor, limit: Math.min(1000, limit - keys.length) });
    keys.push(...result.keys);
    more = result.list_complete === false || Boolean(result.cursor);
    cursor = result.cursor;
  } while (more && cursor && keys.length < limit);
  const events = [];
  for (let i = 0; i < keys.length; i += 100) {
    const values = await env.KANARI_KV.get(keys.slice(i, i + 100).map(entry => entry.name), "json");
    for (const event of values.values()) {
      // Old KV prefixes can overlap (e.g. a and a:b). Never export a sibling token.
      if (event?.token === token) events.push(event);
    }
  }
  return { events, truncated: more };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // Check the request URL before auth, storage or notification work.
    // Forwarded headers cannot grant the loopback-only development exception.
    const local = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
      return reply("HTTPS required", 400);
    }
    const { pathname, searchParams } = url;
    if (pathname.startsWith("/admin/")) {
      if (request.method === "OPTIONS") return quiet();
      // One boundary for every privileged operation. Old public flags are ignored.
      if (!env.ADMIN_KEY || request.headers.get("authorization") !== `Bearer ${env.ADMIN_KEY}`) return reply("Forbidden", 403);
      if (duplicateParams(searchParams)) return reply("Duplicate parameter", 400);
      try {
        if (pathname === "/admin/sign") {
          if (request.method !== "GET") return reply("Method not allowed", 405);
          const token = searchParams.get("token") || "";
          const src = searchParams.get("src") || "";
          const nonce = searchParams.get("nonce") || randomId();
          if (!validToken(token) || MANAGED_TOKEN.test(token) || src.length > 512 || nonce.length > 256) return reply("Invalid legacy token or parameter", 400);
          const master = env.MASTER_SECRET || env.SIGNING_SECRET;
          if (!master) return reply("Signing not configured", 503);
          const ts = Math.floor(Date.now() / 1000);
          const params = new URLSearchParams({ ts: String(ts) });
          if (src) params.set("src", src);
          params.set("nonce", nonce);
          const query = canonicalQuery(params);
          const path = `/canary/${token}`;
          const derived = await hmacHex(master, `token:${token}`);
          const sig = await hmacHex(derived, `${ts}|${path}|${query}`);
          return json({ url: `${url.origin}${path}?${query}&sig=${sig}`, token, ts, nonce });
        }
        if (pathname === "/admin/export") {
          if (request.method !== "GET") return reply("Method not allowed", 405);
          const token = searchParams.get("token") || "";
          if (!validToken(token)) return reply("Invalid token", 400);
          const limit = Math.max(1, Math.min(1000, Math.floor(number(env.EXPORT_MAX_ITEMS, 1000))));
          if (!env.KANARI_STORE && MANAGED_TOKEN.test(token)) return reply("Storage not configured", 503);
          const current = env.KANARI_STORE ? await store(env).fetch(request) : null;
          if (current && !current.ok) return new Response(current.body, { status: current.status, headers });
          const events = current ? await current.json() : [];
          const legacy = MANAGED_TOKEN.test(token) ? { events: [], truncated: false } : await legacyEvents(env, token, limit);
          events.push(...legacy.events);
          const response = json(events.sort((a, b) => (b.ts || "").localeCompare(a.ts || "")).slice(0, limit));
          response.headers.set("access-control-expose-headers", "x-kanariya-legacy-truncated");
          response.headers.set("x-kanariya-legacy-truncated", String(legacy.truncated));
          return response;
        }
        if (!env.KANARI_STORE) return reply("Storage not configured", 503);
        return await forward(request, env);
      } catch {
        console.error("kanariya_admin_error");
        return reply("Storage unavailable", 503);
      }
    }
    if (!pathname.startsWith("/canary/")) return reply("Not found", 404);
    if (request.method === "OPTIONS") return quiet();
    if (request.method !== "GET") return reply("Method not allowed", 405);
    const token = pathname.slice("/canary/".length);
    // Never reinterpret an extra path segment, encoded alias or malformed managed token.
    if (!validToken(token) || duplicateParams(searchParams)) return quiet();
    if (!env.KANARI_STORE) {
      console.error("kanariya_storage_not_configured");
      return quiet();
    }
    try {
      const registered = MANAGED_TOKEN.test(token);
      let nonce = "";
      let nonceExpiresAt = 0;
      if (!registered && ["1", "true", "yes"].includes(String(env.REQUIRE_SIGNATURE || "").toLowerCase())) {
        const legacy = env.SIGNING_SECRET || "";
        const master = env.MASTER_SECRET || legacy;
        const ts = Number(searchParams.get("ts"));
        const sig = (searchParams.get("sig") || "").toLowerCase();
        const window = number(env.SIGNATURE_WINDOW_SECONDS, 300);
        if (!master || !Number.isFinite(ts) || !/^[a-f0-9]{64}$/.test(sig)) return quiet();
        if (window > 0 && Math.abs(Math.floor(Date.now() / 1000) - ts) > window) return quiet();
        const value = `${ts}|${pathname}|${canonicalQuery(searchParams)}`;
        const expected = await hmacHex(await hmacHex(master, `token:${token}`), value);
        if (sig !== expected && (!legacy || sig !== await hmacHex(legacy, value))) return quiet();
        nonce = searchParams.get("nonce") || "";
        if (nonce.length > 256) return quiet();
        nonceExpiresAt = window > 0 ? Math.max(Date.now() + window * 1000, (ts + window + 1) * 1000) : Date.now() + 300000;
        // Preserve replay suppression for a nonce accepted just before this migration.
        if (nonce && env.KANARI_KV && await env.KANARI_KV.get(`nonce:${token}:${nonce}`)) return quiet();
      }
      const ip = request.headers.get("cf-connecting-ip") || (request.headers.get("x-forwarded-for") || "").split(",")[0].trim();
      const event = {
        id: randomId(), ts: new Date().toISOString(), token, test: false,
        src: clip(searchParams.get("src")),
        ipHash: ip && env.IP_HMAC_KEY ? await hmacHex(env.IP_HMAC_KEY, ip) : "",
        country: clip(request.cf?.country, 16), asn: request.cf?.asn || "",
        ua: clip(request.headers.get("user-agent"), 256), referer: clip(request.headers.get("referer")),
      };
      const response = await store(env).fetch(new Request("https://kanariya.internal/internal/hit", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ event, registered, nonce, nonceExpiresAt }),
      }));
      if (!response.ok) console.error("kanariya_record_failed");
    } catch {
      // Never log a token, a URL, provider credentials or request metadata on failure.
      console.error("kanariya_record_failed");
    }
    return quiet();
  },
};
