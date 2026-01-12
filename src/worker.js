const DEFAULT_EVENT_TTL_SECONDS = 60 * 60 * 24 * 30;
const DEFAULT_DEDUPE_TTL_SECONDS = 60 * 30;
const DEFAULT_EXPORT_MAX_ITEMS = 1000;

function getTtl(envValue, fallback) {
  const parsed = Number(envValue);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function textOrEmpty(value, max = 512) {
  if (!value) return "";
  return value.length > max ? value.slice(0, max) : value;
}

async function hmacHex(secret, value) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return [...new Uint8Array(signature)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(value) {
  const encoder = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomId() {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function listEventsForToken(env, token, maxItems) {
  const prefix = `event:${token}:`;
  let cursor;
  const keys = [];
  do {
    const response = await env.KANARI_KV.list({ prefix, cursor, limit: 100 });
    keys.push(...response.keys);
    cursor = response.cursor;
  } while (cursor && keys.length < maxItems);

  const events = [];
  for (const entry of keys.slice(0, maxItems)) {
    const event = await env.KANARI_KV.get(entry.name, "json");
    if (event) events.push(event);
  }

  events.sort((a, b) => (a.ts || "").localeCompare(b.ts || ""));
  return events;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const { pathname, searchParams } = url;

    if (pathname.startsWith("/canary/")) {
      const token = pathname.slice("/canary/".length).split("/")[0];
      if (!token) {
        return new Response("Not found", { status: 404 });
      }

      const src = textOrEmpty(searchParams.get("src") || "");
      const ip =
        request.headers.get("cf-connecting-ip") ||
        (request.headers.get("x-forwarded-for") || "").split(",")[0].trim();
      const ua = textOrEmpty(request.headers.get("user-agent") || "", 256);
      const referer = textOrEmpty(request.headers.get("referer") || "", 512);
      const cf = request.cf || {};

      const eventTtl = getTtl(env.EVENT_TTL_SECONDS, DEFAULT_EVENT_TTL_SECONDS);
      const dedupeTtl = getTtl(env.DEDUPE_TTL_SECONDS, DEFAULT_DEDUPE_TTL_SECONDS);

      try {
        const ipHash = ip && env.IP_HMAC_KEY ? await hmacHex(env.IP_HMAC_KEY, ip) : "";
        const uaHash = ua ? await sha256Hex(ua) : "";
        const canDedupe = Boolean(ipHash && uaHash);
        const dedupeKey = `dedupe:${token}:${ipHash}:${uaHash}`;
        const dedupeHit = canDedupe ? await env.KANARI_KV.get(dedupeKey) : false;

        // Store minimal metadata only; avoid request body or full query logging.
        const event = {
          ts: new Date().toISOString(),
          token,
          src,
          ipHash,
          country: cf.country || "",
          asn: cf.asn || "",
          ua,
          referer,
        };

        const eventKey = `event:${token}:${event.ts}:${randomId()}`;
        await env.KANARI_KV.put(eventKey, JSON.stringify(event), {
          expirationTtl: eventTtl,
        });

        if (!dedupeHit) {
          if (canDedupe) {
            await env.KANARI_KV.put(dedupeKey, "1", { expirationTtl: dedupeTtl });
          }

          if (env.WEBHOOK_URL) {
            const payload = {
              kind: "kanariya.canary",
              event,
            };
            ctx.waitUntil(
              fetch(env.WEBHOOK_URL, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify(payload),
              })
            );
          }
        }
      } catch (err) {
        console.error("kanariya_error", err);
      }

      return new Response(null, { status: 204 });
    }

    if (pathname === "/admin/export") {
      const token = textOrEmpty(searchParams.get("token") || "");
      const authHeader = request.headers.get("authorization") || "";
      const adminKey = env.ADMIN_KEY || "";
      const bearerKey = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";

      if (!adminKey || bearerKey !== adminKey) {
        return new Response("Forbidden", { status: 403 });
      }
      if (!token) {
        return new Response("Missing token", { status: 400 });
      }

      try {
        const maxItems = getTtl(env.EXPORT_MAX_ITEMS, DEFAULT_EXPORT_MAX_ITEMS);
        const events = await listEventsForToken(env, token, maxItems);
        return new Response(JSON.stringify(events), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      } catch (err) {
        console.error("kanariya_admin_error", err);
        return new Response("Error", { status: 500 });
      }
    }

    return new Response("Not found", { status: 404 });
  },
};
