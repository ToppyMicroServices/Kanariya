const DEFAULT_EVENT_TTL_SECONDS = 60 * 60 * 24 * 30;
const DEFAULT_DEDUPE_TTL_SECONDS = 60 * 30;
const DEFAULT_EXPORT_MAX_ITEMS = 1000;
const DEFAULT_RATE_LIMIT_WINDOW_SECONDS = 60;
const DEFAULT_RATE_LIMIT_MAX = 60;
const DEFAULT_SIGNATURE_WINDOW_SECONDS = 300;

function getTtl(envValue, fallback) {
  const parsed = Number(envValue);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function getNumber(envValue, fallback) {
  const parsed = Number(envValue);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function textOrEmpty(value, max = 512) {
  if (!value) return "";
  return value.length > max ? value.slice(0, max) : value;
}

function canonicalQuery(params) {
  const entries = [];
  for (const [key, value] of params.entries()) {
    if (key === "sig") continue;
    entries.push([key, value]);
  }
  entries.sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));
  return entries
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");
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

async function derivedSigningKey(masterSecret, token) {
  if (!masterSecret || !token) return "";
  return await hmacHex(masterSecret, `token:${token}`);
}

async function sha256Hex(value) {
  const encoder = new TextEncoder();
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function parseEmailList(value) {
  if (!value) return [];
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function randomId() {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function corsHeaders() {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-headers": "authorization, content-type",
    "access-control-allow-methods": "GET, OPTIONS",
  };
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
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders() });
      }

      const token = pathname.slice("/canary/".length).split("/")[0];
      if (!token) {
        return new Response("Not found", { status: 404, headers: corsHeaders() });
      }

      const src = textOrEmpty(searchParams.get("src") || "");
      const ip =
        request.headers.get("cf-connecting-ip") ||
        (request.headers.get("x-forwarded-for") || "").split(",")[0].trim();
      const ua = textOrEmpty(request.headers.get("user-agent") || "", 256);
      const referer = textOrEmpty(request.headers.get("referer") || "", 512);
      const cf = request.cf || {};

      const requireSignature = ["1", "true", "yes"].includes(
        String(env.REQUIRE_SIGNATURE || "").toLowerCase()
      );
      const legacySigningSecret = env.SIGNING_SECRET || "";
      // Backward/ops-friendly behavior:
      // - If MASTER_SECRET is not set but SIGNING_SECRET exists, treat SIGNING_SECRET as the master secret
      //   for per-token derived signing.
      // - Still accept legacy signatures that were created directly with SIGNING_SECRET.
      const masterSecret = env.MASTER_SECRET || legacySigningSecret || "";
      const signatureWindow = getNumber(
        env.SIGNATURE_WINDOW_SECONDS,
        DEFAULT_SIGNATURE_WINDOW_SECONDS
      );
      if (requireSignature) {
        const tsParam = searchParams.get("ts");
        const sigParam = (searchParams.get("sig") || "").toLowerCase();
        const nonce = searchParams.get("nonce") || "";
        const ts = Number(tsParam);
        if ((!masterSecret && !legacySigningSecret) || !Number.isFinite(ts) || !sigParam) {
          return new Response(null, { status: 204, headers: corsHeaders() });
        }
        const now = Math.floor(Date.now() / 1000);
        if (signatureWindow > 0 && Math.abs(now - ts) > signatureWindow) {
          return new Response(null, { status: 204, headers: corsHeaders() });
        }

        const query = canonicalQuery(searchParams);
        const stringToSign = `${ts}|${pathname}|${query}`;
        const derivedKey = masterSecret ? await derivedSigningKey(masterSecret, token) : "";
        const legacyExpected = legacySigningSecret ? await hmacHex(legacySigningSecret, stringToSign) : "";
        const expected = derivedKey ? await hmacHex(derivedKey, stringToSign) : "";
        if (!expected || expected !== sigParam) {
          if (!legacyExpected || legacyExpected !== sigParam) {
            return new Response(null, { status: 204, headers: corsHeaders() });
          }
        }

        if (nonce) {
          const nonceKey = `nonce:${token}:${nonce}`;
          const seen = await env.KANARI_KV.get(nonceKey);
          if (seen) {
            return new Response(null, { status: 204, headers: corsHeaders() });
          }
          const nonceTtl = signatureWindow > 0 ? signatureWindow : DEFAULT_SIGNATURE_WINDOW_SECONDS;
          await env.KANARI_KV.put(nonceKey, "1", { expirationTtl: nonceTtl });
        }
      }

      const eventTtl = getTtl(env.EVENT_TTL_SECONDS, DEFAULT_EVENT_TTL_SECONDS);
      const dedupeTtl = getTtl(env.DEDUPE_TTL_SECONDS, DEFAULT_DEDUPE_TTL_SECONDS);
      const rateLimitWindow = getNumber(
        env.RATE_LIMIT_WINDOW_SECONDS,
        DEFAULT_RATE_LIMIT_WINDOW_SECONDS
      );
      const rateLimitMax = getNumber(env.RATE_LIMIT_MAX, DEFAULT_RATE_LIMIT_MAX);

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
        const canRateLimit = Boolean(ipHash && rateLimitWindow > 0 && rateLimitMax > 0);
        if (canRateLimit) {
          const windowId = Math.floor(Date.now() / 1000 / rateLimitWindow);
          const rateKey = `rl:${token}:${ipHash}:${windowId}`;
          const rateCount = Number(await env.KANARI_KV.get(rateKey)) || 0;
          if (rateCount >= rateLimitMax) {
            return new Response(null, { status: 204, headers: corsHeaders() });
          }
          await env.KANARI_KV.put(rateKey, String(rateCount + 1), {
            expirationTtl: rateLimitWindow,
          });
        }

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

          if (env.MAIL_FROM && env.MAIL_TO) {
            const toList = parseEmailList(env.MAIL_TO);
            if (toList.length) {
              const subjectPrefix = env.MAIL_SUBJECT_PREFIX || "Kanariya alert";
              const subject = `${subjectPrefix}: ${token}`;
              const body = [
                `token: ${token}`,
                `src: ${src}`,
                `ts: ${event.ts}`,
                `country: ${event.country}`,
                `asn: ${event.asn}`,
                `ipHash: ${event.ipHash}`,
                `ua: ${event.ua}`,
                `referer: ${event.referer}`,
              ].join("\n");

              const message = {
                personalizations: [
                  {
                    to: toList.map((email) => ({ email })),
                  },
                ],
                from: {
                  email: env.MAIL_FROM,
                  name: env.MAIL_FROM_NAME || "Kanariya",
                },
                subject,
                content: [{ type: "text/plain", value: body }],
              };

              ctx.waitUntil(
                fetch("https://api.mailchannels.net/tx/v1/send", {
                  method: "POST",
                  headers: { "content-type": "application/json" },
                  body: JSON.stringify(message),
                })
              );
            }
          }
        }
      } catch (err) {
        console.error("kanariya_error", err);
      }

      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (pathname === "/admin/sign") {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders() });
      }
      if (request.method !== "GET") {
        return new Response("Method not allowed", { status: 405, headers: corsHeaders() });
      }

      const token = textOrEmpty(searchParams.get("token") || "");
      const src = textOrEmpty(searchParams.get("src") || "");
      const nonceParam = textOrEmpty(searchParams.get("nonce") || "", 256);
      const authHeader = request.headers.get("authorization") || "";
      const adminKey = env.ADMIN_KEY || "";
      const bearerKey = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
      const allowPublicSign = ["1", "true", "yes"].includes(
        String(env.ALLOW_PUBLIC_SIGN || "").toLowerCase()
      );
      if (!allowPublicSign) {
        if (!adminKey || bearerKey !== adminKey) {
          return new Response("Forbidden", { status: 403, headers: corsHeaders() });
        }
      }

      if (!token) {
        return new Response("Missing token", { status: 400, headers: corsHeaders() });
      }

      const legacySigningSecret = env.SIGNING_SECRET || "";
      const masterSecret = env.MASTER_SECRET || legacySigningSecret || "";
      if (!masterSecret) {
        return new Response("Signing not configured", { status: 503, headers: corsHeaders() });
      }

      try {
        const ts = Math.floor(Date.now() / 1000);
        const nonce = nonceParam || randomId();
        const params = new URLSearchParams();
        params.set("ts", String(ts));
        if (src) params.set("src", src);
        if (nonce) params.set("nonce", nonce);
        const query = canonicalQuery(params);
        const path = `/canary/${token}`;
        const stringToSign = `${ts}|${path}|${query}`;
        const derivedKey = await derivedSigningKey(masterSecret, token);
        const sig = await hmacHex(derivedKey, stringToSign);

        const signedUrl = `${url.origin}${path}?${query}&sig=${sig}`;
        return new Response(JSON.stringify({ url: signedUrl, token, ts, nonce }), {
          status: 200,
          headers: { "content-type": "application/json", ...corsHeaders() },
        });
      } catch (err) {
        console.error("kanariya_admin_error", err);
        return new Response("Error", { status: 500, headers: corsHeaders() });
      }
    }

    if (pathname === "/admin/export") {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders() });
      }

      const token = textOrEmpty(searchParams.get("token") || "");
      const authHeader = request.headers.get("authorization") || "";
      const adminKey = env.ADMIN_KEY || "";
      const bearerKey = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
      const allowPublicExport = ["1", "true", "yes"].includes(
        String(env.ALLOW_PUBLIC_EXPORT || "").toLowerCase()
      );

      if (!allowPublicExport) {
        if (!adminKey || bearerKey !== adminKey) {
          return new Response("Forbidden", { status: 403, headers: corsHeaders() });
        }
      }
      if (!token) {
        return new Response("Missing token", { status: 400, headers: corsHeaders() });
      }

      try {
        const maxItems = getTtl(env.EXPORT_MAX_ITEMS, DEFAULT_EXPORT_MAX_ITEMS);
        const events = await listEventsForToken(env, token, maxItems);
        return new Response(JSON.stringify(events), {
          status: 200,
          headers: { "content-type": "application/json", ...corsHeaders() },
        });
      } catch (err) {
        console.error("kanariya_admin_error", err);
        return new Response("Error", { status: 500, headers: corsHeaders() });
      }
    }

    return new Response("Not found", { status: 404 });
  },
};
