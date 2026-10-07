import { describe, it, expect, afterEach, vi } from "vitest";
import worker from "../src/worker.js";
import { setup, admin, hits } from "./helpers.js";

const requestHit = url => new Request(url, { headers: { "cf-connecting-ip": "203.0.113.9", "user-agent": "UnitTest" } });
const create = async (s, data = {}) => {
  const res = await worker.fetch(admin("/admin/tokens", { method: "POST", data: { name: "Invoice", location: "Drive / invoices", src: "invoice_2026", ...data } }), s.env);
  expect(res.status).toBe(201);
  return res.json();
};
const inventory = async s => (await (await worker.fetch(admin("/admin/tokens"), s.env)).json()).tokens;
const send = (s, request) => worker.fetch(request, s.env);

afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

describe("HTTPS transport", () => {
  it.each([
    ["GET", "/canary/legacy"],
    ["OPTIONS", "/canary/legacy"],
    ["GET", "/admin/tokens"],
    ["POST", "/admin/tokens"],
    ["OPTIONS", "/admin/tokens"],
    ["GET", "/admin/export?token=legacy"],
    ["GET", "/admin/sign?token=legacy"],
    ["POST", `/admin/tokens/kr_${"a".repeat(64)}/test`],
    ["POST", `/admin/tokens/kr_${"a".repeat(64)}/revoke`],
  ])("rejects public HTTP %s %s before touching bindings", async (method, path) => {
    const env = new Proxy({}, { get() { throw new Error("Bindings must not be accessed"); } });
    const response = await worker.fetch(new Request(`http://example.test${path}`, {
      method,
      headers: {
        authorization: "Bearer synthetic-admin",
        "x-forwarded-proto": "https",
        "cf-visitor": '{"scheme":"https"}',
        "content-type": "application/json",
      },
      ...(method === "POST" ? { body: '{"name":"Synthetic token"}' } : {}),
    }), env);
    expect(response.status).toBe(400);
    expect(await response.text()).toBe("HTTPS required");
    expect(response.headers.get("location")).toBeNull();
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it.each(["localhost.example.test", "127.0.0.1.example.test", "0.0.0.0", "192.168.1.5"])("rejects HTTP for non-loopback host %s", async host => {
    const response = await worker.fetch(new Request(`http://${host}/admin/tokens`), {});
    expect(response.status).toBe(400);
  });

  it("does not count or queue a plaintext hit for an existing managed token", async () => {
    const s = setup({ WEBHOOK_URL: "https://hooks.example.test" });
    const token = await create(s);
    expect(token.url).toMatch(/^https:\/\//);
    expect((await send(s, requestHit(token.url.replace("https:", "http:")))).status).toBe(400);
    expect(hits(s, token.token)).toHaveLength(0);
    expect(s.object.rows("SELECT * FROM deliveries")).toHaveLength(0);
    expect((await inventory(s))[0].hitCount).toBe(0);
  });

  it.each(["localhost", "127.0.0.1", "[::1]"])("preserves HTTP development on %s", async host => {
    const s = setup();
    const origin = `http://${host}:8787`;
    const response = await worker.fetch(new Request(`${origin}/admin/tokens`, {
      method: "POST",
      headers: { authorization: "Bearer test-admin", "content-type": "application/json" },
      body: JSON.stringify({ name: "Local synthetic token" }),
    }), s.env);
    expect(response.status).toBe(201);
    const token = await response.json();
    expect(token.url).toBe(`${origin}/canary/${token.token}`);
    expect((await send(s, requestHit(token.url))).status).toBe(204);
    expect(hits(s, token.token)).toHaveLength(1);
  });
});

describe("private administration", () => {
  it.each(["GET /admin/export?token=legacy", "POST /admin/export?token=legacy", "GET /admin/tokens", "POST /admin/tokens", "GET /admin/sign?token=legacy", `POST /admin/tokens/kr_${"a".repeat(64)}/test`, `POST /admin/tokens/kr_${"a".repeat(64)}/revoke`])("requires the key for %s even with public flags", async route => {
    const s = setup({ ALLOW_PUBLIC_EXPORT: "1", ALLOW_PUBLIC_SIGN: "1" });
    await s.env.KANARI_KV.put("event:legacy:old", JSON.stringify({ token: "legacy", ts: "2026-01-01", src: "private" }));
    const [method, path] = route.split(" ");
    for (const key of ["", "wrong"]) {
      const res = await send(s, admin(path, { method, key }));
      expect(res.status).toBe(403);
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(await res.text()).not.toContain("private");
    }
    s.env.ADMIN_KEY = "";
    expect((await send(s, admin(path, { method, key: "" }))).status).toBe(403);
  });
  it("bounds old KV reads and marks truncated legacy history", async () => {
    const s = setup({ EXPORT_MAX_ITEMS: "2" });
    for (let i = 0; i < 1005; i++) await s.env.KANARI_KV.put(`event:legacy:${String(i).padStart(4, "0")}`, JSON.stringify({ token: "legacy", ts: new Date(i * 1000).toISOString() }));
    await s.env.KANARI_KV.put("event:legacy:sibling:1", JSON.stringify({ token: "legacy:sibling", ts: "2099", secret: true }));
    const res = await send(s, admin("/admin/export?token=legacy"));
    expect(res.status).toBe(200);
    const events = await res.json();
    expect(events).toHaveLength(2);
    expect(events[0].ts).toBe(new Date(1000).toISOString());
    expect(res.headers.get("x-kanariya-legacy-truncated")).toBe("true");
    expect(events.every(event => event.token === "legacy")).toBe(true);
    s.env.EXPORT_MAX_ITEMS = "1000";
    const collision = setup();
    await collision.env.KANARI_KV.put("event:legacy:child:1", JSON.stringify({ token: "legacy:child", secret: true }));
    expect(await (await send(collision, admin("/admin/export?token=legacy"))).json()).toEqual([]);
    expect((await send(s, admin("/admin/export?token=legacy", { method: "POST" }))).status).toBe(405);
  });
  it("rejects aliases and duplicate parameters before access", async () => {
    const s = setup();
    for (const token of ["legacy:child", "legacy/extra", "%6cegacy"]) {
      expect((await send(s, admin(`/admin/export?token=${encodeURIComponent(token)}`))).status).toBe(400);
      await send(s, requestHit(`https://example.test/canary/${token}`));
    }
    expect((await send(s, admin("/admin/export?token=legacy&token=other"))).status).toBe(400);
    expect(s.object.rows("SELECT * FROM events")).toHaveLength(0);
  });
});

describe("managed token lifecycle", () => {
  it("uses 256-bit tokens, accepts repeated hits beyond five minutes and trusts placement metadata", async () => {
    const s = setup({ REQUIRE_SIGNATURE: "1" });
    const token = await create(s);
    expect(token.token).toMatch(/^kr_[a-f0-9]{64}$/);
    expect(Date.parse(token.expiresAt) - Date.parse(token.createdAt)).toBe(90 * 86400000);
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 86400000);
    await send(s, requestHit(token.url));
    await send(s, requestHit(`${token.url}?src=forged&ts=0&sig=bad`));
    expect(hits(s, token.token)).toHaveLength(2);
    expect(hits(s, token.token).every(e => e.src === "invoice_2026" && e.location === "Drive / invoices")).toBe(true);
    const row = (await inventory(s))[0];
    expect(row.hitCount).toBe(2);
    expect(row.lastSeenAt).toBeTruthy();
    expect(hits(s, token.token)[0].ipHash).not.toBe("203.0.113.9");
    expect(hits(s, token.token)[0].ipHash).toMatch(/^[a-f0-9]{64}$/);
  });
  it("records TEST separately without consuming URL, expiry or real detection counters", async () => {
    const s = setup({ WEBHOOK_URL: "https://hooks.example.test" });
    const token = await create(s);
    const tested = await send(s, admin(`/admin/tokens/${token.token}/test`, { method: "POST" }));
    expect(tested.status).toBe(200);
    expect((await tested.json()).deliveries[0].state).toBe("pending");
    const before = (await inventory(s))[0];
    expect(before.hitCount).toBe(0);
    expect(before.lastSeenAt).toBeNull();
    expect(before.lastTestAt).toBeTruthy();
    expect(before.expiresAt).toBe(token.expiresAt);
    expect((await send(s, admin(`/admin/tokens/${token.token}/test`, { method: "POST" }))).status).toBe(429);
    await send(s, requestHit(token.url));
    expect(hits(s, token.token).filter(e => !e.test)).toHaveLength(1);
    expect((await inventory(s))[0].hitCount).toBe(1);
  });
  it("enforces revocation and expiry even when unsigned legacy mode is enabled", async () => {
    const s = setup({ REQUIRE_SIGNATURE: "0" });
    const revoked = await create(s);
    const expired = await create(s, { expiresAt: new Date(Date.now() + 1000).toISOString() });
    await send(s, admin(`/admin/tokens/${revoked.token}/revoke`, { method: "POST" }));
    s.restart();
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 2000);
    for (const row of [revoked, expired]) {
      await send(s, requestHit(row.url));
      await send(s, requestHit(`${row.url}?ts=1&sig=anything`));
      expect(hits(s, row.token)).toHaveLength(0);
    }
    await send(s, requestHit(`https://example.test/canary/kr_${"a".repeat(64)}`));
    expect(s.object.rows("SELECT * FROM events")).toHaveLength(0);
    expect((await inventory(s)).map(t => t.state).sort()).toEqual(["expired", "revoked"]);
    // An administrative test does not reactivate an inactive plant.
    expect((await send(s, admin(`/admin/tokens/${revoked.token}/test`, { method: "POST" }))).status).toBe(200);
    expect((await inventory(s)).find(t => t.token === revoked.token).state).toBe("revoked");
  });
  it("serializes simultaneous hits for rate limits and dedupe", async () => {
    const s = setup({ WEBHOOK_URL: "https://hooks.example.test", RATE_LIMIT_MAX: "3" });
    const token = await create(s, { expiresAt: null });
    await Promise.all(Array.from({ length: 20 }, () => send(s, requestHit(token.url))));
    expect(hits(s, token.token)).toHaveLength(3);
    expect((await inventory(s))[0].hitCount).toBe(3);
    expect(s.object.rows("SELECT * FROM deliveries")).toHaveLength(1);
  });
  it("rejects malformed creation and enforces inventory capacity", async () => {
    const s = setup({ TOKEN_MAX_ITEMS: "1" });
    for (const data of [{}, { name: " " }, { name: "x".repeat(121) }, { name: "X", expiresAt: 123 }, { name: "X", expiresAt: "yesterday" }, { name: "X", expiresAt: "2020-01-01" }]) {
      expect((await send(s, admin("/admin/tokens", { method: "POST", data }))).status).toBe(400);
    }
    await create(s);
    expect((await send(s, admin("/admin/tokens", { method: "POST", data: { name: "Second" } }))).status).toBe(409);
  });
  it("fails closed on missing binding and rolls back evidence when alarm persistence fails", async () => {
    const s = setup();
    const token = await create(s);
    vi.spyOn(s.storage, "setAlarm").mockRejectedValue(new Error("disk failure"));
    vi.spyOn(console, "error").mockImplementation(() => {});
    await send(s, requestHit(token.url));
    expect(hits(s, token.token)).toHaveLength(0);
    expect((await inventory(s))[0].hitCount).toBe(0);
    delete s.env.KANARI_STORE;
    expect((await send(s, admin("/admin/tokens"))).status).toBe(503);
    expect((await send(s, requestHit(token.url))).status).toBe(204);
  });
});

describe("legacy compatibility", () => {
  it.each(["MASTER_SECRET", "SIGNING_SECRET"])("retains %s signing, replay suppression and expiry", async secret => {
    const s = setup({ [secret]: "legacy-test-secret", REQUIRE_SIGNATURE: "1" });
    const signed = await send(s, admin("/admin/sign?token=legacy&src=old"));
    expect(signed.status).toBe(200);
    const { url } = await signed.json();
    await send(s, requestHit("https://example.test/canary/legacy?src=unsigned"));
    expect(hits(s, "legacy")).toHaveLength(0);
    await Promise.all([send(s, requestHit(url)), send(s, requestHit(url))]);
    expect(hits(s, "legacy")).toHaveLength(1);
    expect(hits(s, "legacy")[0].src).toBe("old");
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 400000);
    await send(s, requestHit(url));
    expect(hits(s, "legacy")).toHaveLength(1);
  });
  it("retains a nonce through the validity of a future-skewed signature", async () => {
    const s = setup({ MASTER_SECRET: "secret", REQUIRE_SIGNATURE: "1", SIGNATURE_WINDOW_SECONDS: "300" });
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now + 299000);
    const { url } = await (await send(s, admin("/admin/sign?token=skewed"))).json();
    clock.mockReturnValue(now);
    await send(s, requestHit(url));
    clock.mockReturnValue(now + 301000);
    await send(s, requestHit(url));
    expect(hits(s, "skewed")).toHaveLength(1);
  });
  it("preserves ordinary legacy kr_ names without managed fallback", async () => {
    const s = setup({ MASTER_SECRET: "secret", REQUIRE_SIGNATURE: "1" });
    const signed = await send(s, admin("/admin/sign?token=kr_invoice"));
    expect(signed.status).toBe(200);
    const { url } = await signed.json();
    await send(s, requestHit(url));
    expect(hits(s, "kr_invoice")).toHaveLength(1);
    expect((await send(s, admin("/admin/export?token=kr_invoice"))).status).toBe(200);
  });
  it("honors legacy nonce markers already in KV", async () => {
    const s = setup({ MASTER_SECRET: "secret", REQUIRE_SIGNATURE: "1" });
    const signed = await (await send(s, admin("/admin/sign?token=legacy&nonce=used"))).json();
    await s.env.KANARI_KV.put("nonce:legacy:used", "1");
    await send(s, requestHit(signed.url));
    expect(hits(s, "legacy")).toHaveLength(0);
  });
});

describe("durable notification outbox", () => {
  it("keeps per-channel retry state across reconstruction and does not resend accepted channels", async () => {
    const s = setup({ WEBHOOK_URL: "https://generic.example.test", SLACK_WEBHOOK_URL: "https://slack.example.test" });
    const token = await create(s);
    const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(async url => new Response(null, { status: url.includes("slack") ? 503 : 200 }));
    await send(s, requestHit(token.url));
    expect(fetch).not.toHaveBeenCalled();
    await s.object.alarm();
    let exported = await (await send(s, admin(`/admin/export?token=${token.token}`))).json();
    expect(exported[0].deliveries.find(d => d.type === "webhook").state).toBe("accepted");
    expect(exported[0].deliveries.find(d => d.type === "slack").state).toBe("retrying");
    const next = Date.parse(exported[0].deliveries.find(d => d.type === "slack").nextAttemptAt);
    s.restart();
    vi.spyOn(Date, "now").mockReturnValue(next + 1);
    fetch.mockResolvedValue(new Response(null, { status: 200 }));
    await s.object.alarm();
    exported = await (await send(s, admin(`/admin/export?token=${token.token}`))).json();
    expect(exported[0].deliveries.every(d => d.state === "accepted")).toBe(true);
    expect(fetch).toHaveBeenCalledTimes(3);
    expect(exported[0].deliveries.find(d => d.type === "slack").attempts).toBe(2);
  });
  it("stops bounded retries and records terminal failure", async () => {
    const s = setup({ WEBHOOK_URL: "https://generic.example.test", NOTIFY_MAX_ATTEMPTS: "2" });
    const token = await create(s);
    vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("network"));
    await send(s, requestHit(token.url));
    await s.object.alarm();
    const row = s.object.one("SELECT * FROM deliveries");
    vi.spyOn(Date, "now").mockReturnValue(row.next_at + 1);
    await s.object.alarm();
    expect(s.object.one("SELECT * FROM deliveries")).toMatchObject({ state: "failed", attempts: 2, error: "network_error", next_at: null });
  });
  it("retains observable queue overflow and deletes expired details without erasing inventory", async () => {
    const s = setup({ WEBHOOK_URL: "https://generic.example.test", SLACK_WEBHOOK_URL: "https://slack.example.test", NOTIFY_QUEUE_MAX: "1", EVENT_TTL_SECONDS: "60" });
    const token = await create(s);
    await send(s, requestHit(token.url));
    expect(s.object.rows("SELECT state,error FROM deliveries")).toEqual(expect.arrayContaining([{ state: "failed", error: "queue_full" }]));
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 61000);
    await s.object.alarm();
    expect(hits(s, token.token)).toHaveLength(0);
    expect(s.object.rows("SELECT * FROM deliveries")).toHaveLength(0);
    expect((await inventory(s))[0].hitCount).toBe(1);
  });
  it("uses a recovery alarm and stable delivery ID after an interrupted send", async () => {
    const s = setup({ WEBHOOK_URL: "https://generic.example.test" });
    const token = await create(s);
    await send(s, requestHit(token.url));
    const row = s.object.one("SELECT * FROM deliveries");
    s.object.sql.exec("UPDATE deliveries SET state='retrying',attempts=1,next_at=?", Date.now() + 60000);
    s.restart();
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 61000);
    const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
    await s.object.alarm();
    expect(JSON.parse(fetch.mock.calls[0][1].body).deliveryId).toBe(row.id);
    expect(s.object.one("SELECT * FROM deliveries")).toMatchObject({ state: "accepted", attempts: 2 });
  });
});
