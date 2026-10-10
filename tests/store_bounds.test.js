import { afterEach, describe, expect, it, vi } from "vitest";
import worker from "../src/worker.js";
import { admin, hits, setup } from "./helpers.js";

const send = (s, request) => worker.fetch(request, s.env);
const create = async s => {
  const response = await send(s, admin("/admin/tokens", { method: "POST", data: { name: "Capacity fixture", expiresAt: null } }));
  expect(response.status).toBe(201);
  return response.json();
};
const hit = (url, ip = "198.51.100.7", ua = "Fixture") => new Request(url, {
  headers: { ...(ip === null ? {} : { "cf-connecting-ip": ip }), ...(ua === null ? {} : { "user-agent": ua }) },
});
const rows = (s, table) => s.object.rows(`SELECT * FROM ${table} ORDER BY 1`);
const inventory = async s => (await (await send(s, admin("/admin/tokens"))).json()).tokens;

afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

describe("retained event capacity", () => {
  it("stops one saturated token before any guard or delivery writes and preserves another token's evidence", async () => {
    const s = setup({ WEBHOOK_URL: "https://fixture.test/hook", EVENT_MAX_ITEMS_PER_TOKEN: "2", EVENT_MAX_ITEMS: "4", RATE_LIMIT_WINDOW_SECONDS: "86400" });
    const saturated = await create(s);
    const other = await create(s);
    await send(s, hit(other.url));
    const evidence = rows(s, "events")[0];
    const pending = rows(s, "deliveries")[0];
    await send(s, hit(saturated.url));
    await send(s, hit(saturated.url));
    const guards = rows(s, "guards");
    const deliveries = rows(s, "deliveries");
    await Promise.all(Array.from({ length: 20 }, (_, i) => send(s, hit(saturated.url, `198.51.100.${i + 10}`, `Changed-${i}`))));
    expect(hits(s, saturated.token)).toHaveLength(2);
    expect(rows(s, "guards")).toEqual(guards);
    expect(rows(s, "deliveries")).toEqual(deliveries);
    expect(rows(s, "events")).toContainEqual(evidence);
    expect(rows(s, "deliveries")).toContainEqual(pending);
    expect((await inventory(s)).find(t => t.token === saturated.token).hitCount).toBe(2);
    expect((await send(s, hit(other.url))).status).toBe(204);
    expect(hits(s, other.token)).toHaveLength(2);
  });

  it("shares the installation cap across legacy, managed and administrative test events", async () => {
    const s = setup({ WEBHOOK_URL: "https://fixture.test/hook", EVENT_MAX_ITEMS: "3", EVENT_MAX_ITEMS_PER_TOKEN: "3", RATE_LIMIT_MAX: "0" });
    const token = await create(s);
    await send(s, hit("https://example.test/canary/legacy"));
    await send(s, hit(token.url));
    const test = await send(s, admin(`/admin/tokens/${token.token}/test`, { method: "POST" }));
    expect(test.status).toBe(200);
    const snapshot = { events: rows(s, "events"), guards: rows(s, "guards"), deliveries: rows(s, "deliveries") };
    s.restart();
    s.env.EVENT_MAX_ITEMS = "1";
    expect((await send(s, hit("https://example.test/canary/new-legacy"))).status).toBe(204);
    expect((await send(s, hit(token.url, "198.51.100.99"))).status).toBe(204);
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 11000);
    const full = await send(s, admin(`/admin/tokens/${token.token}/test`, { method: "POST" }));
    expect(full.status).toBe(409);
    expect(await full.json()).toEqual({ error: "event_capacity" });
    expect(rows(s, "events")).toEqual(snapshot.events);
    expect(rows(s, "guards")).toEqual(snapshot.guards);
    expect(rows(s, "deliveries")).toEqual(snapshot.deliveries);
    expect((await inventory(s))[0].hitCount).toBe(1);
  });

  it("does not consume a legacy nonce when storage is full", async () => {
    const s = setup({ MASTER_SECRET: "synthetic-secret", REQUIRE_SIGNATURE: "1", EVENT_MAX_ITEMS: "1" });
    const first = await (await send(s, admin("/admin/sign?token=legacy&nonce=first"))).json();
    const second = await (await send(s, admin("/admin/sign?token=legacy&nonce=second"))).json();
    await send(s, hit(first.url));
    const guards = rows(s, "guards");
    await send(s, hit(second.url));
    expect(hits(s, "legacy")).toHaveLength(1);
    expect(rows(s, "guards")).toEqual(guards);
    expect(guards.some(row => row.key.includes('"second"'))).toBe(false);
  });

  it("recovers capacity by deleting expired rows before admission without waiting for an alarm", async () => {
    const now = 1_800_000_000_000;
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    const s = setup({ WEBHOOK_URL: "https://fixture.test/hook", EVENT_MAX_ITEMS: "1", EVENT_MAX_ITEMS_PER_TOKEN: "1", EVENT_TTL_SECONDS: "60", RATE_LIMIT_MAX: "0", DEDUPE_TTL_SECONDS: "60" });
    const first = await create(s);
    const second = await create(s);
    await send(s, hit(first.url));
    const oldId = hits(s, first.token)[0].id;
    clock.mockReturnValue(now + 60000);
    await send(s, hit(second.url));
    expect(hits(s, first.token)).toEqual([]);
    expect(hits(s, second.token)).toHaveLength(1);
    expect(rows(s, "deliveries")).toHaveLength(1);
    expect(rows(s, "deliveries")[0].event_id).not.toBe(oldId);
    expect(rows(s, "guards").every(row => row.expires_at > Date.now())).toBe(true);
    expect((await inventory(s)).map(t => t.hitCount)).toEqual([1, 1]);
  });

  it("serializes concurrent admission at both retained-row limits", async () => {
    const s = setup({ EVENT_MAX_ITEMS: "4", EVENT_MAX_ITEMS_PER_TOKEN: "3", RATE_LIMIT_MAX: "0" });
    const token = await create(s);
    const responses = await Promise.all(Array.from({ length: 30 }, () => send(s, hit(token.url))));
    expect(responses.every(response => response.status === 204)).toBe(true);
    expect(hits(s, token.token)).toHaveLength(3);
    expect((await inventory(s))[0].hitCount).toBe(3);
    await Promise.all(Array.from({ length: 30 }, (_, i) => send(s, hit(`https://example.test/canary/legacy-${i}`))));
    expect(rows(s, "events")).toHaveLength(4);
  });

  it.each(["0", "-5"])("clamps %s capacity settings to one instead of disabling them", async value => {
    const s = setup({ EVENT_MAX_ITEMS: value, EVENT_MAX_ITEMS_PER_TOKEN: value, RATE_LIMIT_MAX: "0" });
    await send(s, hit("https://example.test/canary/first"));
    await send(s, hit("https://example.test/canary/first"));
    await send(s, hit("https://example.test/canary/second"));
    expect(rows(s, "events")).toHaveLength(1);
  });
});

describe("notification suppression", () => {
  it("honors every unexpired legacy UA guard across reconstruction, then admits after expiry", async () => {
    const s = setup({ WEBHOOK_URL: "https://fixture.test/hook", RATE_LIMIT_MAX: "0" });
    const token = await create(s);
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    await send(s, hit(token.url));
    const ipHash = hits(s, token.token)[0].ipHash;
    s.object.sql.exec("DELETE FROM guards");
    for (const [ua, expiry] of [["Original", now + 120000], ["Other", now + 240000]]) {
      s.object.sql.exec("INSERT INTO guards VALUES(?,?,?)", JSON.stringify(["dedupe", token.token, ipHash, ua]), 1, expiry);
    }
    // A different token's later expiry must not extend this token's suppression.
    s.object.sql.exec("INSERT INTO guards VALUES(?,?,?)", JSON.stringify(["dedupe", `${token.token}_other`, ipHash, "Original"]), 1, now + 360000);
    s.restart();
    await send(s, hit(token.url, "198.51.100.7", "Original"));
    await send(s, hit(token.url, "198.51.100.7", "Changed"));
    await send(s, hit(token.url, "198.51.100.7", null));
    expect(rows(s, "deliveries")).toHaveLength(1);
    clock.mockReturnValue(now + 120000);
    await send(s, hit(token.url));
    expect(rows(s, "deliveries")).toHaveLength(1);
    clock.mockReturnValue(now + 240000);
    await send(s, hit(token.url));
    expect(rows(s, "deliveries")).toHaveLength(2);
    expect(hits(s, token.token)).toHaveLength(6);
  });

  it.each(["managed", "legacy"])("deduplicates changed and omitted User-Agent for a %s token while recording repeats", async mode => {
    const s = setup({ WEBHOOK_URL: "https://fixture.test/hook", RATE_LIMIT_MAX: "0" });
    const url = mode === "managed" ? (await create(s)).url : "https://example.test/canary/legacy";
    const token = url.split("/").at(-1);
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    await send(s, hit(url));
    // The aggregate cooldown has elapsed, so IP dedupe must still suppress these.
    clock.mockReturnValue(now + 61000);
    await send(s, hit(url, "198.51.100.7", "Changed"));
    await send(s, hit(url, "198.51.100.7", null));
    expect(hits(s, token)).toHaveLength(3);
    expect(rows(s, "deliveries")).toHaveLength(1);
    expect(rows(s, "guards").every(row => !row.key.includes("Fixture") && !row.key.includes("Changed"))).toBe(true);
  });

  it.each([
    ["missing IP", {}, null],
    ["missing HMAC key", { IP_HMAC_KEY: "" }, "198.51.100.7"],
  ])("uses a private per-token fallback bucket for %s", async (_label, overrides, ip) => {
    const s = setup({ WEBHOOK_URL: "https://fixture.test/hook", RATE_LIMIT_MAX: "0", ...overrides });
    const token = await create(s);
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    await send(s, hit(token.url, ip, null));
    clock.mockReturnValue(now + 61000);
    await send(s, hit(token.url, ip, "Changed"));
    expect(hits(s, token.token)).toHaveLength(2);
    expect(hits(s, token.token).every(event => event.ipHash === "")).toBe(true);
    expect(rows(s, "deliveries")).toHaveLength(1);
    const stored = JSON.stringify([...rows(s, "events"), ...rows(s, "guards")]);
    expect(stored).not.toContain("198.51.100.7");
  });

  it("bounds rotating-IP notifications per token without suppressing evidence or other tokens", async () => {
    const s = setup({ WEBHOOK_URL: "https://fixture.test/hook", RATE_LIMIT_MAX: "0", NOTIFY_TOKEN_COOLDOWN_SECONDS: "60" });
    const token = await create(s);
    const other = await create(s);
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    await Promise.all(Array.from({ length: 20 }, (_, i) => send(s, hit(token.url, `198.51.100.${i + 1}`, i % 2 ? null : `Changed-${i}`))));
    expect(hits(s, token.token)).toHaveLength(20);
    expect((await inventory(s)).find(t => t.token === token.token).hitCount).toBe(20);
    expect(rows(s, "deliveries")).toHaveLength(1);
    s.restart();
    await send(s, hit(other.url));
    expect(rows(s, "deliveries")).toHaveLength(2);
    clock.mockReturnValue(now + 60000);
    await send(s, hit(token.url, "198.51.100.99", null));
    expect(rows(s, "deliveries")).toHaveLength(3);
    expect(hits(s, token.token)).toHaveLength(21);
  });

  it("allows a normal visitor after IP dedupe expires and keeps admin tests independent", async () => {
    const s = setup({ WEBHOOK_URL: "https://fixture.test/hook", RATE_LIMIT_MAX: "0" });
    const token = await create(s);
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    await send(s, hit(token.url));
    expect((await send(s, admin(`/admin/tokens/${token.token}/test`, { method: "POST" }))).status).toBe(200);
    clock.mockReturnValue(now + 1800000);
    await send(s, hit(token.url));
    expect(rows(s, "deliveries")).toHaveLength(3);
    expect(hits(s, token.token).filter(event => event.test)).toHaveLength(1);
    expect((await inventory(s))[0].hitCount).toBe(2);
  });

  it.each(["0", "-1"])("clamps %s notification cooldown to one second instead of disabling it", async value => {
    const s = setup({ WEBHOOK_URL: "https://fixture.test/hook", RATE_LIMIT_MAX: "0", NOTIFY_TOKEN_COOLDOWN_SECONDS: value });
    const token = await create(s);
    const now = Date.now();
    const clock = vi.spyOn(Date, "now").mockReturnValue(now);
    await send(s, hit(token.url));
    await send(s, hit(token.url, "198.51.100.8"));
    expect(rows(s, "deliveries")).toHaveLength(1);
    clock.mockReturnValue(now + 1000);
    await send(s, hit(token.url, "198.51.100.8"));
    expect(rows(s, "deliveries")).toHaveLength(2);
  });
});
