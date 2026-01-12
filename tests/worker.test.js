import { describe, it, expect, beforeEach, vi } from "vitest";
import worker from "../src/worker.js";
import { webcrypto } from "crypto";

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}

class MemoryKV {
  constructor() {
    this.store = new Map();
  }

  async get(key, type) {
    const value = this.store.get(key);
    if (value === undefined) return null;
    if (type === "json") return JSON.parse(value);
    return value;
  }

  async put(key, value) {
    this.store.set(key, value);
  }

  async list({ prefix = "", limit = 100 }) {
    const keys = [];
    for (const key of this.store.keys()) {
      if (key.startsWith(prefix)) {
        keys.push({ name: key });
      }
    }
    return { keys: keys.slice(0, limit), cursor: "" };
  }
}

const baseEnv = () => ({
  KANARI_KV: new MemoryKV(),
  IP_HMAC_KEY: "unit-test-secret",
  EVENT_TTL_SECONDS: "2592000",
  DEDUPE_TTL_SECONDS: "1800",
});

function withCf(request, cf) {
  Object.defineProperty(request, "cf", { value: cf, enumerable: false });
  return request;
}

describe("kanariya worker", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 204 on /canary and stores event", async () => {
    const env = baseEnv();
    const request = withCf(
      new Request("https://example.com/canary/test-token?src=smoke", {
        headers: { "user-agent": "UnitTest", "cf-connecting-ip": "203.0.113.1" },
      }),
      { country: "JP", asn: 64512 }
    );

    const response = await worker.fetch(request, env, { waitUntil() {} });
    expect(response.status).toBe(204);

    const listed = await env.KANARI_KV.list({ prefix: "event:test-token:" });
    expect(listed.keys.length).toBe(1);
  });

  it("dedupes webhook notifications", async () => {
    const env = { ...baseEnv(), WEBHOOK_URL: "https://hooks.example.test" };
    const calls = [];
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (url, options) => {
        calls.push({ url, options });
        return new Response("ok", { status: 200 });
      });

    const request = withCf(
      new Request("https://example.com/canary/test-token?src=dedupe", {
        headers: { "user-agent": "UnitTest", "cf-connecting-ip": "203.0.113.5" },
      }),
      { country: "US", asn: 64513 }
    );

    await worker.fetch(request, env, { waitUntil(promise) { return promise; } });
    await worker.fetch(request, env, { waitUntil(promise) { return promise; } });

    expect(fetchSpy).toHaveBeenCalled();
    expect(calls.length).toBe(1);
  });

  it("hashes IPs before storage", async () => {
    const env = baseEnv();
    const request = withCf(
      new Request("https://example.com/canary/test-token?src=hash", {
        headers: { "user-agent": "UnitTest", "cf-connecting-ip": "203.0.113.9" },
      }),
      { country: "GB", asn: 64514 }
    );

    await worker.fetch(request, env, { waitUntil() {} });

    const listed = await env.KANARI_KV.list({ prefix: "event:test-token:" });
    const event = await env.KANARI_KV.get(listed.keys[0].name, "json");
    expect(event.ipHash).toBeTruthy();
    expect(event.ipHash).not.toEqual("203.0.113.9");
  });
});
