import { createRequire } from "node:module";
const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite");
import { webcrypto } from "node:crypto";
import { KanariyaStore } from "../src/store.js";
if (!globalThis.crypto) globalThis.crypto = webcrypto;

export class MemoryStorage {
  constructor() {
    this.db = new DatabaseSync(":memory:");
    this.alarm = null;
    this.tail = Promise.resolve();
    this.sql = { exec: (query, ...args) => {
      if (!args.length && query.trim().split(";").filter(Boolean).length > 1) { this.db.exec(query); return []; }
      const statement = this.db.prepare(query);
      return statement.columns().length ? statement.all(...args) : (statement.run(...args), []);
    } };
  }
  async getAlarm() { return this.alarm; }
  async setAlarm(time) { this.alarm = time; }
  async deleteAlarm() { this.alarm = null; }
  async transaction(fn) {
    const result = this.tail.then(async () => {
      const oldAlarm = this.alarm;
      this.db.exec("BEGIN");
      try { const value = await fn(this); this.db.exec("COMMIT"); return value; }
      catch (error) { this.db.exec("ROLLBACK"); this.alarm = oldAlarm; throw error; }
    });
    this.tail = result.catch(() => {});
    return result;
  }
}
export class MemoryKV {
  constructor() { this.store = new Map(); }
  async get(key, type) { if (Array.isArray(key)) return new Map(await Promise.all(key.map(async k => [k, await this.get(k, type)]))); const value = this.store.get(key); return value === undefined ? null : type === "json" ? JSON.parse(value) : value; }
  async put(key, value) { this.store.set(key, value); }
  async list({ prefix = "", limit = 100, cursor = "0" }) {
    const all = [...this.store.keys()].filter(key => key.startsWith(prefix)).sort();
    const start = Number(cursor);
    return { keys: all.slice(start, start + limit).map(name => ({ name })), list_complete: start + limit >= all.length, cursor: start + limit < all.length ? String(start + limit) : "" };
  }
}
export function setup(overrides = {}) {
  const env = { KANARI_KV: new MemoryKV(), ADMIN_KEY: "test-admin", IP_HMAC_KEY: "test-ip-key", ...overrides };
  const storage = new MemoryStorage();
  let object = new KanariyaStore({ storage }, env);
  env.KANARI_STORE = { idFromName: value => value, get: () => ({ fetch: request => object.fetch(request) }) };
  return { env, storage, get object() { return object; }, restart() { object = new KanariyaStore({ storage }, env); } };
}
export function admin(path, { method = "GET", data, key = "test-admin" } = {}) {
  return new Request(`https://example.test${path}`, { method, headers: { authorization: `Bearer ${key}`, "content-type": "application/json" }, ...(data === undefined ? {} : { body: JSON.stringify(data) }) });
}
export function hits(store, token) { return store.object.rows("SELECT body FROM events WHERE token=? ORDER BY ts,id", token).map(row => JSON.parse(row.body)); }
