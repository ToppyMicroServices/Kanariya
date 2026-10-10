import { createHmac } from 'node:crypto';
import { isIP } from 'node:net';
import { unb64, importKey, openJSON, sealJSON } from './crypto.js';
import { Denied } from './http.js';
import { ATTEMPT_WINDOW_MS, MAX_ATTEMPTS } from './password.js';

// Over-budget traffic stops before R2 or the document queue. The separate
// admission state stores source HMACs only inside ciphertext.
export class PasswordAdmission {
  constructor(storage, env, context) {
    this.storage = storage; this.env = env; this.context = `admission:${context}`;
    this.tail = Promise.resolve(); this.cached = null;
  }
  source(request) {
    const ip = request.headers.get('cf-connecting-ip');
    if (!ip || !isIP(ip)) throw new Denied(503, 'source_unavailable');
    const normalized = ip.includes(':') ? new URL(`http://[${ip}]`).hostname : ip;
    const raw = unb64(this.env.VAULT_AUDIT_KEY, 32);
    if (raw.length !== 32) throw new Error('invalid_key');
    try { return createHmac('sha256', raw).update(`${this.context}\0${normalized}`).digest('hex'); }
    finally { raw.fill(0); }
  }
  take(source, kind) {
    const next = this.tail.then(() => this.reserve(source, kind));
    this.tail = next.catch(() => {}); return next;
  }
  async reserve(source, kind) {
    const now = Date.now();
    const max = kind === 'login' ? MAX_ATTEMPTS : 30, totalMax = kind === 'login' ? 120 : 600;
    if (!this.cached) {
      const key = await importKey(this.env.VAULT_AUDIT_KEY);
      const box = await this.storage.get('encrypted-admission');
      const state = box ? await openJSON(box, key, this.context) : { rates: [] };
      if (!Array.isArray(state.rates)) throw new Error('invalid_admission');
      this.cached = state;
    }
    const rates = this.cached.rates.filter(r => r.start + (r.kind === 'login' ? ATTEMPT_WINDOW_MS : 60000) > now);
    const rate = rates.find(r => r.source === source && r.kind === kind);
    if ((rate?.count || 0) >= max || rates.filter(r => r.kind === kind).reduce((n, r) => n + r.count, 0) >= totalMax) {
      throw new Denied(429, 'rate_limited');
    }
    const updated = structuredClone(rates);
    const entry = updated.find(r => r.source === source && r.kind === kind);
    if (entry) entry.count++; else updated.push({ source, kind, start: now, count: 1 });
    const state = { rates: updated }, key = await importKey(this.env.VAULT_AUDIT_KEY);
    await this.storage.transaction(async tx => { await tx.put('encrypted-admission', await sealJSON(state, key, this.context)); });
    this.cached = state;
  }
}
