import { WorkerEntrypoint } from 'cloudflare:workers';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const methods = new Set(['status', 'create', 'revoke', 'events']);

// This named entrypoint is reachable only through an explicitly configured
// service binding. Public fetch keeps its existing ADMIN_KEY boundary.
export class CanaryManagement extends WorkerEntrypoint {
  async #operation(action, documentId, expiresAt) {
    if (!methods.has(action) || !UUID.test(documentId) || typeof documentId !== 'string' ||
        (action === 'create' && (!Number.isSafeInteger(expiresAt) || expiresAt <= Date.now() || expiresAt > 8640000000000000))) {
      return { status: 400, value: { error: 'invalid_request' } };
    }
    if (!this.env.KANARI_STORE) return { status: 503, value: { error: 'canary_storage_unavailable' } };
    try {
      const response = await this.env.KANARI_STORE.get(this.env.KANARI_STORE.idFromName('kanariya-v1')).fetch(
        new Request(`https://kanariya.internal/internal/vault-canary/${action}`, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ documentId, ...(action === 'create' ? { expiresAt } : {}) }),
        }));
      const bytes = await response.arrayBuffer();
      if (bytes.byteLength > 65536 || !response.headers.get('content-type')?.startsWith('application/json')) throw new Error();
      return { status: response.status, value: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) };
    } catch { return { status: 503, value: { error: 'canary_storage_unavailable' } }; }
  }
  status(documentId) { return this.#operation('status', documentId); }
  create(documentId, expiresAt) { return this.#operation('create', documentId, expiresAt); }
  revoke(documentId) { return this.#operation('revoke', documentId); }
  events(documentId) { return this.#operation('events', documentId); }
}
