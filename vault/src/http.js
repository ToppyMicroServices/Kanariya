export const ACCESS_ROUTE = /^\/v1\/documents\/([0-9a-f-]{36})\/(open|revoke|status|retry-notifications)$/;
export const PASSWORD_ROUTE = /^\/p\/([0-9a-f-]{36})\/(open|session|status)$/;
export const HEADERS = {
  'cache-control': 'private, no-store, max-age=0', 'cdn-cache-control': 'no-store',
  'cloudflare-cdn-cache-control': 'no-store', 'surrogate-control': 'no-store', pragma: 'no-cache', expires: '0',
  'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff', 'x-frame-options': 'SAMEORIGIN',
  'cross-origin-resource-policy': 'same-origin',
  'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; worker-src 'self'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'",
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
};
export function json(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), { status, headers: { ...HEADERS, 'content-type': 'application/json', ...headers } });
}
export class Denied extends Error {
  constructor(status = 403, code = 'not_allowed') { super(code); this.status = status; this.code = code; }
}
export function failure(error) {
  return error instanceof Denied ? json({ error: error.code }, error.status) : json({ error: 'unavailable' }, 503);
}
export function origin(env) {
  const url = new URL(env.PUBLIC_ORIGIN);
  if (url.protocol !== 'https:' || url.origin !== env.PUBLIC_ORIGIN || url.hostname.endsWith('.invalid')) throw new Error('configuration');
  return url.origin;
}
export function dummyPin(env) {
  if (typeof env.DUMMY_DOCUMENT_ID !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(env.DUMMY_DOCUMENT_ID) ||
      typeof env.DUMMY_RECORD_SHA256 !== 'string' || !/^[0-9a-f]{64}$/.test(env.DUMMY_RECORD_SHA256)) throw new Error('configuration');
  return { id: env.DUMMY_DOCUMENT_ID, digest: env.DUMMY_RECORD_SHA256 };
}
export function passwordEnabled(env) {
  if (env.PASSWORD_READER_ENABLED !== '1') throw new Denied();
}

// Materialize small public request bodies before entering the per-document state
// queue. An unauthenticated slow upload must never hold owner revoke/status.
export async function requestBody(request, timeoutMs = 5000) {
  if (!request.body || ['GET', 'HEAD'].includes(request.method)) return request;
  const declared = request.headers.get('content-length');
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > 2048)) throw new Denied(400, 'invalid_request');
  const reader = request.body.getReader(), chunks = [];
  let length = 0, timer;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Denied(408, 'request_timeout')), timeoutMs);
  });
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), deadline]);
      if (done) break;
      length += value.byteLength;
      if (length > 2048) throw new Denied(400, 'invalid_request');
      chunks.push(value);
    }
  } catch (error) {
    // Cancellation itself may wait for an uncooperative source; never await it.
    void reader.cancel().catch(() => {});
    throw error;
  } finally { clearTimeout(timer); reader.releaseLock(); }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
  return new Request(request, { body });
}
