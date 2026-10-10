import { identity } from './auth.js';
import { dummyPin, origin, Denied, json, requestBody } from './http.js';
import { boundedBody, parseJSON } from './crypto.js';

export const CANARY_ORIGIN = 'https://kanariya.toppymicros.com';
const TOKEN = /^kr_[a-f0-9]{64}$/;
const EVENT = /^[a-f0-9]{32}$/;
const time = value => Number.isSafeInteger(value) && value > 0 && value <= 8640000000000000;
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));

function statusValue(value, id) {
  if (!exact(value, ['documentId', 'canary']) || value.documentId !== id) throw new Error('canary_response');
  const item = value.canary;
  if (item === null) return { configured: true, documentId: id, canary: null };
  if (!exact(item, ['token', 'state', 'expiresAt', 'hitCount', 'lastSeenAt']) || !TOKEN.test(item.token) ||
      !['active', 'expired', 'revoked'].includes(item.state) || !time(item.expiresAt) ||
      !Number.isSafeInteger(item.hitCount) || item.hitCount < 0 || !(item.lastSeenAt === null || time(item.lastSeenAt))) throw new Error('canary_response');
  return { configured: true, documentId: id, canary: { ...item, url: `${CANARY_ORIGIN}/canary/${item.token}` } };
}
function eventValue(value, id) {
  if (!exact(value, ['documentId', 'events']) || value.documentId !== id || !Array.isArray(value.events) || value.events.length > 50) throw new Error('canary_response');
  for (const event of value.events) {
    if (!exact(event, ['id', 'at', 'outcome', 'notifications']) || !EVENT.test(event.id) || !time(event.at) ||
        event.outcome !== 'url_requested' || !Array.isArray(event.notifications) || event.notifications.length > 4 ||
        event.notifications.some(n => !exact(n, ['type', 'state']) || !['email', 'webhook', 'slack', 'discord'].includes(n.type) ||
          !['pending', 'retrying', 'accepted', 'failed'].includes(n.state))) throw new Error('canary_response');
  }
  return { configured: true, documentId: id, events: value.events };
}
async function rpc(binding, method, args) {
  let timer;
  try {
    const result = await Promise.race([binding[method](...args), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('canary_timeout_unknown')), 5000);
    })]);
    if (!exact(result, ['status', 'value']) || ![200, 201, 400, 409, 503].includes(result.status)) throw new Error('canary_response');
    if (result.status >= 400) {
      if (!exact(result.value, ['error']) || !['invalid_request', 'canary_exists', 'canary_capacity', 'canary_storage_unavailable'].includes(result.value.error)) throw new Error('canary_response');
      throw new Denied(result.status, result.value.error);
    }
    return { value: result.value, status: result.status };
  } finally { clearTimeout(timer); }
}

// An absent binding is an inactive feature. No bearer key or alternate network
// path is used. The caller resolves the document deadline only for creation.
export async function handleCanary(request, env, { id, getExpiresAt }) {
  const url = new URL(request.url), logs = url.pathname === `/v1/documents/${id}/canary-logs`;
  if (id !== dummyPin(env).id || url.origin !== origin(env) || url.search ||
      (!logs && url.pathname !== `/v1/documents/${id}/canary`)) throw new Denied();
  let subject;
  try { subject = await identity(request, env); } catch { throw new Denied(401, 'unauthenticated'); }
  if (typeof env.VAULT_OWNER_SUB !== 'string' || !env.VAULT_OWNER_SUB || env.VAULT_OWNER_SUB.length > 256) throw new Error('configuration');
  if (subject !== env.VAULT_OWNER_SUB) throw new Denied();
  if (!(logs ? ['GET'] : ['GET', 'POST']).includes(request.method)) throw new Denied(405, 'method_not_allowed');
  if (request.method === 'POST' && (request.headers.get('origin') !== url.origin || request.headers.get('content-type') !== 'application/json' ||
      ['cross-site', 'same-site'].includes(request.headers.get('sec-fetch-site')))) throw new Denied();
  const binding = env.CANARY_ADMIN;
  if (!binding || ['status', 'create', 'revoke', 'events'].some(method => typeof binding[method] !== 'function')) {
    if (request.method !== 'GET') throw new Denied(503, 'canary_not_configured');
    return json(logs ? { configured: false, documentId: id, events: [] } : { configured: false, documentId: id, canary: null });
  }
  if (request.method === 'GET') {
    const result = await rpc(binding, logs ? 'events' : 'status', [id]);
    return json(logs ? eventValue(result.value, id) : statusValue(result.value, id));
  }
  const ready = await requestBody(request, 5000, 128);
  let input;
  try { input = parseJSON(await boundedBody(ready, 128)); } catch { throw new Denied(400, 'invalid_request'); }
  if (!exact(input, ['action']) || !['create', 'revoke'].includes(input.action)) throw new Denied(400, 'invalid_request');
  const args = [id];
  if (input.action === 'create') {
    const expiresAt = await getExpiresAt();
    if (!time(expiresAt) || expiresAt <= Date.now()) throw new Denied(403, 'not_allowed');
    args.push(expiresAt);
  }
  const result = await rpc(binding, input.action, args);
  return json(statusValue(result.value, id), result.status);
}
