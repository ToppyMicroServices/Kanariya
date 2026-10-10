const encoder = new TextEncoder();
const enabled = env => typeof env.CANARY_SOURCE_KEY === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(env.CANARY_SOURCE_KEY);
const controls = /[\u0000-\u001f\u007f-\u009f]/;

function ip(value) {
  if (typeof value !== 'string' || !value || value.length > 45) return '';
  if (/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value) && value.split('.').every(n => Number(n) <= 255)) return value;
  if (!value.includes(':') || !/^[0-9a-f:.]+$/i.test(value)) return '';
  try { return new URL(`http://[${value}]/`).hostname.slice(1, -1); } catch { return ''; }
}

function host(value) {
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password && url.hostname.length <= 253 ? url.hostname : '';
  } catch { return ''; }
}

function valid(value) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === 'asn,country,ip,network,refererHost' && Boolean(value.ip) && ip(value.ip) === value.ip &&
    typeof value.country === 'string' && /^(?:[A-Z]{2})?$/.test(value.country) &&
    (value.asn === null || Number.isSafeInteger(value.asn) && value.asn > 0 && value.asn <= 4294967295) &&
    typeof value.network === 'string' && value.network.length <= 160 && !controls.test(value.network) &&
    typeof value.refererHost === 'string' && value.refererHost.length <= 253 &&
    (!value.refererHost || host(`https://${value.refererHost}/`) === value.refererHost);
}

// Use Cloudflare's edge fields, never the visitor-supplied X-Forwarded-For.
// A reference host is a navigation hint, not the visitor's own domain.
export function accessSource(request, env) {
  if (!enabled(env)) return null;
  let address = ip(request.headers.get('cf-connecting-ip'));
  const ipv6 = ip(request.headers.get('cf-connecting-ipv6'));
  if (/^(24[0-9]|25[0-5])\./.test(address) && ipv6.includes(':')) address = ipv6;
  if (!address) return null;
  const cf = request.cf || {};
  return {
    ip: address,
    country: typeof cf.country === 'string' && /^[A-Z]{2}$/.test(cf.country) ? cf.country : '',
    asn: Number.isSafeInteger(cf.asn) && cf.asn > 0 && cf.asn <= 4294967295 ? cf.asn : null,
    network: String(cf.asOrganization || '').replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').slice(0, 160),
    refererHost: host(request.headers.get('referer')),
  };
}

const hex = bytes => [...bytes].map(n => n.toString(16).padStart(2, '0')).join('');
const bytes = value => Uint8Array.from(value.match(/../g), n => parseInt(n, 16));
const aad = event => encoder.encode(JSON.stringify(['kanariya-access-source-v1', event.id, event.token, event.documentId, event.ts]));
async function key(env) {
  const value = env.CANARY_SOURCE_KEY;
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) throw new Error('source_key_unavailable');
  const raw = atob(value);
  if (raw.length !== 32 || btoa(raw) !== value) throw new Error('source_key_unavailable');
  return crypto.subtle.importKey('raw', Uint8Array.from(raw, c => c.charCodeAt(0)), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function sealSource(env, source, event) {
  if (!enabled(env) || !valid(source)) return null;
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(event) }, await key(env), encoder.encode(JSON.stringify(source)));
    return { v: 1, iv: hex(iv), data: hex(new Uint8Array(data)) };
  } catch { return null; } // Retain the minimal event; never fall back to plaintext.
}

export async function openSource(env, box, event) {
  if (!box || box.v !== 1 || Object.keys(box).sort().join(',') !== 'data,iv,v' ||
      typeof box.iv !== 'string' || !/^[a-f0-9]{24}$/.test(box.iv) || typeof box.data !== 'string' ||
      box.data.length > 4096 || !/^(?:[a-f0-9]{2}){16,}$/.test(box.data)) return null;
  try {
    const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes(box.iv), additionalData: aad(event) }, await key(env), bytes(box.data));
    const source = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    return valid(source) ? source : null;
  } catch { return null; }
}
