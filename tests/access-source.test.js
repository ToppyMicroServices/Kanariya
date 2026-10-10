import { expect, it } from 'vitest';
import { accessSource, openSource, sealSource } from '../src/access-source.js';

const env = { CANARY_SOURCE_KEY: btoa('s'.repeat(32)) };
const event = { id: '1'.repeat(32), token: 'kr_' + 'a'.repeat(64), documentId: 'f025a92a-082d-4eaf-9b78-9ed396b9bb85', ts: new Date().toISOString() };
const source = { ip: '198.51.100.9', country: 'JP', asn: 64512, network: 'Synthetic Network', refererHost: 'source.example.test' };
function request(headers = {}, cf = {}) {
  const value = new Request('https://fixture.test', { headers });
  Object.defineProperty(value, 'cf', { value: cf }); return value;
}

it('captures only edge IP and bounded network/referring host when opted in', () => {
  const req = request({ 'cf-connecting-ip': source.ip, referer: 'https://source.example.test:8443/private?q=secret#private' }, { country: 'JP', asn: 64512, asOrganization: source.network });
  expect(accessSource(req, env)).toEqual(source);
  expect(accessSource(req, {})).toBeNull();
  for (const value of ['', '198.51.100.999', '127.1', '0x7f.0.0.1', '019.0.0.1', 'fe80::1%en0', '198.51.100.1,192.0.2.1']) {
    expect(accessSource(request({ 'cf-connecting-ip': value, 'x-forwarded-for': source.ip }), env)).toBeNull();
  }
  expect(accessSource(request({ 'x-forwarded-for': source.ip }), env)).toBeNull();
  expect(accessSource(request({ 'cf-connecting-ip': '2001:0db8:0:0::1' }), env).ip).toBe('2001:db8::1');
  expect(accessSource(request({ 'cf-connecting-ip': '240.1.2.3', 'cf-connecting-ipv6': '2001:db8::2' }), env).ip).toBe('2001:db8::2');
  expect(accessSource(request({ 'cf-connecting-ip': source.ip, 'cf-connecting-ipv6': '2001:db8::2' }), env).ip).toBe(source.ip);
});

it('never includes credentials, paths, query, full headers or unbounded network fields', () => {
  const value = accessSource(request({ 'cf-connecting-ip': source.ip, referer: 'https://user:password@example.test/private' }, { country: 'ZZZ', asn: -1, asOrganization: 'Synthetic\n\u0085' + 'x'.repeat(200) }), env);
  expect(value.refererHost).toBe(''); expect(value.country).toBe(''); expect(value.asn).toBeNull();
  expect(value.network).toHaveLength(160); expect(value.network).not.toContain('\n');
  expect(value.network).not.toContain('\u0085');
});

it('uses fresh AES-GCM ciphertext bound to the exact event and separate secret', async () => {
  const first = await sealSource(env, source, event), second = await sealSource(env, source, event);
  expect(first).not.toEqual(second); expect(JSON.stringify(first)).not.toContain(source.ip);
  expect(await openSource(env, first, event)).toEqual(source);
  for (const name of ['id', 'token', 'documentId', 'ts']) expect(await openSource(env, first, { ...event, [name]: 'different' })).toBeNull();
  expect(await openSource({ CANARY_SOURCE_KEY: btoa('t'.repeat(32)) }, first, event)).toBeNull();
  expect(await openSource(env, { ...first, data: (first.data[0] === 'a' ? 'b' : 'a') + first.data.slice(1) }, event)).toBeNull();
  expect(await openSource(env, { ...first, extra: 'untrusted' }, event)).toBeNull();
});

it('has no plaintext fallback for missing/malformed keys or invalid sources', async () => {
  for (const key of [undefined, 'test-key', btoa('s'.repeat(31)), btoa('s'.repeat(33))]) expect(await sealSource({ CANARY_SOURCE_KEY: key }, source, event)).toBeNull();
  for (const invalid of [{ ...source, extra: 'secret' }, { ...source, ip: '' }, { ...source, ip: 'attacker' }, { ...source, refererHost: 'example.test/private' }, { ...source, network: 'x\n' }, { ...source, network: 'x\u0085' }]) expect(await sealSource(env, invalid, event)).toBeNull();
  expect(await openSource(env, null, event)).toBeNull();
  expect(await openSource(env, { v: 1, iv: '0'.repeat(24), data: '0'.repeat(4098) }, event)).toBeNull();
});
