import { identity, accessConfiguration } from './auth.js';
import { UUID } from './crypto.js';
import { ACCESS_ROUTE, PASSWORD_ROUTE, HEADERS, json, Denied, failure, origin, dummyPin, passwordEnabled } from './http.js';
import * as viewer from './viewer.js';
import { pdfjsAssets } from './pdfjs-assets.generated.js';
import { brandAsset } from './brand.js';
import * as admin from './admin.js';
import * as registrationPreview from './registration-preview.js';
import { pdfPreparationAssets } from './pdf-preparation-assets.generated.js';
import { handleCanary } from './canary-management.js';
export { VaultDocument } from './document.js';

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      if (url.origin !== origin(env) || url.search) throw new Denied();
      const pin = dummyPin(env);
      const ownerPage = url.pathname === '/v1/admin';
      const ownerAsset = url.pathname === '/v1/admin/assets/admin.js' ? ['js', 'text/javascript; charset=utf-8'] :
        url.pathname === '/v1/admin/assets/management.js' ? ['managementJs', 'text/javascript; charset=utf-8'] :
        url.pathname === '/v1/admin/assets/canary.js' ? ['canaryJs', 'text/javascript; charset=utf-8'] :
        url.pathname === '/v1/admin/assets/admin.css' ? ['css', 'text/css; charset=utf-8'] : null;
      const preparationAsset = Object.hasOwn(pdfPreparationAssets, url.pathname) ? pdfPreparationAssets[url.pathname] :
        url.pathname === '/v1/admin/assets/registration-preview.js' ? { data: registrationPreview.js, mime: 'text/javascript; charset=utf-8' } :
        url.pathname === '/v1/admin/assets/pdf-preparation-worker.js' ? { data: registrationPreview.workerJs, mime: 'text/javascript; charset=utf-8' } : null;
      const management = url.pathname === '/v1/management';
      if (ownerPage || ownerAsset || preparationAsset || management) {
        if (request.method !== 'GET') throw new Denied(405, 'method_not_allowed');
        let subject;
        try { subject = await identity(request, env); } catch { throw new Denied(401, 'unauthenticated'); }
        if (typeof env.VAULT_OWNER_SUB !== 'string' || !env.VAULT_OWNER_SUB || env.VAULT_OWNER_SUB.length > 256) throw new Error('configuration');
        if (subject !== env.VAULT_OWNER_SUB) throw new Denied();
        if (management) return json({ documentId: pin.id });
        const [body, mime] = ownerPage ? [admin.html, 'text/html; charset=utf-8'] : preparationAsset ? [preparationAsset.data, preparationAsset.mime] : [admin[ownerAsset[0]], ownerAsset[1]];
        return new Response(body, { headers: { ...HEADERS, 'content-type': mime } });
      }
      const replacement = /^\/v1\/registrations\/([0-9a-f-]{36})\/replacement$/.exec(url.pathname);
      if (url.pathname === '/v1/registrations' || replacement && UUID.test(replacement[1])) {
        if (!['GET', 'POST'].includes(request.method)) throw new Denied(405, 'method_not_allowed');
        let subject;
        try { subject = await identity(request, env); } catch { throw new Denied(401, 'unauthenticated'); }
        if (typeof env.VAULT_OWNER_SUB !== 'string' || !env.VAULT_OWNER_SUB || env.VAULT_OWNER_SUB.length > 256) throw new Error('configuration');
        if (subject !== env.VAULT_OWNER_SUB) throw new Denied();
        return env.VAULT.get(env.VAULT.idFromName('owner-registration:v1')).fetch(request);
      }
      const canaryMatch = /^\/v1\/documents\/([0-9a-f-]{36})\/(canary|canary-logs)$/.exec(url.pathname);
      if (canaryMatch && UUID.test(canaryMatch[1])) {
        return await handleCanary(request, env, { id: canaryMatch[1], getExpiresAt: async () => {
          const metadataRequest = new Request(`${url.origin}/v1/documents/${canaryMatch[1]}/metadata`, { headers: request.headers });
          const response = await env.VAULT.get(env.VAULT.idFromName(canaryMatch[1])).fetch(metadataRequest);
          if (!response.ok) throw new Denied();
          const metadata = await response.json();
          if (metadata.id !== canaryMatch[1] || metadata.revoked) throw new Denied();
          return metadata.expiresAt;
        } });
      }
      const passwordPath = url.pathname.startsWith('/p/');
      if (passwordPath) { passwordEnabled(env); accessConfiguration(env); }
      const match = (passwordPath ? PASSWORD_ROUTE : ACCESS_ROUTE).exec(url.pathname);
      if (match && UUID.test(match[1])) {
        if (match[1] !== pin.id) throw new Denied();
        return env.VAULT.get(env.VAULT.idFromName(match[1])).fetch(request);
      }
      const page = passwordPath && url.pathname === `/p/${pin.id}`;
      const path = passwordPath && url.pathname.startsWith('/p/assets/') ? url.pathname.slice('/p/assets'.length) : url.pathname;
      const asset = path === '/brand.png' ? brandAsset : Object.hasOwn(pdfjsAssets, path) ? pdfjsAssets[path] : null;
      if (passwordPath) {
        if (!page && (!url.pathname.startsWith('/p/assets/') || (!asset && !['/viewer.js', '/viewer.css'].includes(path)))) throw new Denied();
        if (request.method !== 'GET') throw new Denied(405, 'method_not_allowed');
      } else {
        if (request.method !== 'GET') return json({ error: 'not_found' }, 404);
        if (!asset && !['/', '/viewer.js', '/viewer.css'].includes(path)) return json({ error: 'not_found' }, 404);
        try { await identity(request, env); } catch { return json({ error: 'unauthenticated' }, 401); }
      }
      if (asset) {
        const body = asset.encoding === 'base64' ? Uint8Array.from(atob(asset.data), char => char.charCodeAt(0)) : asset.data;
        return new Response(body, { headers: { ...HEADERS, 'content-type': asset.mime } });
      }
      const [body, mime] = page ? [viewer.passwordHtml, 'text/html; charset=utf-8'] : path === '/' ? [viewer.html, 'text/html; charset=utf-8'] :
        path === '/viewer.js' ? [passwordPath ? viewer.passwordJs : viewer.js, 'text/javascript; charset=utf-8'] : [viewer.css, 'text/css; charset=utf-8'];
      return new Response(body, { headers: { ...HEADERS, 'content-type': mime } });
    } catch (error) { return failure(error); }
  },
};
