import test from "node:test";
import assert from "node:assert/strict";
import { assessDenial, probe } from "../scripts/probe-live-denials.mjs";

const origin = "https://vault.example.test", empty = new Uint8Array();
test("live probe does not mistake outages, exposed PDFs or ordinary redirects for denial", () => {
  assert.equal(assessDenial(new Response(null, { status: 503 }), empty, origin), "service_unavailable_not_verified");
  assert.equal(assessDenial(new Response(null, { status: 403, headers: { "content-type": "application/pdf" } }), empty, origin), "content_exposed");
  assert.equal(assessDenial(new Response(null, { status: 403 }), new TextEncoder().encode("%PDF-1.7"), origin), "content_exposed");
  assert.equal(assessDenial(new Response(null, { status: 302, headers: { location: "https://example.invalid/" } }), empty, origin), "unexpected_redirect");
  assert.equal(assessDenial(new Response(null, { status: 200 }), empty, origin), "unexpected_response");
});
test("live probe reports Access interception separately without following redirects", async () => {
  let calls = 0;
  const report = await probe(origin, crypto.randomUUID(), async (url, init) => {
    calls++; assert.equal(new URL(url).origin, origin); assert.equal(init.redirect, "manual");
    return new Response(null, { status: 302, headers: { location: "https://team.cloudflareaccess.com/cdn-cgi/access/login?opaque=not-recorded" } });
  });
  assert.equal(calls, 6); assert.equal(report.status, "denial_probes_passed_only");
  assert.equal(report.authorizedViewingVerified, false); assert.equal(report.notificationReceiptVerified, false);
  assert.ok(!JSON.stringify(report).includes("opaque="));
});
test("one failed probe prevents an overall passing result", async () => {
  let calls = 0;
  const report = await probe(origin, crypto.randomUUID(), async () => new Response(null, { status: ++calls === 2 ? 503 : 401 }));
  assert.equal(report.status, "failed");
});
