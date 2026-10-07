import test from "node:test";
import assert from "node:assert/strict";
import { deliverNotification, requireNotificationTargets } from "../../src/notifications.js";

const event = { kind: "vault.decryption", id: crypto.randomUUID(), outcome: "decrypted",
  name: "SYNTHETIC_PRIVATE_NAME", location: "SYNTHETIC_PRIVATE_LOCATION", token: "SYNTHETIC_PRIVATE_TOKEN",
  ua: "SYNTHETIC_PRIVATE_UA", referer: "SYNTHETIC_PRIVATE_REFERER" };
for (const env of [
  { MAIL_FROM: "sender@example.test", MAIL_TO: "recipient@example.test", MAILCHANNELS_API_KEY: "synthetic" },
  { SLACK_WEBHOOK_URL: "https://hooks.example.test/fixture" },
  { DISCORD_WEBHOOK_URL: "https://hooks.example.test/fixture" },
  { WEBHOOK_URL: "https://hooks.example.test/fixture" },
]) test(`vault notifications omit private event metadata: ${Object.keys(env)[0]}`, async () => {
  const original = globalThis.fetch; let body;
  globalThis.fetch = async (_url, options) => { body = options.body; return new Response(null, { status: 202 }); };
  try {
    const [target] = await requireNotificationTargets(env);
    assert.equal((await deliverNotification(env, target, event, crypto.randomUUID())).ok, true);
    assert.ok(body.includes(event.id)); assert.ok(!body.includes("SYNTHETIC_PRIVATE"));
  } finally { globalThis.fetch = original; }
});
