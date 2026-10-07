import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import { deliverNotification, notificationTargets, requireNotificationTargets } from "../src/notifications.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const event = {
  id: "event-123", ts: "2026-09-20T00:00:00.000Z", token: "token-123", src: "finance-note",
  name: "Expense notes", location: "Team folder", test: false, ipHash: "hashed-ip",
  country: "JP", asn: 64512, ua: "UnitTest", referer: "https://example.test/note",
};
const emailEnv = {
  MAIL_FROM: "canary@example.test", MAIL_TO: "one@example.test, two@example.test",
  MAILCHANNELS_API_KEY: "fixture-api-key",
};
const cloudflareEmailEnv = {
  MAIL_PROVIDER: "cloudflare", MAIL_FROM: "canary@example.test", MAIL_TO: "one@example.test, two@example.test",
};

async function send(env, item = event) {
  const [target] = await notificationTargets(env);
  return await deliverNotification(env, target, item, "delivery-456");
}

describe("notification targets", () => {
  it("returns only opaque destination identities and includes partial email configuration", async () => {
    const env = {
      WEBHOOK_URL: "https://hooks.example.test/secret-path",
      SLACK_WEBHOOK_URL: "https://hooks.slack.test/secret-path",
      DISCORD_WEBHOOK_URL: "https://discord.test/secret-path",
      MAIL_FROM: "canary@example.test",
    };
    const targets = await notificationTargets(env);
    expect(targets.map((target) => target.type)).toEqual(["webhook", "slack", "discord", "email"]);
    for (const target of targets) {
      expect(Object.keys(target).sort()).toEqual(["fingerprint", "type"]);
      expect(target.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    }
    expect(JSON.stringify(targets)).not.toContain("secret-path");
    expect(await notificationTargets({})).toEqual([]);
    expect(await notificationTargets({ MAIL_TO: "" })).toHaveLength(1);
    expect(await notificationTargets({ MAIL_PROVIDER: "cloudflare" })).toHaveLength(1);
  });

  it("binds identities to destination and channel but permits API key rotation", async () => {
    const [original] = await notificationTargets(emailEnv);
    expect(await notificationTargets({ ...emailEnv, MAILCHANNELS_API_KEY: "rotated-key" })).toEqual([original]);
    expect(await notificationTargets({ ...emailEnv, MAIL_TO: "someone-else@example.test" })).not.toEqual([original]);
    expect(await notificationTargets({ ...emailEnv, MAIL_FROM: "other@example.test" })).not.toEqual([original]);
    const [webhook, slack] = await notificationTargets({ WEBHOOK_URL: "https://example.test/hook", SLACK_WEBHOOK_URL: "https://example.test/hook" });
    expect(webhook.fingerprint).not.toBe(slack.fingerprint);
  });

  it("preserves existing MailChannels identities and binds native email to its provider", async () => {
    const [legacy] = await notificationTargets(emailEnv);
    expect(await notificationTargets({ ...emailEnv, MAIL_PROVIDER: "mailchannels" })).toEqual([legacy]);
    const [native] = await notificationTargets(cloudflareEmailEnv);
    expect(native.fingerprint).not.toBe(legacy.fingerprint);
    expect(await notificationTargets({ ...cloudflareEmailEnv, MAILCHANNELS_API_KEY: "irrelevant-rotation" })).toEqual([native]);
    expect(await notificationTargets({ ...cloudflareEmailEnv, MAIL_PROVIDER: "unsupported" })).not.toEqual([native]);
    expect(await notificationTargets({ ...cloudflareEmailEnv, MAIL_TO: "other@example.test" })).not.toEqual([native]);
  });
});

describe("notification delivery", () => {
  let fetchSpy;
  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));
  });
  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("keeps the generic webhook envelope and stable delivery ID", async () => {
    const result = await send({ WEBHOOK_URL: "https://hooks.example.test/secret-path" });
    const [url, options] = fetchSpy.mock.calls[0];
    expect(url).toBe("https://hooks.example.test/secret-path");
    expect(JSON.parse(options.body)).toEqual({ kind: "kanariya.canary", event, deliveryId: "delivery-456" });
    expect(options).toMatchObject({ method: "POST", redirect: "manual", headers: { "content-type": "application/json" } });
    expect(options.signal).toBeInstanceOf(AbortSignal);
    expect(result).toEqual({ ok: true, retryable: false, httpStatus: 204, error: null, retryAfterMs: null });
  });

  it("renders Slack metadata as plain text and keeps the fallback safe", async () => {
    await send({ SLACK_WEBHOOK_URL: "https://hooks.slack.test/services/fixture" }, {
      ...event, test: true, src: "<!channel> <@U123> @everyone", ua: "line1\nforged: line2",
    });
    const payload = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(payload).toMatchObject({ mrkdwn: false, parse: "none", link_names: false, unfurl_links: false, unfurl_media: false });
    expect(payload.text).toContain("TEST");
    expect(payload.text).toContain(event.id);
    expect(payload.text).not.toContain("<!channel>");
    expect(payload.blocks[0].text.type).toBe("plain_text");
    expect(payload.blocks[0].text.text).toContain("<!channel> <@U123> @everyone");
    expect(payload.blocks[0].text.text).toContain("ua: line1 forged: line2");
    expect(payload.blocks[0].text.text).toContain("delivery ID: delivery-456");
  });

  it("uses Discord confirmation, disables mentions, and bounds long content", async () => {
    await send({ DISCORD_WEBHOOK_URL: "https://discord.test/api/webhooks/fixture?wait=false&thread_id=123" }, {
      ...event, name: "@everyone", location: "long".repeat(300), src: "x".repeat(1000), referer: "y".repeat(1000), ua: "z".repeat(1000),
    });
    const [url, options] = fetchSpy.mock.calls[0];
    const payload = JSON.parse(options.body);
    expect(new URL(url).searchParams.get("wait")).toBe("true");
    expect(new URL(url).searchParams.get("thread_id")).toBe("123");
    expect(payload.allowed_mentions).toEqual({ parse: [] });
    expect(payload.content.length).toBeLessThanOrEqual(2000);
    expect(payload.content).toContain("DETECTION");
    expect(payload.content).toContain(event.id);
    expect(payload.content).toContain("@everyone");
  });

  it("authenticates MailChannels and keeps existing email fields", async () => {
    fetchSpy.mockResolvedValue(new Response(null, { status: 202 }));
    await send({ ...emailEnv, MAIL_FROM_NAME: "Canary", MAIL_SUBJECT_PREFIX: "Access alert" }, { ...event, test: true });
    const [url, options] = fetchSpy.mock.calls[0];
    expect(url).toBe("https://api.mailchannels.net/tx/v1/send");
    expect(options.headers["X-Api-Key"]).toBe("fixture-api-key");
    const payload = JSON.parse(options.body);
    expect(payload.personalizations).toEqual([{ to: [{ email: "one@example.test" }, { email: "two@example.test" }] }]);
    expect(payload.from).toEqual({ email: "canary@example.test", name: "Canary" });
    expect(payload.subject).toBe("Access alert [TEST]: token-123");
    expect(payload.content[0]).toMatchObject({ type: "text/plain" });
    expect(payload.content[0].value).toContain("event ID: event-123");
    expect(payload.content[0].value).toContain("name: Expense notes");
    expect(payload.content[0].value).toContain("location: Team folder");
    expect(options.body).not.toContain("fixture-api-key");
  });

  it("sends native structured plain-text email without an API key or HTTP request", async () => {
    vi.useFakeTimers();
    const nativeSend = vi.fn().mockResolvedValue({ messageId: "provider-private-message-id" });
    const env = { ...cloudflareEmailEnv, MAIL_FROM_NAME: "Canary", MAIL_SUBJECT_PREFIX: "Access alert", NOTIFY_EMAIL: { send: nativeSend } };
    const [target] = await requireNotificationTargets(env);
    expect(nativeSend).not.toHaveBeenCalled();
    const result = await deliverNotification(env, target, { ...event, test: true }, "delivery-456");
    expect(nativeSend).toHaveBeenCalledTimes(1);
    expect(nativeSend.mock.calls[0][0]).toEqual({
      from: { email: "canary@example.test", name: "Canary" },
      to: ["one@example.test", "two@example.test"],
      subject: "Access alert [TEST]: token-123",
      text: expect.stringContaining("delivery ID: delivery-456"),
    });
    expect(result).toEqual({ ok: true, retryable: false, httpStatus: null, error: null, retryAfterMs: null });
    expect(JSON.stringify(result)).not.toContain("provider-private-message-id");
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("minimizes native vault alerts to the opaque event ID and fixed outcome", async () => {
    const nativeSend = vi.fn().mockResolvedValue({ messageId: "fixture-message" });
    await send({ ...cloudflareEmailEnv, NOTIFY_EMAIL: { send: nativeSend } }, {
      ...event, kind: "vault.decryption", outcome: "decrypted", subject: "private-access-subject",
      documentId: "private-document-id", plaintext: "PRIVATE-CV-CONTENT", recipient: "private-applicant@example.test",
    });
    const message = nativeSend.mock.calls[0][0];
    expect(message.subject).toBe("Kanariya protected-document event");
    expect(message.text).toBe("Kanariya protected-document event\nevent ID: event-123\nstatus: decrypted");
    for (const value of [event.token, event.src, event.ipHash, event.referer, "private-access-subject", "private-document-id", "PRIVATE-CV-CONTENT", "private-applicant@example.test"]) {
      expect(JSON.stringify(message)).not.toContain(value);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it.each([
    { NOTIFY_EMAIL: undefined }, { NOTIFY_EMAIL: null }, { NOTIFY_EMAIL: {} }, { NOTIFY_EMAIL: { send: "not-a-function" } },
    { MAIL_FROM: "invalid" }, { MAIL_TO: "recipient@example.test\r\n" },
    { MAIL_PROVIDER: "unsupported" }, { MAIL_PROVIDER: "" }, { MAIL_PROVIDER: null }, { MAIL_PROVIDER: {} },
  ])("rejects invalid native configuration before readiness or delivery %#", async (override) => {
    const nativeSend = vi.fn();
    const env = { ...cloudflareEmailEnv, NOTIFY_EMAIL: { send: nativeSend }, ...override };
    await expect(requireNotificationTargets(env)).rejects.toThrow("configuration_error");
    expect(await send(env)).toEqual({ ok: false, retryable: false, httpStatus: null, error: "configuration_error", retryAfterMs: null });
    expect(nativeSend).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("enforces the documented native recipient limit before sending", async () => {
    const nativeSend = vi.fn().mockResolvedValue({ messageId: "fixture-message" });
    const recipients = Array.from({ length: 51 }, (_, index) => `recipient-${index}@example.test`);
    const env = { ...cloudflareEmailEnv, MAIL_TO: recipients.join(","), NOTIFY_EMAIL: { send: nativeSend } };
    await expect(requireNotificationTargets(env)).rejects.toThrow("configuration_error");
    expect((await send(env)).error).toBe("configuration_error");
    expect(nativeSend).not.toHaveBeenCalled();
    expect((await send({ ...env, MAIL_TO: recipients.slice(0, 50).join(",") })).ok).toBe(true);
    expect(nativeSend.mock.calls[0][0].to).toHaveLength(50);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("does not let a valid webhook hide an incomplete native email target", async () => {
    const nativeSend = vi.fn();
    await expect(requireNotificationTargets({
      WEBHOOK_URL: "https://hooks.example.test/fixture", MAIL_PROVIDER: "cloudflare", NOTIFY_EMAIL: { send: nativeSend },
    })).rejects.toThrow("configuration_error");
    expect(nativeSend).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("never moves queued email between providers automatically", async () => {
    const nativeSend = vi.fn();
    const nativeEnv = { ...cloudflareEmailEnv, NOTIFY_EMAIL: { send: nativeSend } };
    const [legacyTarget] = await notificationTargets(emailEnv);
    const [nativeTarget] = await notificationTargets(nativeEnv);
    for (const [env, target] of [[nativeEnv, legacyTarget], [emailEnv, nativeTarget]]) {
      expect(await deliverNotification(env, target, event, "delivery-456")).toMatchObject({ ok: false, retryable: false, error: "configuration_changed" });
    }
    expect(nativeSend).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it.each([
    ["E_RATE_LIMIT_EXCEEDED", "email_rate_limit", true],
    ["E_DAILY_LIMIT_EXCEEDED", "email_rate_limit", true],
    ["E_INTERNAL_SERVER_ERROR", "email_provider_unavailable", true],
    ["E_DELIVERY_FAILED", "email_delivery_failed", false],
    ["E_SENDER_NOT_VERIFIED", "email_provider_error", false],
    ["E_RECIPIENT_NOT_ALLOWED", "email_provider_error", false],
    ["provider-private-error-code", "email_provider_error", false],
  ])("classifies native %s using fixed metadata only", async (code, expected, retryable) => {
    const nativeSend = vi.fn().mockRejectedValue(Object.assign(new Error("private-recipient@example.test provider-private-secret"), { code }));
    const result = await send({ ...cloudflareEmailEnv, NOTIFY_EMAIL: { send: nativeSend } });
    expect(result).toEqual({ ok: false, retryable, httpStatus: null, error: expected, retryAfterMs: null });
    expect(JSON.stringify(result)).not.toContain("private");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it.each([undefined, null, {}, { messageId: "" }, { messageId: " " }, { messageId: 123 }, { status: "sent" }])("does not accept an undocumented native result %#", async (response) => {
    const nativeSend = vi.fn().mockResolvedValue(response);
    expect(await send({ ...cloudflareEmailEnv, NOTIFY_EMAIL: { send: nativeSend } })).toEqual({ ok: false, retryable: false, httpStatus: null, error: "email_response_unknown", retryAfterMs: null });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it.each(["resolve", "reject"])("bounds native wait and handles late %s without automatic retry", async (finish) => {
    let started, resolveSend, rejectSend;
    const requestStarted = new Promise((resolve) => { started = resolve; });
    const nativeSend = vi.fn(() => new Promise((resolve, reject) => {
      resolveSend = resolve; rejectSend = reject; started();
    }));
    const env = { ...cloudflareEmailEnv, NOTIFY_EMAIL: { send: nativeSend } };
    const [target] = await notificationTargets(env);
    vi.useFakeTimers();
    const pending = deliverNotification(env, target, event, "delivery-456");
    await requestStarted;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(await pending).toEqual({ ok: false, retryable: false, httpStatus: null, error: "email_timeout_unknown", retryAfterMs: null });
    if (finish === "resolve") resolveSend({ messageId: "late-private-id" });
    else rejectSend(new Error("late-private-error"));
    await Promise.resolve();
    expect(nativeSend).toHaveBeenCalledTimes(1);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([
    { MAIL_FROM: "from@example.test", MAIL_TO: "to@example.test" },
    { MAIL_FROM: "from@example.test", MAILCHANNELS_API_KEY: "key" },
    { MAIL_TO: "to@example.test", MAILCHANNELS_API_KEY: "key" },
    { ...emailEnv, MAIL_TO: " , " },
    { ...emailEnv, MAILCHANNELS_API_KEY: "bad\nkey" },
  ])("fails incomplete email configuration without sending %#", async (env) => {
    expect(await send(env)).toEqual({ ok: false, retryable: false, httpStatus: null, error: "configuration_error", retryAfterMs: null });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it.each([
    "missing-at", "@example.test", "sender@", "sender@@example.test", "sender @example.test",
    "Sender <sender@example.test>", "sender(comment)@example.test", "sender;other@example.test",
    "sender\u0000@example.test", "sender@example.test\n",
  ])("rejects a malformed email sender before readiness or delivery %#", async (from) => {
    const env = { ...emailEnv, MAIL_FROM: from };
    await expect(requireNotificationTargets(env)).rejects.toThrow("configuration_error");
    expect(await send(env)).toEqual({ ok: false, retryable: false, httpStatus: null, error: "configuration_error", retryAfterMs: null });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it.each([
    "missing-at", "@example.test", "recipient@", "recipient@@example.test", "bad recipient@example.test",
    "Recipient <recipient@example.test>", "recipient\u007f@example.test", "recipient@example.test\r\n",
  ])("rejects a malformed recipient mixed with valid recipients before readiness or delivery %#", async (to) => {
    const env = { ...emailEnv, MAIL_TO: `one@example.test, ${to}, two@example.test` };
    await expect(requireNotificationTargets(env)).rejects.toThrow("configuration_error");
    expect(await send(env)).toEqual({ ok: false, retryable: false, httpStatus: null, error: "configuration_error", retryAfterMs: null });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("accepts ordinary bare email formats with plus tags and comma spacing", async () => {
    const env = { ...emailEnv, MAIL_FROM: "alerts+vault@example.test", MAIL_TO: "first.last+vault@example.test, other_name@example.test" };
    const [target] = await requireNotificationTargets(env);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect((await deliverNotification(env, target, event, "delivery-456")).ok).toBe(true);
    const payload = JSON.parse(fetchSpy.mock.calls[0][1].body);
    expect(payload.from.email).toBe(env.MAIL_FROM);
    expect(payload.personalizations[0].to).toEqual([{ email: "first.last+vault@example.test" }, { email: "other_name@example.test" }]);
  });

  it.each(["http://hooks.example.test/path", "https://user:secret@hooks.example.test/path", "not-a-url", ""])("rejects unsafe or invalid webhook destination %#", async (url) => {
    expect(await send({ WEBHOOK_URL: url })).toMatchObject({ ok: false, retryable: false, error: "configuration_error" });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("does not send an old event to a removed or changed destination", async () => {
    const [target] = await notificationTargets({ WEBHOOK_URL: "https://example.test/old" });
    for (const env of [{}, { WEBHOOK_URL: "https://example.test/new" }]) {
      expect(await deliverNotification(env, target, event, "delivery-456")).toMatchObject({ ok: false, retryable: false, error: "configuration_changed" });
    }
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("uses the rotated email API key with the saved destination identity", async () => {
    const [target] = await notificationTargets(emailEnv);
    await deliverNotification({ ...emailEnv, MAILCHANNELS_API_KEY: "rotated" }, target, event, "delivery-456");
    expect(fetchSpy.mock.calls[0][1].headers["X-Api-Key"]).toBe("rotated");
  });

  it.each([
    [200, true, false], [202, true, false], [301, false, false], [400, false, false],
    [401, false, false], [403, false, false], [404, false, false], [408, false, true],
    [429, false, true], [500, false, true], [503, false, true],
  ])("classifies HTTP %s without reading provider bodies", async (status, ok, retryable) => {
    const response = new Response("secret echoed by provider", { status });
    const textSpy = vi.spyOn(response, "text");
    const jsonSpy = vi.spyOn(response, "json");
    fetchSpy.mockResolvedValue(response);
    const result = await send({ WEBHOOK_URL: "https://example.test/secret" });
    expect(result).toMatchObject({ ok, retryable, httpStatus: status });
    expect(JSON.stringify(result)).not.toContain("secret");
    expect(textSpy).not.toHaveBeenCalled();
    expect(jsonSpy).not.toHaveBeenCalled();
  });

  it.each([["90", 90_000], ["1.5", 1500], ["99999999", 86_400_000], ["invalid", null], ["-5", null]])("handles Retry-After %s", async (header, expected) => {
    fetchSpy.mockResolvedValue(new Response(null, { status: 429, headers: { "retry-after": header } }));
    expect((await send({ WEBHOOK_URL: "https://example.test/hook" })).retryAfterMs).toBe(expected);
  });

  it("handles Retry-After HTTP dates and past dates", async () => {
    vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-09-20T00:00:00Z"));
    fetchSpy.mockResolvedValue(new Response(null, { status: 503, headers: { "retry-after": "Sun, 20 Sep 2026 00:01:00 GMT" } }));
    expect((await send({ WEBHOOK_URL: "https://example.test/hook" })).retryAfterMs).toBe(60_000);
    fetchSpy.mockResolvedValue(new Response(null, { status: 503, headers: { "retry-after": "Sun, 20 Sep 2026 00:00:00 GMT" } }));
    expect((await send({ WEBHOOK_URL: "https://example.test/hook" })).retryAfterMs).toBe(0);
  });

  it("does not return secrets in network errors", async () => {
    fetchSpy.mockRejectedValue(new Error("failed https://example.test/secret-url api-key-secret"));
    expect(await send({ WEBHOOK_URL: "https://example.test/secret-url" })).toEqual({ ok: false, retryable: true, httpStatus: null, error: "network_error", retryAfterMs: null });
  });

  it("treats a redirect as terminal and does not follow its Location", async () => {
    const response = new Response("provider response", {
      status: 307, headers: { location: "https://different.example.test/receive" },
    });
    const cancel = vi.spyOn(response.body, "cancel");
    fetchSpy.mockResolvedValue(response);
    expect(await send(emailEnv)).toEqual({ ok: false, retryable: false, httpStatus: 307, error: "http_error", retryAfterMs: null });
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.mock.calls[0][0]).toBe("https://api.mailchannels.net/tx/v1/send");
    expect(fetchSpy.mock.calls[0][1].redirect).toBe("manual");
    expect(cancel).toHaveBeenCalledTimes(1);
  });

  it("aborts a pending request after ten seconds and clears its timer", async () => {
    const [target] = await notificationTargets({ WEBHOOK_URL: "https://example.test/hook" });
    let started;
    const requestStarted = new Promise((resolve) => { started = resolve; });
    fetchSpy.mockImplementation((_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener("abort", () => reject(new Error("secret timeout URL")));
      started();
    }));
    vi.useFakeTimers();
    const pending = deliverNotification({ WEBHOOK_URL: "https://example.test/hook" }, target, event, "delivery-456");
    await requestStarted;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(await pending).toEqual({ ok: false, retryable: true, httpStatus: null, error: "timeout", retryAfterMs: null });
    expect(fetchSpy.mock.calls[0][1].signal.aborted).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });
});
