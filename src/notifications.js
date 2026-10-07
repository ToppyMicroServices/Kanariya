const WEBHOOK_SETTINGS = [
  ["webhook", "WEBHOOK_URL"],
  ["slack", "SLACK_WEBHOOK_URL"],
  ["discord", "DISCORD_WEBHOOK_URL"],
];
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_RETRY_AFTER_MS = 24 * 60 * 60 * 1000;
const MAILCHANNELS_URL = "https://api.mailchannels.net/tx/v1/send";

function setting(value) {
  return typeof value === "string" ? value.trim() : "";
}

function isPresent(value) {
  return value !== undefined && value !== null;
}

function emailList(value) {
  return setting(value).split(",").map((email) => email.trim()).filter(Boolean);
}

function bareEmail(value) {
  // Catch obvious configuration errors; this does not verify deliverability.
  return /^[^\s@\u0000-\u001f\u007f<>()\[\]:;,\\"]+@[^\s@\u0000-\u001f\u007f<>()\[\]:;,\\"]+$/.test(value);
}

function mailProvider(env) {
  return env.MAIL_PROVIDER === undefined ? "mailchannels" : setting(env.MAIL_PROVIDER);
}

function destinations(env) {
  const targets = WEBHOOK_SETTINGS
    .filter(([, key]) => isPresent(env[key]))
    .map(([type, key]) => ({ type, identity: setting(env[key]) }));
  // A partially configured email target must have a visible failed delivery.
  if (isPresent(env.MAIL_FROM) || isPresent(env.MAIL_TO) || env.MAIL_PROVIDER !== undefined) {
    const provider = mailProvider(env);
    const addressIdentity = [setting(env.MAIL_FROM), emailList(env.MAIL_TO)];
    targets.push({
      type: "email",
      // Preserve queued MailChannels identities; other providers have a distinct
      // namespace so an alarm cannot silently reroute an existing email job.
      identity: provider === "mailchannels" ? addressIdentity : [provider, ...addressIdentity],
    });
  }
  return targets;
}

async function fingerprint(target) {
  const data = new TextEncoder().encode(JSON.stringify([target.type, target.identity]));
  const hash = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

// Only these opaque identities belong in the durable outbox, never webhook URLs or API keys.
export async function notificationTargets(env) {
  return await Promise.all(destinations(env).map(async (target) => ({
    type: target.type,
    fingerprint: await fingerprint(target),
  })));
}

function truncate(value, max) {
  if (value.length <= max) return value;
  let end = max - 1;
  // Avoid splitting a UTF-16 surrogate pair at the truncation boundary.
  if (/[\uD800-\uDBFF]/.test(value[end - 1])) end -= 1;
  return `${value.slice(0, end)}…`;
}

function line(value, max = 512) {
  return truncate(String(value ?? "").replace(/[\u0000-\u001f\u007f]/g, " "), max);
}

function title(event) {
  if (event.kind === "vault.decryption") return "Kanariya protected-document event";
  return event.test === true ? "Kanariya TEST notification" : "Kanariya DETECTION: token accessed";
}

function eventText(event, deliveryId) {
  if (event.kind === "vault.decryption") {
    const outcome = ["decrypted", "failed", "unknown"].includes(event.outcome) ? event.outcome : "unknown";
    return `${title(event)}\nevent ID: ${line(event.id, 128)}\nstatus: ${outcome}`;
  }
  return [
    title(event),
    `event ID: ${line(event.id, 128)}`,
    `delivery ID: ${line(deliveryId, 128)}`,
    `ts: ${line(event.ts, 64)}`,
    `token: ${line(event.token, 256)}`,
    ...(event.name ? [`name: ${line(event.name, 256)}`] : []),
    ...(event.location ? [`location: ${line(event.location, 256)}`] : []),
    `src: ${line(event.src)}`,
    `country: ${line(event.country, 64)}`,
    `asn: ${line(event.asn, 64)}`,
    `ipHash: ${line(event.ipHash, 128)}`,
    `ua: ${line(event.ua, 256)}`,
    `referer: ${line(event.referer)}`,
  ].join("\n");
}

function slackText(value) {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function httpsUrl(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new Error("configuration_error");
  }
  return url;
}

function requestFor(env, target, event, deliveryId) {
  const headers = { "content-type": "application/json" };
  let url;
  let payload;
  if (target.type === "email") {
    const from = setting(env.MAIL_FROM);
    const to = emailList(env.MAIL_TO);
    const provider = mailProvider(env);
    if (!bareEmail(from) || !to.length || to.some((email) => !bareEmail(email)) ||
        /[\u0000-\u001f\u007f]/.test(`${env.MAIL_FROM}${env.MAIL_TO}`) ||
        !["mailchannels", "cloudflare"].includes(provider)) {
      throw new Error("configuration_error");
    }
    const sender = { email: from, name: line(env.MAIL_FROM_NAME || "Kanariya", 256) };
    const subject = event.kind === "vault.decryption" ? "Kanariya protected-document event" : line(`${env.MAIL_SUBJECT_PREFIX || "Kanariya alert"} [${event.test === true ? "TEST" : "DETECTION"}]: ${event.token}`, 256);
    const text = eventText(event, deliveryId);
    if (provider === "cloudflare") {
      if (typeof env.NOTIFY_EMAIL?.send !== "function" || to.length > 50) {
        throw new Error("configuration_error");
      }
      return { provider, message: { from: sender, to, subject, text } };
    }
    const apiKey = setting(env.MAILCHANNELS_API_KEY);
    if (!apiKey || /[\r\n]/.test(apiKey)) throw new Error("configuration_error");
    url = new URL(MAILCHANNELS_URL);
    headers["X-Api-Key"] = apiKey;
    payload = {
      personalizations: [{ to: to.map((email) => ({ email })) }],
      from: sender,
      subject,
      content: [{ type: "text/plain", value: text }],
    };
  } else {
    const key = WEBHOOK_SETTINGS.find(([type]) => type === target.type)?.[1];
    url = httpsUrl(setting(env[key]));
    if (target.type === "slack") {
      payload = {
        // The fallback stays short and excludes attacker-controlled request metadata.
        text: slackText(`${title(event)} — event ID: ${line(event.id, 128)}`),
        mrkdwn: false,
        parse: "none",
        link_names: false,
        unfurl_links: false,
        unfurl_media: false,
        blocks: [{ type: "section", text: { type: "plain_text", text: truncate(eventText(event, deliveryId), 3000), emoji: false } }],
      };
    } else if (target.type === "discord") {
      url.searchParams.set("wait", "true");
      payload = {
        content: truncate(eventText(event, deliveryId), 2000),
        allowed_mentions: { parse: [] },
      };
    } else {
      payload = event.kind === "vault.decryption"
        ? { kind: "vault.decryption", event: { id: event.id, outcome: ["decrypted", "failed", "unknown"].includes(event.outcome) ? event.outcome : "unknown" }, deliveryId }
        : { kind: "kanariya.canary", event, deliveryId };
    }
  }
  return { url: url.toString(), headers, body: JSON.stringify(payload) };
}

function failure(error, retryable = false, httpStatus = null, retryAfterMs = null) {
  return { ok: false, retryable, httpStatus, error, retryAfterMs };
}

async function deliverCloudflareEmail(env, message) {
  let timeout;
  // Handle late resolution/rejection even after the bounded wait has ended.
  // The binding has no abort API, so a timeout leaves acceptance unknown.
  const pending = Promise.resolve().then(() => env.NOTIFY_EMAIL.send(message)).then(
    (response) => typeof response?.messageId === "string" && response.messageId.trim()
      ? { ok: true, retryable: false, httpStatus: null, error: null, retryAfterMs: null }
      : failure("email_response_unknown"),
    (error) => {
      if (["E_RATE_LIMIT_EXCEEDED", "E_DAILY_LIMIT_EXCEEDED"].includes(error?.code)) {
        return failure("email_rate_limit", true);
      }
      if (error?.code === "E_INTERNAL_SERVER_ERROR") return failure("email_provider_unavailable", true);
      if (error?.code === "E_DELIVERY_FAILED") return failure("email_delivery_failed");
      // Do not retain provider messages, addresses or unrecognized error codes.
      return failure("email_provider_error");
    },
  );
  try {
    return await Promise.race([pending, new Promise((resolve) => {
      timeout = setTimeout(() => resolve(failure("email_timeout_unknown")), REQUEST_TIMEOUT_MS);
    })]);
  } finally {
    clearTimeout(timeout);
  }
}

// Validate every configured destination before the vault releases any document.
export async function requireNotificationTargets(env) {
  const targets = await notificationTargets(env);
  if (!targets.length) throw new Error("notification_configuration");
  for (const target of targets) requestFor(env, target, { kind: "vault.decryption", id: "configuration-check", outcome: "unknown" }, "configuration-check");
  return targets;
}

function retryAfter(value) {
  if (!value) return null;
  const trimmed = value.trim();
  let delay;
  if (/^\d+(?:\.\d+)?$/.test(trimmed)) {
    delay = Number(trimmed) * 1000;
  } else if (/^[A-Za-z]{3}, /.test(trimmed)) {
    delay = Date.parse(trimmed) - Date.now();
  } else {
    return null;
  }
  if (!Number.isFinite(delay)) return null;
  return Math.min(MAX_RETRY_AFTER_MS, Math.max(0, delay));
}

export async function deliverNotification(env, target, event, deliveryId) {
  const current = (await notificationTargets(env)).find((item) => item.type === target?.type);
  if (!current || current.fingerprint !== target.fingerprint) {
    return failure("configuration_changed");
  }

  let request;
  try {
    request = requestFor(env, target, event, deliveryId);
  } catch {
    return failure("configuration_error");
  }
  if (request.provider === "cloudflare") return await deliverCloudflareEmail(env, request.message);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(request.url, {
      method: "POST",
      headers: request.headers,
      body: request.body,
      // Workers supports manual/follow; inspect 3xx without forwarding credentials.
      redirect: "manual",
      signal: controller.signal,
    });
    // Release the connection without reading or retaining a provider response body.
    response.body?.cancel().catch(() => {});
    // Provider acceptance does not establish inbox delivery or that a person read the alert.
    if (response.ok) {
      return { ok: true, retryable: false, httpStatus: response.status, error: null, retryAfterMs: null };
    }
    const retryable = response.status === 408 || response.status === 429 ||
      (response.status >= 500 && response.status < 600);
    return failure("http_error", retryable, response.status,
      retryable ? retryAfter(response.headers.get("retry-after")) : null);
  } catch {
    // Exceptions can include secret-bearing URLs; retain only a fixed error code.
    return failure(controller.signal.aborted ? "timeout" : "network_error", true);
  } finally {
    clearTimeout(timeout);
  }
}
