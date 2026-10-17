import { createRemoteJWKSet, jwtVerify } from "jose";
import { normalizeContactEmail } from "./contacts.js";
const sets = new Map();

export function accessConfiguration(env) {
  if (!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(env.ACCESS_ISSUER || "") ||
      typeof env.ACCESS_AUDIENCE !== "string" || !env.ACCESS_AUDIENCE || env.ACCESS_AUDIENCE.length > 256 || env.ACCESS_AUDIENCE === "unconfigured") throw new Error("auth_configuration");
}

export function emailReaderConfiguration(env) {
  accessConfiguration(env);
  if (env.EMAIL_READER_ENABLED !== "1" || typeof env.READER_ACCESS_AUDIENCE !== "string" ||
      !env.READER_ACCESS_AUDIENCE || env.READER_ACCESS_AUDIENCE.length > 256 ||
      env.READER_ACCESS_AUDIENCE.trim() !== env.READER_ACCESS_AUDIENCE ||
      env.READER_ACCESS_AUDIENCE === "unconfigured" || env.READER_ACCESS_AUDIENCE === env.ACCESS_AUDIENCE) {
    throw new Error("auth_configuration");
  }
}

async function verifiedPayload(request, env, audience) {
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token || token.length > 16384) throw new Error("unauthenticated");
  let keys = sets.get(env.ACCESS_ISSUER);
  if (!keys) {
    keys = createRemoteJWKSet(new URL(`${env.ACCESS_ISSUER}/cdn-cgi/access/certs`), { timeoutDuration: 5000 });
    if (sets.size >= 8) sets.delete(sets.keys().next().value);
    sets.set(env.ACCESS_ISSUER, keys);
  }
  const { payload } = await jwtVerify(token, keys, {
    issuer: env.ACCESS_ISSUER, audience, algorithms: ["RS256"],
    requiredClaims: ["sub", "exp", "iat"], clockTolerance: 0,
  });
  if (typeof payload.sub !== "string" || !payload.sub || payload.sub.length > 256 ||
      typeof payload.iat !== "number" || payload.iat > Date.now() / 1000 + 30 ||
      typeof payload.exp !== "number" || payload.exp <= payload.iat) throw new Error("unauthenticated");
  return payload;
}

export async function identity(request, env) {
  accessConfiguration(env);
  // Keep the existing administrator and subject-based reader contract.
  return (await verifiedPayload(request, env, env.ACCESS_AUDIENCE)).sub;
}

export async function emailIdentity(request, env) {
  emailReaderConfiguration(env);
  const payload = await verifiedPayload(request, env, env.READER_ACCESS_AUDIENCE);
  // The dedicated Access application must require the One-time PIN login
  // provider. Its application JWT has a signed email, but no guaranteed AMR
  // claim. Unsigned email headers and client identity metadata are ignored.
  if (payload.type !== "app" || !Number.isSafeInteger(payload.iat) || payload.iat <= 0 ||
      !Number.isSafeInteger(payload.exp) || !Number.isSafeInteger(payload.exp * 1000) ||
      Object.hasOwn(payload, "common_name") || Object.hasOwn(payload, "service_token_id")) throw new Error("unauthenticated");
  let email;
  try { email = normalizeContactEmail(payload.email); } catch { throw new Error("unauthenticated"); }
  return { subject: payload.sub, email, expiresAt: payload.exp * 1000 };
}
