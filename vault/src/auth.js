import { createRemoteJWKSet, jwtVerify } from "jose";
const sets = new Map();

export async function identity(request, env) {
  if (!/^https:\/\/[a-z0-9-]+\.cloudflareaccess\.com$/.test(env.ACCESS_ISSUER || "") ||
      !env.ACCESS_AUDIENCE || env.ACCESS_AUDIENCE === "unconfigured") throw new Error("auth_configuration");
  const token = request.headers.get("cf-access-jwt-assertion");
  if (!token || token.length > 16384) throw new Error("unauthenticated");
  let keys = sets.get(env.ACCESS_ISSUER);
  if (!keys) {
    keys = createRemoteJWKSet(new URL(`${env.ACCESS_ISSUER}/cdn-cgi/access/certs`), { timeoutDuration: 5000 });
    if (sets.size >= 8) sets.delete(sets.keys().next().value);
    sets.set(env.ACCESS_ISSUER, keys);
  }
  const { payload } = await jwtVerify(token, keys, {
    issuer: env.ACCESS_ISSUER, audience: env.ACCESS_AUDIENCE, algorithms: ["RS256"],
    requiredClaims: ["sub", "exp", "iat"], clockTolerance: 0,
  });
  if (typeof payload.sub !== "string" || !payload.sub || payload.sub.length > 256 ||
      typeof payload.iat !== "number" || payload.iat > Date.now() / 1000 + 30 ||
      typeof payload.exp !== "number" || payload.exp <= payload.iat) throw new Error("unauthenticated");
  // Email headers and unsigned identity metadata are deliberately ignored.
  return payload.sub;
}
