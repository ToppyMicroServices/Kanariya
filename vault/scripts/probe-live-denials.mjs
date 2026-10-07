// Run only against the operator's own dummy-only deployment. No credentials,
// real document content, response bodies or redirect query strings are retained.
import { writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { UUID, boundedBody } from "../src/crypto.js";

export function assessDenial(response, bytes, origin) {
  const contentType = response.headers.get("content-type") || "";
  if (/application\/pdf/i.test(contentType) || new TextDecoder().decode(bytes).includes("%PDF-")) return "content_exposed";
  if ([401, 403].includes(response.status)) return "denied";
  if ([302, 303, 307].includes(response.status)) {
    const location = response.headers.get("location");
    if (!location) return "unexpected_redirect";
    const url = new URL(location, origin);
    if (url.protocol === "https:" && !url.username && !url.password &&
        (/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(url.hostname) ||
         (url.origin === origin && url.pathname.startsWith("/cdn-cgi/access/")))) return "login_required";
    return "unexpected_redirect";
  }
  return response.status >= 500 ? "service_unavailable_not_verified" : "unexpected_response";
}

export async function probe(origin, documentId, fetcher = fetch) {
  const parsed = new URL(origin);
  if (parsed.protocol !== "https:" || parsed.origin !== origin || !UUID.test(documentId)) throw new Error("invalid_target");
  const base = `${origin}/v1/documents/${documentId}`;
  const forgery = `${Buffer.from('{"alg":"none"}').toString("base64url")}.${Buffer.from('{"sub":"dummy-forged-user"}').toString("base64url")}.`;
  const cases = [
    { name: "anonymous_open", action: "open" },
    { name: "forged_assertion", action: "open", headers: { "cf-access-jwt-assertion": forgery } },
    { name: "unsigned_email_header", action: "open", headers: { "cf-access-authenticated-user-email": "dummy@example.invalid" } },
    { name: "foreign_origin", action: "open", headers: { origin: "https://untrusted.example.invalid" } },
    { name: "anonymous_owner_status", action: "status", method: "GET" },
    { name: "anonymous_owner_revoke", action: "revoke" },
  ];
  const report = { status: "running_not_verified", origin, documentId, checks: [],
    scope: "Unauthenticated denial probes only; Access interception does not verify the Worker's authenticated grant checks.",
    realDataUsed: false, credentialsUsed: false, authorizedViewingVerified: false, notificationReceiptVerified: false };
  for (const item of cases) {
    try {
      const response = await fetcher(`${base}/${item.action}`, {
        method: item.method || "POST", redirect: "manual", signal: AbortSignal.timeout(15000),
        headers: { origin, "content-type": "application/json", ...item.headers },
        ...(item.method === "GET" ? {} : { body: JSON.stringify(item.action === "open" ? { requestId: crypto.randomUUID() } : {}) }),
      });
      const result = assessDenial(response, await boundedBody(response, 65536), origin);
      report.checks.push({ name: item.name, httpStatus: response.status, result });
    } catch {
      report.checks.push({ name: item.name, result: "request_failed_not_verified" });
    }
  }
  report.status = report.checks.every(c => ["denied", "login_required"].includes(c.result)) ? "denial_probes_passed_only" : "failed";
  return report;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [origin, documentId, reportPath] = process.argv.slice(2);
  try {
    if (!reportPath || process.argv.length !== 5) throw new Error("invalid_arguments");
    // An interrupted probe leaves an explicitly incomplete report.
    await writeFile(reportPath, JSON.stringify({ status: "running_not_verified" }) + "\n", { mode: 0o600 });
    const report = await probe(origin, documentId);
    await writeFile(reportPath, JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
    console.log(JSON.stringify({ status: report.status, checks: report.checks.length }));
    if (report.status !== "denial_probes_passed_only") process.exitCode = 1;
  } catch {
    console.error('{"status":"failed","code":"probe_failed"}'); process.exitCode = 1;
  }
}
