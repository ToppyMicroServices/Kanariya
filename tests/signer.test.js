import { describe, it, expect } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { webcrypto } from "node:crypto";
import worker from "../src/worker.js";
import { setup, hits } from "./helpers.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const script = fileURLToPath(new URL("../scripts/gen_signed_url.py", import.meta.url));

describe("Python signer and Worker interoperability", () => {
  for (const secretName of ["MASTER_SECRET", "SIGNING_SECRET"]) {
    it.each(["invoice_2026", "team's notes! (copy)*", "請求書 & review=1"])(
      `accepts ${secretName} URLs with source %s and rejects tampering`,
      async (src) => {
        const state = setup({
          [secretName]: "interoperability-test-secret",
          REQUIRE_SIGNATURE: "1",
          IP_HMAC_KEY: "interoperability-ip-key",
        });
        const env = state.env;
        const secretFlag = secretName === "MASTER_SECRET" ? "--master-secret" : "--secret";
        const url = execFileSync("python3", [
          script, "--base-url", "https://example.test/canary",
          "--token", "interop-token", "--src", src,
          secretFlag, env[secretName],
        ], { encoding: "utf8" }).trim();
        const tampered = new URL(url);
        tampered.searchParams.set("src", `${src}-changed`);
        await worker.fetch(new Request(tampered), env, { waitUntil() {} });
        expect(hits(state, "interop-token")).toHaveLength(0);

        const response = await worker.fetch(new Request(url), env, { waitUntil() {} });
        expect(response.status).toBe(204);
        const events = hits(state, "interop-token");
        expect(events).toHaveLength(1);
        expect(events[0].src).toBe(src);

      }
    );
  }
});

describe("Python signer base URL validation", () => {
  it.each([
    "https://example.test/canary",
    "https://example.test:8443/canary",
    "http://localhost:8787/canary",
    "http://127.0.0.1:8787/canary",
    "http://[::1]:8787/canary",
  ])("keeps %s interoperable with the Worker", async (base) => {
    const state = setup({ MASTER_SECRET: "https-interoperability-secret", REQUIRE_SIGNATURE: "1" });
    const url = execFileSync("python3", [
      script, "--base-url", base, "--token", "https-interop-token",
      "--master-secret", state.env.MASTER_SECRET,
    ], { encoding: "utf8" }).trim();
    expect(new URL(url).origin).toBe(new URL(base).origin);
    const response = await worker.fetch(new Request(url), state.env, { waitUntil() {} });
    expect(response.status).toBe(204);
    expect(hits(state, "https-interop-token")).toHaveLength(1);
  });

  it.each([
    "http://example.test/canary",
    "http://localhost.example.test/canary",
    "http://127.0.0.1.example.test/canary",
    "http://localhost./canary",
    "http://localhost%2eexample.test/canary",
    "http://example.test@localhost/canary",
    "http://localhost@evil.example/canary",
    "https://user:private-url-secret@example.test/canary",
    "https://@example.test/canary",
    "http://localhost\\@example.test/canary",
    "ftp://example.test/canary",
    "example.test/canary",
    "https:///canary",
    "https://example.test:not-a-port/canary",
    "https://example.test:65536/canary",
    "https://example.test:/canary",
    "https://example.test:１２/canary",
    "https://[::1/canary",
    "https://[::1]extra/canary",
    "https://-invalid.example/canary",
    "https://bad..example/canary",
    "https://exa mple.test/canary",
    "https://example.test\n/canary",
  ])("rejects %s without echoing the URL or secret", (base) => {
    const result = spawnSync("python3", [
      script, "--base-url", base, "--token", "synthetic-token",
      "--master-secret", "synthetic-signing-secret",
    ], { encoding: "utf8" });
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Invalid base URL: use HTTPS, or HTTP on localhost, without credentials.\n");
  });
});
