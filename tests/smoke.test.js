import { afterEach, describe, expect, it } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import worker from "../src/worker.js";
import { setup, hits } from "./helpers.js";

const python = execFileSync("python3", ["-c", "import sys; print(sys.executable)"], { encoding: "utf8" }).trim();

const temporary = [];
afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function run(base, secrets = {}) {
  const directory = mkdtempSync(join(tmpdir(), "kanariya-smoke-transport-"));
  temporary.push(directory);
  const marker = join(directory, "curl-calls");
  const pythonArgs = join(directory, "python-args");
  const curlArgs = join(directory, "curl-args");
  // No real network access: record whether the script reaches curl at all.
  writeFileSync(join(directory, "curl"), '#!/bin/sh\nprintf "call\\n" >> "$KANARIYA_TEST_MARKER"\nprintf "%s\\n" "$@" >> "$KANARIYA_TEST_CURL_ARGS"\nprintf 200\n', { mode: 0o700 });
  writeFileSync(join(directory, "python3"), '#!/bin/sh\nprintf "%s\\n" "$@" >> "$KANARIYA_TEST_PYTHON_ARGS"\nexec "$KANARIYA_TEST_PYTHON" "$@"\n', { mode: 0o700 });
  const result = spawnSync("bash", [fileURLToPath(new URL("../scripts/smoke_test.sh", import.meta.url))], {
    encoding: "utf8",
    env: {
      ...process.env, PATH: `${directory}:${process.env.PATH}`, KANARIYA_TEST_MARKER: marker,
      KANARIYA_TEST_PYTHON: python, KANARIYA_TEST_PYTHON_ARGS: pythonArgs, KANARIYA_TEST_CURL_ARGS: curlArgs,
      BASE_URL: base, TOKEN: "synthetic-token", ADMIN_KEY: "synthetic-admin", MASTER_SECRET: "", SIGNING_SECRET: "", ...secrets,
    },
  });
  return {
    result, calls: existsSync(marker) ? readFileSync(marker, "utf8").trim().split("\n").length : 0,
    pythonArgs: existsSync(pythonArgs) ? readFileSync(pythonArgs, "utf8") : "",
    curlArgs: existsSync(curlArgs) ? readFileSync(curlArgs, "utf8") : "",
  };
}

describe("smoke script transport", () => {
  it.each(["http://example.test", "http://localhost.example.test", "https://user:secret@example.test"])("rejects %s before sending a token or credential", base => {
    const { result, calls } = run(base);
    expect(result.status).toBe(1);
    expect(calls).toBe(0);
    expect(result.stdout).toBe("");
    expect(result.stderr).toBe("Invalid base URL: use HTTPS, or HTTP on localhost, without credentials.\n");
  });
  it.each(["https://example.test", "http://localhost:8787", "http://127.0.0.1:8787", "http://[::1]:8787"])("preserves %s diagnostics using fake curl", base => {
    const { result, calls } = run(base);
    expect(result.status).toBe(0);
    expect(calls).toBe(2);
  });
});

describe("smoke script secret transport", () => {
  it.each([
    { MASTER_SECRET: "synthetic-master-argv-marker" },
    { SIGNING_SECRET: "synthetic-legacy-argv-marker" },
    { MASTER_SECRET: "synthetic-master-argv-marker", SIGNING_SECRET: "synthetic-legacy-argv-marker" },
  ])("keeps signing secrets out of child argv and preserves signed URLs for %j", async secrets => {
    const { result, calls, pythonArgs, curlArgs } = run("https://example.test", secrets);
    expect(result.status).toBe(0);
    expect(calls).toBe(2);
    expect(pythonArgs).toContain("gen_signed_url.py");
    expect(pythonArgs).not.toContain("--secret");
    expect(pythonArgs).not.toContain("--master-secret");
    for (const value of Object.values(secrets)) {
      expect(`${pythonArgs}${curlArgs}${result.stdout}${result.stderr}`).not.toContain(value);
    }
    const url = curlArgs.split("\n").find(argument => argument.startsWith("https://example.test/canary/"));
    expect(new URL(url).searchParams.get("sig")).toMatch(/^[a-f0-9]{64}$/);
    const state = setup({ ...secrets, REQUIRE_SIGNATURE: "1" });
    const response = await worker.fetch(new Request(url), state.env, { waitUntil() {} });
    expect(response.status).toBe(204);
    expect(hits(state, "synthetic-token")).toHaveLength(1);
  });
});
