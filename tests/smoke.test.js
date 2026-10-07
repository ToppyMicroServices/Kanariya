import { afterEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const temporary = [];
afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
});

function run(base) {
  const directory = mkdtempSync(join(tmpdir(), "kanariya-smoke-transport-"));
  temporary.push(directory);
  const marker = join(directory, "curl-calls");
  // No real network access: record whether the script reaches curl at all.
  writeFileSync(join(directory, "curl"), '#!/bin/sh\nprintf "call\\n" >> "$KANARIYA_TEST_MARKER"\nprintf 200\n', { mode: 0o700 });
  const result = spawnSync("bash", [fileURLToPath(new URL("../scripts/smoke_test.sh", import.meta.url))], {
    encoding: "utf8",
    env: {
      ...process.env, PATH: `${directory}:${process.env.PATH}`, KANARIYA_TEST_MARKER: marker,
      BASE_URL: base, TOKEN: "synthetic-token", ADMIN_KEY: "synthetic-admin", SIGNING_SECRET: "",
    },
  });
  return { result, calls: existsSync(marker) ? readFileSync(marker, "utf8").trim().split("\n").length : 0 };
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
