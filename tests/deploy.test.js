import { afterEach, describe, expect, it } from "vitest";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, readlinkSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("../scripts/wrangler_deploy.sh", import.meta.url));
const temporary = [];
afterEach(() => {
  for (const directory of temporary.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "kanariya deploy-test-"));
  temporary.push(directory);
  const scratch = join(directory, "temporary");
  const gate = join(directory, "gate");
  mkdirSync(scratch);
  mkdirSync(gate);
  const victim = join(directory, "synthetic-target.txt");
  writeFileSync(victim, "untouched synthetic target\n");
  symlinkSync(victim, join(scratch, "kv_namespaces.json"));
  const fake = join(directory, "fake wrangler");
  writeFileSync(fake, String.raw`#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
if (process.argv.slice(2).join(" ") === "deploy") {
  process.exit(process.env.KANARIYA_TEST_FAIL === "deploy" ? 7 : 0);
}
if (process.argv.slice(2).join(" ") !== "kv namespace list --json") process.exit(8);
const scratch = process.env.TMPDIR;
const stdout = fs.fstatSync(1);
const directories = () => fs.readdirSync(scratch).filter(name => name.startsWith("kanariya-deploy."));
let file;
for (const name of directories()) {
  const candidate = path.join(scratch, name, "kv_namespaces.json");
  if (!fs.existsSync(candidate)) continue;
  const stat = fs.statSync(candidate);
  if (stat.dev === stdout.dev && stat.ino === stdout.ino) file = candidate;
}
if (!file) process.exit(9);
if (process.env.KANARIYA_TEST_CONCURRENT === "1") {
  fs.writeFileSync(path.join(process.env.KANARIYA_TEST_GATE, path.basename(process.env.KANARIYA_TEST_LOG) + ".ready"), "ready");
  const start = Date.now();
  while (fs.readdirSync(process.env.KANARIYA_TEST_GATE).filter(name => name.endsWith(".ready")).length < 2) {
    if (Date.now() - start > 5000) process.exit(10);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
  }
}
fs.writeFileSync(process.env.KANARIYA_TEST_LOG, JSON.stringify({
  file, directoryMode: fs.statSync(path.dirname(file)).mode & 0o777,
  fileMode: fs.statSync(file).mode & 0o777, concurrentDirectories: directories(),
}));
if (process.env.KANARIYA_TEST_CONCURRENT === "1") {
  fs.writeFileSync(path.join(process.env.KANARIYA_TEST_GATE, path.basename(process.env.KANARIYA_TEST_LOG) + ".recorded"), "recorded");
  const start = Date.now();
  while (fs.readdirSync(process.env.KANARIYA_TEST_GATE).filter(name => name.endsWith(".recorded")).length < 2) {
    if (Date.now() - start > 5000) process.exit(12);
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
  }
}
if (process.env.KANARIYA_TEST_FAIL === "list") process.exit(11);
process.stdout.write(JSON.stringify([{ title: "KANARI_KV", id: process.env.KANARIYA_TEST_KV_ID }]));
`, { mode: 0o700 });
  return { directory, scratch, gate, victim, fake };
}

function options(state, name = "single", overrides = {}) {
  const toml = join(state.directory, `${name}.toml`);
  writeFileSync(toml, 'kv_namespaces = [{ binding = "KANARI_KV", id = "original-id" }]\n');
  const log = join(state.directory, `${name}.json`);
  return {
    toml, log,
    process: {
      encoding: "utf8", cwd: state.directory,
      env: {
        ...process.env, TMPDIR: state.scratch, WRANGLER_BIN: state.fake, WRANGLER_TOML: toml,
        KV_TITLE: "KANARI_KV", AUTO_UPDATE_TOML: "", KANARIYA_TEST_FAIL: "",
        KANARIYA_TEST_LOG: log, KANARIYA_TEST_KV_ID: `${name}-namespace-id`,
        KANARIYA_TEST_GATE: state.gate, KANARIYA_TEST_CONCURRENT: "", ...overrides,
      },
    },
  };
}

const args = ["-c", 'umask 022; exec bash "$1"', "kanariya-deploy-test", script];
const run = config => spawnSync("bash", args, config.process);

function runConcurrent(config) {
  return new Promise((resolve, reject) => {
    const child = spawn("bash", args, config.process);
    let stdout = "", stderr = "";
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", status => resolve({ status, stdout, stderr }));
  });
}

function expectClean(state) {
  expect(readdirSync(state.scratch)).toEqual(["kv_namespaces.json"]);
  expect(lstatSync(join(state.scratch, "kv_namespaces.json")).isSymbolicLink()).toBe(true);
  expect(readlinkSync(join(state.scratch, "kv_namespaces.json"))).toBe(state.victim);
  expect(readFileSync(state.victim, "utf8")).toBe("untouched synthetic target\n");
}

describe("deploy helper temporary files", () => {
  it("uses private files, leaves an existing synthetic symlink untouched, and cleans up", () => {
    const state = fixture();
    const config = options(state);
    const result = run(config);
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain('"id":"single-namespace-id"');
    expect(readFileSync(config.toml, "utf8")).toContain('id = "original-id"');
    const record = JSON.parse(readFileSync(config.log, "utf8"));
    expect(record.file).not.toBe(join(state.scratch, "kv_namespaces.json"));
    expect(record.directoryMode).toBe(0o700);
    expect(record.fileMode).toBe(0o600);
    expect(existsSync(record.file)).toBe(false);
    expectClean(state);
  });

  it("updates only the selected TOML when AUTO_UPDATE_TOML=1", () => {
    const state = fixture();
    const config = options(state, "update", { AUTO_UPDATE_TOML: "1" });
    const result = run(config);
    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(config.toml, "utf8")).toContain('id = "update-namespace-id"');
    expectClean(state);
  });

  it.each(["deploy", "list"])("cleans up after a fake %s failure", failure => {
    const state = fixture();
    const config = options(state, "failure", { KANARIYA_TEST_FAIL: failure, AUTO_UPDATE_TOML: "1" });
    const result = run(config);
    expect(result.status).not.toBe(0);
    expect(readFileSync(config.toml, "utf8")).toContain('id = "original-id"');
    expectClean(state);
  });

  it("isolates concurrent runs and reads each run's own namespace list", async () => {
    const state = fixture();
    const first = options(state, "first", { KANARIYA_TEST_CONCURRENT: "1", AUTO_UPDATE_TOML: "1" });
    const second = options(state, "second", { KANARIYA_TEST_CONCURRENT: "1", AUTO_UPDATE_TOML: "1" });
    const results = await Promise.all([runConcurrent(first), runConcurrent(second)]);
    for (const result of results) expect(result.status, result.stderr).toBe(0);
    const records = [first, second].map(config => JSON.parse(readFileSync(config.log, "utf8")));
    expect(records[0].file).not.toBe(records[1].file);
    for (const record of records) expect(record.concurrentDirectories).toHaveLength(2);
    expect(readFileSync(first.toml, "utf8")).toContain('id = "first-namespace-id"');
    expect(readFileSync(second.toml, "utf8")).toContain('id = "second-namespace-id"');
    expectClean(state);
  });
});
