import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { describe, it, expect } from "vitest";

const readPage = path => readFileSync(new URL(path, import.meta.url), "utf8");
const html = readPage("../public/index.html");
const policyMatch = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"\s*\/>/);
const policy = policyMatch?.[1] || "";
const directives = new Map(policy.split(";").map(value => {
  const [name, ...sources] = value.trim().split(/\s+/);
  return [name, sources];
}));
const contents = tag => [...html.matchAll(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, "g"))].map(match => match[1]);
const script = contents("script")[0];

function connection(base) {
  const source = script.match(/function readConnection\(\) \{[\s\S]*?\n      \}/)?.[0];
  if (!source) throw new Error("The connection validator was not found");
  return runInNewContext(`(${source})()`, {
    URL,
    ui: { adminKey: { value: "synthetic-test-key" }, apiBase: { value: base } },
    revision: 1,
  });
}

describe("static Token Studio CSP", () => {
  it("protects both copies before any executable or styled content", () => {
    expect(readPage("../docs/index.html")).toBe(html);
    expect(policyMatch).not.toBeNull();
    expect(html.match(/http-equiv="Content-Security-Policy"/g)).toHaveLength(1);
    expect(policyMatch.index).toBeLessThan(html.indexOf("<style>"));
    expect(policyMatch.index).toBeLessThan(html.indexOf("<script>"));
    expect(directives.get("default-src")).toEqual(["'none'"]);
    expect(directives.get("base-uri")).toEqual(["'none'"]);
    expect(directives.get("form-action")).toEqual(["'none'"]);
    expect(policy).not.toMatch(/unsafe-inline|unsafe-eval|data:|blob:|\*/);
  });

  it.each(["script", "style"])("allows only the exact %s block", tag => {
    const blocks = contents(tag);
    expect(blocks).toHaveLength(1);
    const hash = createHash("sha256").update(blocks[0]).digest("base64");
    expect(directives.get(`${tag}-src`)).toEqual([`'sha256-${hash}'`]);
    const changedHash = createHash("sha256").update(`${blocks[0]}\n`).digest("base64");
    expect(directives.get(`${tag}-src`)).not.toContain(`'sha256-${changedHash}'`);
  });

  it("does not rely on inline event handlers or style attributes", () => {
    const markup = html.replace(/<(script|style)>[\s\S]*?<\/\1>/g, "");
    expect(markup).not.toMatch(/<[^>]*\s(?:on\w+|style)\s*=/i);
    expect(markup).not.toMatch(/<script\b|<link\b|<iframe\b|<object\b/i);
  });

  it("keeps HTTPS APIs and HTTP loopbacks available without invalid IPv6 source syntax", () => {
    // CSP host sources do not support IPv6 literals. The page's connection
    // validator limits the HTTP scheme allowance to the three loopback hosts.
    expect(directives.get("connect-src")).toEqual(["https:", "http:"]);
    for (const base of [
      "https://kanariya.toppymicros.com",
      "https://custom-api.example:8443",
      "http://localhost:8787",
      "http://127.0.0.1:8787",
      "http://[::1]:8787",
    ]) {
      expect(connection(base).base).toBe(new URL(base).origin);
    }
  });

  it.each([
    "http://api.example",
    "http://localhost.example",
    "http://127.0.0.1.example",
    "http://0.0.0.0:8787",
    "http://192.168.1.5:8787",
    "https://api.example/path",
    "https://api.example?key=synthetic",
    "https://api.example#synthetic",
    "https://synthetic:synthetic@api.example",
  ])("continues to reject unsafe or non-origin API address %s", base => {
    expect(() => connection(base)).toThrow();
  });
});
