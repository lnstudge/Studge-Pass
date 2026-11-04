// Regression guard for the dashboard's XSS surface: the page renders data from
// docs/preview/status.json, which lives in the repository and could be edited by
// a malicious pull request. Rendering is therefore only allowed through DOM
// text nodes, never through HTML sinks.
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.resolve(here, "..");

const sourceFiles = readdirSync(here).filter(
  (file) => file.endsWith(".ts") && !file.endsWith(".test.ts")
);

const forbidden: { name: string; pattern: RegExp }[] = [
  { name: "innerHTML assignment", pattern: /\.innerHTML\s*=/ },
  { name: "outerHTML assignment", pattern: /\.outerHTML\s*=/ },
  { name: "insertAdjacentHTML", pattern: /\.insertAdjacentHTML\s*\(/ },
  { name: "document.write", pattern: /document\.write\s*\(/ },
  { name: "eval", pattern: /\beval\s*\(/ },
  { name: "new Function", pattern: /new\s+Function\s*\(/ },
];

describe("static scan of the dashboard source", () => {
  it("finds no DOM XSS sinks", () => {
    const violations: string[] = [];
    for (const file of sourceFiles) {
      const text = readFileSync(path.join(here, file), "utf8");
      for (const rule of forbidden) {
        if (rule.pattern.test(text)) {
          violations.push(`${file}: ${rule.name}`);
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it("index.html has no inline event handlers and no javascript: URLs", () => {
    const html = readFileSync(path.join(packageRoot, "index.html"), "utf8");
    expect(/\son[a-z]+\s*=/i.test(html)).toBe(false);
    expect(/javascript:/i.test(html)).toBe(false);
  });

  it("index.html declares a Content-Security-Policy without unsafe-eval", () => {
    const html = readFileSync(path.join(packageRoot, "index.html"), "utf8");
    expect(html).toContain("Content-Security-Policy");
    expect(html).not.toContain("unsafe-eval");
    expect(html).not.toContain("unsafe-inline' 'self'");
  });
});
