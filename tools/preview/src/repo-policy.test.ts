// Repository policy guards: these tests fail the build if someone weakens a
// rule that AGENTS.md makes non-negotiable. They are cheap to run and catch
// drift that a reviewer might miss in a large diff.
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");
const workflowDir = path.join(repoRoot, ".github", "workflows");

const workflowFiles = readdirSync(workflowDir).filter((file) => file.endsWith(".yml"));
const workflowText = new Map(
  workflowFiles.map((file) => [file, readFileSync(path.join(workflowDir, file), "utf8")])
);

describe("CI workflows", () => {
  it("exist", () => {
    expect(workflowFiles.length).toBeGreaterThanOrEqual(3);
  });

  it("declare read-only default permissions", () => {
    for (const [file, text] of workflowText) {
      expect(text, `${file} must declare a top-level permissions block`).toMatch(
        /^permissions:/m
      );
      expect(text, `${file} must default to contents: read`).toMatch(
        /^permissions:\s*\n\s*contents:\s*read/m
      );
    }
  });

  it("never use pull_request_target", () => {
    for (const [file, text] of workflowText) {
      expect(text, `${file} must not use pull_request_target`).not.toContain(
        "pull_request_target"
      );
    }
  });

  it("pin every action to a full commit SHA", () => {
    for (const [file, text] of workflowText) {
      for (const match of text.matchAll(/uses:\s*([^\s#]+)/g)) {
        const reference = match[1];
        expect(
          reference,
          `${file}: action ${reference} must be pinned to a 40-character commit SHA`
        ).toMatch(/@[0-9a-f]{40}$/);
      }
    }
  });
});

describe("dependency install scripts", () => {
  it("are disabled in .npmrc", () => {
    const npmrc = readFileSync(path.join(repoRoot, ".npmrc"), "utf8");
    expect(npmrc).toMatch(/^ignore-scripts\s*=\s*true$/m);
  });
});

describe("gitignore", () => {
  it("covers build output, dependencies, secrets and vault files", () => {
    const gitignore = readFileSync(path.join(repoRoot, ".gitignore"), "utf8");
    for (const entry of ["target/", "node_modules/", ".env*", "*.studgevault", "*.log"]) {
      expect(gitignore, `missing ignore rule ${entry}`).toContain(entry);
    }
  });
});

describe("preview dev server", () => {
  it("binds to loopback only", () => {
    const config = readFileSync(path.join(here, "..", "vite.config.ts"), "utf8");
    expect(config).toContain('host: "127.0.0.1"');
  });
});

describe("Rust sources", () => {
  const crates = ["core", "core-wasm", "relay", "cli", "test-harness"];

  it("never unwrap, expect or panic outside tests", () => {
    const violations: string[] = [];
    for (const crate of crates) {
      const srcDir = path.join(repoRoot, crate, "src");
      for (const entry of readdirSync(srcDir, { recursive: true, withFileTypes: true })) {
        if (!entry.isFile() || !entry.name.endsWith(".rs")) continue;
        const file = path.join(entry.parentPath ?? srcDir, entry.name);
        const text = readFileSync(file, "utf8");
        // Everything from the first #[cfg(test)] onwards is a test module and
        // may panic freely.
        const testStart = text.indexOf("#[cfg(test)]");
        const production = testStart >= 0 ? text.slice(0, testStart) : text;
        for (const pattern of [/\.unwrap\(\)/, /\.expect\(/, /panic!\(/]) {
          if (pattern.test(production)) {
            violations.push(`${path.relative(repoRoot, file)}: ${pattern}`);
          }
        }
      }
    }
    expect(violations).toEqual([]);
  });

  it("forbid unsafe code in core, relay, cli and the wrappers", () => {
    for (const entry of ["core/src/lib.rs", "relay/src/main.rs", "cli/src/main.rs", "core-wasm/src/lib.rs", "test-harness/src/lib.rs"]) {
      const text = readFileSync(path.join(repoRoot, entry), "utf8");
      expect(text, `${entry} must start with #![forbid(unsafe_code)]`).toMatch(
        /^#!\[forbid\(unsafe_code\)\]/
      );
    }
  });
});
