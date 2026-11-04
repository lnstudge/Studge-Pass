// Runs the fast checks and the phase commit log, then writes the results into
// docs/preview/status.json. Everything runs in the repository root.
//
//   pnpm preview:update                 # checks + git log
//   pnpm preview:update --skip-checks   # git log only
//   pnpm preview:update --skip-git      # checks only
//
// Cargo runs inside WSL when invoked through .\x.ps1 (see AGENTS.md). Git always
// runs as the Windows git: from WSL that means git.exe via interop, so the
// repository is never touched by Linux git.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateData } from "./validate-status.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..", "..", "..");
const statusPath = path.join(repoRoot, "docs", "preview", "status.json");
const REPO_URL = "https://github.com/lnstudge/Studge-Pass";

const flags = new Set(process.argv.slice(2));
const skipChecks = flags.has("--skip-checks");
const skipGit = flags.has("--skip-git");

function run(command, args) {
  try {
    const stdout = execFileSync(command, args, {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 15 * 60 * 1000,
    });
    return { ok: true, output: stdout };
  } catch (error) {
    const output = `${error.stdout ?? ""}${error.stderr ?? ""}`;
    return { ok: false, output };
  }
}

function tallyTests(output) {
  const totals = { passed: 0, failed: 0, ignored: 0 };
  let seen = false;
  const pattern = /test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored/g;
  for (const match of output.matchAll(pattern)) {
    seen = true;
    totals.passed += Number(match[1]);
    totals.failed += Number(match[2]);
    totals.ignored += Number(match[3]);
  }
  return seen ? totals : null;
}

function collectChecks() {
  const fmt = run("cargo", ["fmt", "--all", "--", "--check"]);
  const clippy = run("cargo", ["clippy", "--all-targets", "--all-features", "--", "-D", "warnings"]);
  const tests = run("cargo", ["test", "--all"]);
  const deny = run("cargo", ["deny", "check"]);

  const counts = tallyTests(tests.output);
  return {
    fmt: fmt.ok ? "pass" : "fail",
    clippy: clippy.ok ? "pass" : "fail",
    tests: counts ?? { passed: null, failed: null, ignored: null },
    deny: deny.ok ? "pass" : "fail",
    updated_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
  };
}

function parseLog(output) {
  return output
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => {
      const [sha, ...rest] = line.split("\t");
      return { sha, message: rest.join(" ") };
    })
    .filter((entry) => entry.sha !== undefined && entry.message !== "");
}

function collectCommits() {
  // Windows git (git.exe) is the supported path from WSL; plain git covers
  // Linux and macOS contributors.
  for (const candidate of ["git.exe", "git"]) {
    const log = run(candidate, [
      "log",
      "--reverse",
      "--format=%H%x09%s",
      "main..HEAD",
    ]);
    if (log.ok) {
      return parseLog(log.output).map((entry) => ({
        sha: entry.sha,
        message: entry.message,
        url: `${REPO_URL}/commit/${entry.sha}`,
      }));
    }
  }
  console.warn("warning: could not read git log (main..HEAD); leaving commits unchanged");
  return null;
}

const data = JSON.parse(readFileSync(statusPath, "utf8"));

if (!skipChecks) {
  console.log("running checks: cargo fmt, clippy, test --all, deny check ...");
  data.checks = collectChecks();
  console.log(
    `checks: fmt=${data.checks.fmt} clippy=${data.checks.clippy} ` +
      `tests=${data.checks.tests.passed}/${data.checks.tests.failed}/${data.checks.tests.ignored} ` +
      `deny=${data.checks.deny}`
  );
}

if (!skipGit) {
  const commits = collectCommits();
  if (commits !== null) {
    data.commits = commits;
    console.log(`commits: ${commits.length} on this branch`);
  }
}

validateData(data, repoRoot);
writeFileSync(statusPath, `${JSON.stringify(data, null, 2)}\n`, "utf8");
console.log(`wrote ${path.relative(repoRoot, statusPath)}`);
