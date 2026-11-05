// Pure helpers for the dev-preview dashboard. Everything here is unit-tested;
// the DOM code in main.ts stays deliberately thin.

export type StepState = "done" | "doing" | "next";
export type CheckState = "pass" | "fail" | null;
export type Theme = "light" | "dark";

export interface Step {
  n: number;
  title: string;
  state: StepState;
  summary: string;
  commit_sha: string | null;
}

export interface Tests {
  passed: number | null;
  failed: number | null;
  ignored: number | null;
}

export interface Checks {
  fmt: CheckState;
  clippy: CheckState;
  tests: Tests;
  deny: CheckState;
  updated_at: string;
}

export interface Commit {
  sha: string;
  message: string;
  url: string;
}

export interface Screenshot {
  path: string;
  caption: string;
}

export interface TryIt {
  label: string;
  command_or_url: string;
  expect?: string;
}

export interface Risk {
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  status: "open" | "fixed" | "accepted";
}

export interface Link {
  label: string;
  url: string;
}

export interface Phase {
  id: number;
  name: string;
  branch: string;
  pr_url: string | null;
}

export interface Status {
  phase: Phase;
  steps: Step[];
  checks: Checks;
  commits: Commit[];
  screenshots: Screenshot[];
  try_it: TryIt[];
  risks: Risk[];
  links: Link[];
}

export function progressOf(steps: readonly Step[]): {
  done: number;
  total: number;
  percent: number;
} {
  const total = steps.length;
  const done = steps.filter((step) => step.state === "done").length;
  const percent = total === 0 ? 0 : Math.round((done / total) * 100);
  return { done, total, percent };
}

export function testsSummary(tests: Tests): string {
  if (tests.passed === null && tests.failed === null && tests.ignored === null) {
    return "Not run yet";
  }
  return `${tests.passed ?? 0} passed · ${tests.failed ?? 0} failed · ${
    tests.ignored ?? 0
  } ignored`;
}

export function checkLabel(value: CheckState): string {
  if (value === "pass") return "pass";
  if (value === "fail") return "fail";
  return "not run";
}

export function checkTone(value: CheckState): "ok" | "bad" | "idle" {
  if (value === "pass") return "ok";
  if (value === "fail") return "bad";
  return "idle";
}

export function stepLabel(state: StepState): string {
  if (state === "done") return "Done";
  if (state === "doing") return "In progress";
  return "Next";
}

export function shortSha(sha: string): string {
  return sha.slice(0, 7);
}

/**
 * Maps a status.json screenshot path (relative to docs/) to a URL served by the
 * dashboard. Anything that is not a plain relative path under screenshots/ is
 * rejected, so a tampered status.json cannot point the page at other files or
 * other origins.
 */
export function screenshotUrl(path: string): string | null {
  if (!/^screenshots(?:\/[A-Za-z0-9._-]+)+$/.test(path)) return null;
  if (path.split("/").includes("..")) return null;
  return "/" + path;
}

export function themeFrom(
  query: URLSearchParams,
  stored: string | null,
  prefersDark: boolean
): Theme {
  const fromQuery = query.get("theme");
  if (fromQuery === "light" || fromQuery === "dark") return fromQuery;
  if (stored === "light" || stored === "dark") return stored;
  return prefersDark ? "dark" : "light";
}
