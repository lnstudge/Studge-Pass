import { describe, expect, it } from "vitest";
import {
  oplogLayout,
  checkLabel,
  checkTone,
  progressOf,
  screenshotUrl,
  shortSha,
  stepLabel,
  testsSummary,
  themeFrom,
  type Step,
} from "./lib";

const steps: Step[] = [
  { n: 1, title: "one", state: "done", summary: "", commit_sha: null },
  { n: 2, title: "two", state: "done", summary: "", commit_sha: null },
  { n: 3, title: "three", state: "doing", summary: "", commit_sha: null },
  { n: 4, title: "four", state: "next", summary: "", commit_sha: null },
];

describe("progressOf", () => {
  it("counts only done steps", () => {
    expect(progressOf(steps)).toEqual({ done: 2, total: 4, percent: 50 });
  });

  it("handles an empty checklist", () => {
    expect(progressOf([])).toEqual({ done: 0, total: 0, percent: 0 });
  });
});

describe("testsSummary", () => {
  it("says so when nothing has run", () => {
    expect(testsSummary({ passed: null, failed: null, ignored: null })).toBe("Not run yet");
  });

  it("formats counts", () => {
    expect(testsSummary({ passed: 12, failed: 0, ignored: 3 })).toBe(
      "12 passed · 0 failed · 3 ignored"
    );
  });

  it("treats missing values as zero once one count exists", () => {
    expect(testsSummary({ passed: 5, failed: null, ignored: null })).toBe(
      "5 passed · 0 failed · 0 ignored"
    );
  });
});

describe("checkLabel and checkTone", () => {
  it("maps pass, fail and null", () => {
    expect(checkLabel("pass")).toBe("pass");
    expect(checkLabel("fail")).toBe("fail");
    expect(checkLabel(null)).toBe("not run");
    expect(checkTone("pass")).toBe("ok");
    expect(checkTone("fail")).toBe("bad");
    expect(checkTone(null)).toBe("idle");
  });
});

describe("stepLabel", () => {
  it("maps states to human labels", () => {
    expect(stepLabel("done")).toBe("Done");
    expect(stepLabel("doing")).toBe("In progress");
    expect(stepLabel("next")).toBe("Next");
  });
});

describe("screenshotUrl", () => {
  it("accepts a normal relative path", () => {
    expect(screenshotUrl("screenshots/phase-00/step-09-preview-light.png")).toBe(
      "/screenshots/phase-00/step-09-preview-light.png"
    );
  });

  it("rejects path traversal", () => {
    expect(screenshotUrl("screenshots/../../AGENTS.md")).toBeNull();
    expect(screenshotUrl("screenshots/phase-00/../../../secret.png")).toBeNull();
  });

  it("rejects absolute paths and other origins", () => {
    expect(screenshotUrl("/etc/passwd")).toBeNull();
    expect(screenshotUrl("https://evil.example/x.png")).toBeNull();
    expect(screenshotUrl("//evil.example/x.png")).toBeNull();
  });

  it("rejects empty and malformed paths", () => {
    expect(screenshotUrl("")).toBeNull();
    expect(screenshotUrl("screenshots/")).toBeNull();
    expect(screenshotUrl("screenshots/phase-00/bad name.png")).toBeNull();
  });
});

describe("themeFrom", () => {
  const noQuery = new URLSearchParams("");

  it("lets ?theme= win (screenshots pin it)", () => {
    expect(themeFrom(new URLSearchParams("theme=dark"), "light", false)).toBe("dark");
    expect(themeFrom(new URLSearchParams("theme=light"), "dark", true)).toBe("light");
  });

  it("falls back to the stored preference", () => {
    expect(themeFrom(noQuery, "dark", false)).toBe("dark");
  });

  it("falls back to the system preference", () => {
    expect(themeFrom(noQuery, null, true)).toBe("dark");
    expect(themeFrom(noQuery, null, false)).toBe("light");
  });

  it("ignores unknown values", () => {
    expect(themeFrom(new URLSearchParams("theme=blue"), "light", true)).toBe("light");
    expect(themeFrom(noQuery, "blue", false)).toBe("light");
  });
});

describe("shortSha", () => {
  it("keeps seven characters", () => {
    expect(shortSha("13a26e249ccb88d7697648165a22e1059492d185")).toBe("13a26e2");
  });
});

describe("oplogLayout", () => {
  const oplog = {
    vault: "22aa22aa",
    heads: ["bbbbbbbb"],
    nodes: [
      { hash: "aaaaaaaa", kind: "create", lamport: 1, device: "d1d1d1d1", parents: [] },
      { hash: "bbbbbbbb", kind: "update", lamport: 2, device: "d2d2d2d2", parents: ["aaaaaaaa"] },
    ],
  };

  it("places one column per Lamport clock", () => {
    const layout = oplogLayout(oplog, 100, 40);
    const first = layout.nodes.find((entry) => entry.node.hash === "aaaaaaaa");
    const second = layout.nodes.find((entry) => entry.node.hash === "bbbbbbbb");
    expect(first?.x).toBe(28);
    expect(second?.x).toBe(128);
    expect(first?.y).toBe(second?.y);
  });

  it("sizes the canvas to hold every node", () => {
    const layout = oplogLayout(oplog, 100, 40);
    expect(layout.width).toBe(228);
    expect(layout.height).toBe(68);
  });

  it("stacks nodes that share a clock", () => {
    const forked = {
      ...oplog,
      nodes: [
        ...oplog.nodes,
        {
          hash: "cccccccc",
          kind: "update" as const,
          lamport: 2,
          device: "d3d3d3d3",
          parents: ["aaaaaaaa"],
        },
      ],
    };
    const layout = oplogLayout(forked, 100, 40);
    const ys = layout.nodes
      .filter((entry) => entry.node.lamport === 2)
      .map((entry) => entry.y);
    expect(new Set(ys).size).toBe(2);
    expect(layout.height).toBe(108);
  });
});
