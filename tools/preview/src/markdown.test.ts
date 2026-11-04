import { describe, expect, it } from "vitest";
import {
  buildToc,
  parseInline,
  parseMarkdown,
  safeImage,
  safeLink,
  slugify,
} from "./markdown";

describe("safeLink", () => {
  it("allows https and plain relative paths", () => {
    expect(safeLink("https://example.com/x")).toBe("https://example.com/x");
    expect(safeLink("/SPEC.md")).toBe("/SPEC.md");
    expect(safeLink("#section")).toBe("#section");
    expect(safeLink("./docs/SPEC.md")).toBe("./docs/SPEC.md");
  });

  it("rejects other schemes", () => {
    expect(safeLink("javascript:alert(1)")).toBeNull();
    expect(safeLink("data:text/html;base64,AAAA")).toBeNull();
    expect(safeLink("file:///etc/passwd")).toBeNull();
    expect(safeLink("vbscript:msgbox")).toBeNull();
    expect(safeLink("mailto:a@b.c")).toBeNull();
  });

  it("rejects protocol-relative and traversal paths", () => {
    expect(safeLink("//evil.example/x")).toBeNull();
    expect(safeLink("../../secret")).toBeNull();
    expect(safeLink("")).toBeNull();
  });
});

describe("safeImage", () => {
  it("allows local image files and makes them root-relative", () => {
    expect(safeImage("diagrams/key-hierarchy.svg")).toBe("/diagrams/key-hierarchy.svg");
    expect(safeImage("./screenshots/a.png")).toBe("/screenshots/a.png");
  });

  it("rejects remote, traversal and non-image paths", () => {
    expect(safeImage("https://evil.example/x.png")).toBeNull();
    expect(safeImage("//evil.example/x.png")).toBeNull();
    expect(safeImage("../secret.png")).toBeNull();
    expect(safeImage("javascript:alert(1)")).toBeNull();
    expect(safeImage("notes.txt")).toBeNull();
    expect(safeImage("a.png?x=1")).toBeNull();
  });
});

describe("slugify", () => {
  it("builds stable anchors", () => {
    expect(slugify("4.2 The Secret Key")).toBe("4-2-the-secret-key");
    expect(slugify("R-0101 — Metadata to the relay")).toBe("r-0101-metadata-to-the-relay");
    expect(slugify("   ")).toBe("");
  });
});

describe("parseInline", () => {
  it("recognises code, bold, italic, links and images", () => {
    const nodes = parseInline("a `b` **c** *d* [e](/x) ![f](diagrams/g.svg)");
    const types = nodes.map((n) => n.type);
    expect(types).toContain("code");
    expect(types).toContain("strong");
    expect(types).toContain("em");
    expect(types).toContain("link");
    expect(types).toContain("image");
  });

  it("keeps unsafe links as text-only nodes", () => {
    const nodes = parseInline("[click](javascript:alert(1))");
    const link = nodes.find((n) => n.type === "link");
    expect(link).toBeDefined();
    if (link?.type === "link") {
      expect(link.href).toBeNull();
      expect(link.children[0]).toEqual({ type: "text", value: "click" });
    }
  });
});

describe("parseMarkdown", () => {
  const source = [
    "# Title",
    "",
    "A paragraph that",
    "spans two lines.",
    "",
    "## Section",
    "",
    "| a | b |",
    "| --- | --- |",
    "| 1 | 2 |",
    "",
    "```cddl",
    "op = { }",
    "```",
    "",
    "- one",
    "- two",
    "",
    "> quoted",
    "",
    "---",
    "",
    "<!-- hidden -->",
    "tail",
  ].join("\n");

  const blocks = parseMarkdown(source);

  it("parses headings with ids", () => {
    const headings = blocks.filter((b) => b.type === "heading");
    expect(headings).toHaveLength(2);
    if (headings[0]?.type === "heading") {
      expect(headings[0].level).toBe(1);
      expect(headings[0].id).toBe("title");
    }
  });

  it("joins paragraph lines", () => {
    const paragraph = blocks.find((b) => b.type === "paragraph");
    expect(paragraph?.type).toBe("paragraph");
    if (paragraph?.type === "paragraph") {
      expect(paragraph.children).toEqual([
        { type: "text", value: "A paragraph that spans two lines." },
      ]);
    }
  });

  it("parses tables, code fences, lists and quotes", () => {
    expect(blocks.some((b) => b.type === "table")).toBe(true);
    expect(blocks.some((b) => b.type === "code" && b.lang === "cddl")).toBe(true);
    expect(blocks.some((b) => b.type === "list" && b.items.length === 2)).toBe(true);
    expect(blocks.some((b) => b.type === "quote")).toBe(true);
    expect(blocks.some((b) => b.type === "hr")).toBe(true);
  });

  it("drops HTML comments", () => {
    const text = JSON.stringify(blocks);
    expect(text).not.toContain("hidden");
  });

  it("keeps wrapped list items together", () => {
    const parsed = parseMarkdown("- first item\n  continues here\n- second item");
    const list = parsed.find((block) => block.type === "list");
    expect(list).toBeDefined();
    if (list?.type === "list") {
      expect(list.items).toHaveLength(2);
      expect(list.items[0]).toEqual([{ type: "text", value: "first item continues here" }]);
    }
  });

  it("numbers duplicate heading ids", () => {
    const dup = parseMarkdown("## Same\n\n## Same");
    const ids = dup.filter((b) => b.type === "heading").map((h) => (h.type === "heading" ? h.id : ""));
    expect(ids).toEqual(["same", "same-2"]);
  });
});

describe("buildToc", () => {
  it("keeps only level 2 and 3 headings", () => {
    const blocks = parseMarkdown("# T\n\n## A\n\n### B\n\n#### C");
    expect(buildToc(blocks).map((e) => e.text)).toEqual(["A", "B"]);
  });
});
