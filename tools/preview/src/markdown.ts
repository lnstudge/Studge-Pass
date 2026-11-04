// A deliberately small Markdown parser for the two protocol documents.
//
// It produces an AST and never touches the DOM, so it can be unit-tested and so
// the renderer can build every node with createElement/textContent. Raw HTML in
// the source is never interpreted: only the constructs below are recognised,
// everything else is text.

export type Inline =
  | { type: "text"; value: string }
  | { type: "code"; value: string }
  | { type: "strong"; children: Inline[] }
  | { type: "em"; children: Inline[] }
  | { type: "link"; href: string | null; children: Inline[] }
  | { type: "image"; src: string | null; alt: string };

export type Block =
  | { type: "heading"; level: 1 | 2 | 3 | 4; text: string; id: string }
  | { type: "paragraph"; children: Inline[] }
  | { type: "code"; lang: string; value: string }
  | { type: "list"; ordered: boolean; items: Inline[][] }
  | { type: "table"; header: Inline[][]; rows: Inline[][][] }
  | { type: "quote"; children: Inline[] }
  | { type: "hr" };

const SCHEME = /^[a-z][a-z0-9+.-]*:/i;
const IMAGE_PATH = /^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*\.(?:svg|png|jpe?g|webp)$/i;

/**
 * Allows absolute http(s) links and plain relative paths. Rejects every other
 * scheme (javascript:, data:, file:, vbscript: …) and any relative path that
 * tries to climb out of the site.
 */
export function safeLink(raw: string): string | null {
  const url = raw.trim();
  if (url === "") return null;
  if (SCHEME.test(url)) {
    return /^https?:\/\//i.test(url) ? url : null;
  }
  if (url.startsWith("//")) return null;
  if (url.split("/").includes("..")) return null;
  return url;
}

/**
 * Images may only be local files that end in an image extension. Remote images
 * are refused so a document can never make the page fetch from a third party.
 */
export function safeImage(raw: string): string | null {
  const path = raw.trim().replace(/^\.\//, "");
  if (path === "" || SCHEME.test(path) || path.startsWith("//")) return null;
  if (path.split("/").includes("..")) return null;
  if (!IMAGE_PATH.test(path)) return null;
  return "/" + path;
}

export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, "-")
    .replace(/^-+|-+$/g, "");
}

/** Splits inline Markdown into text, code, emphasis, links and images. */
export function parseInline(text: string): Inline[] {
  const out: Inline[] = [];
  let buffer = "";
  let i = 0;

  const flush = (): void => {
    if (buffer !== "") {
      out.push({ type: "text", value: buffer });
      buffer = "";
    }
  };

  while (i < text.length) {
    const ch = text[i] ?? "";

    if (ch === "`") {
      const end = text.indexOf("`", i + 1);
      if (end > i) {
        flush();
        out.push({ type: "code", value: text.slice(i + 1, end) });
        i = end + 1;
        continue;
      }
    }

    if (ch === "!" && text[i + 1] === "[") {
      const match = /^!\[([^\]]*)\]\(([^)\s]+)\)/.exec(text.slice(i));
      if (match) {
        flush();
        out.push({
          type: "image",
          src: safeImage(match[2] ?? ""),
          alt: match[1] ?? "",
        });
        i += match[0].length;
        continue;
      }
    }

    if (ch === "[") {
      const match = /^\[([^\]]*)\]\(([^)\s]+)\)/.exec(text.slice(i));
      if (match) {
        flush();
        out.push({
          type: "link",
          href: safeLink(match[2] ?? ""),
          children: parseInline(match[1] ?? ""),
        });
        i += match[0].length;
        continue;
      }
    }

    if (ch === "*" && text[i + 1] === "*") {
      const end = text.indexOf("**", i + 2);
      if (end > i) {
        flush();
        out.push({ type: "strong", children: parseInline(text.slice(i + 2, end)) });
        i = end + 2;
        continue;
      }
    }

    if (ch === "*") {
      const end = text.indexOf("*", i + 1);
      if (end > i) {
        flush();
        out.push({ type: "em", children: parseInline(text.slice(i + 1, end)) });
        i = end + 1;
        continue;
      }
    }

    buffer += ch;
    i += 1;
  }

  flush();
  return out;
}

function splitRow(line: string): string[] {
  const trimmed = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  return trimmed.split("|").map((cell) => cell.trim());
}

function isTableSeparator(line: string): boolean {
  return /^\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?$/.test(line.trim());
}

/** Parses the subset of Markdown used by SPEC.md and THREAT_MODEL.md. */
export function parseMarkdown(source: string): Block[] {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const blocks: Block[] = [];
  const usedIds = new Map<string, number>();

  const headingId = (text: string): string => {
    const base = slugify(text) || "section";
    const seen = usedIds.get(base) ?? 0;
    usedIds.set(base, seen + 1);
    return seen === 0 ? base : `${base}-${seen + 1}`;
  };

  let i = 0;
  while (i < lines.length) {
    const line = lines[i] ?? "";

    if (line.trim() === "") {
      i += 1;
      continue;
    }

    // HTML comments are dropped entirely.
    if (line.trimStart().startsWith("<!--")) {
      while (i < lines.length && !(lines[i] ?? "").includes("-->")) i += 1;
      i += 1;
      continue;
    }

    if (line.startsWith("```")) {
      const lang = line.slice(3).trim();
      const body: string[] = [];
      i += 1;
      while (i < lines.length && !(lines[i] ?? "").startsWith("```")) {
        body.push(lines[i] ?? "");
        i += 1;
      }
      i += 1;
      blocks.push({ type: "code", lang, value: body.join("\n") });
      continue;
    }

    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    if (heading) {
      const level = (heading[1] ?? "#").length as 1 | 2 | 3 | 4;
      const text = (heading[2] ?? "").trim();
      blocks.push({ type: "heading", level, text, id: headingId(text) });
      i += 1;
      continue;
    }

    if (/^(-{3,}|\*{3,})$/.test(line.trim())) {
      blocks.push({ type: "hr" });
      i += 1;
      continue;
    }

    if (line.startsWith(">")) {
      const quote: string[] = [];
      while (i < lines.length && (lines[i] ?? "").startsWith(">")) {
        quote.push((lines[i] ?? "").replace(/^>\s?/, ""));
        i += 1;
      }
      blocks.push({ type: "quote", children: parseInline(quote.join(" ")) });
      continue;
    }

    // Table: a header row followed by a separator row.
    if (line.trimStart().startsWith("|") && isTableSeparator(lines[i + 1] ?? "")) {
      const header = splitRow(line).map((cell) => parseInline(cell));
      const rows: Inline[][][] = [];
      i += 2;
      while (i < lines.length && (lines[i] ?? "").trimStart().startsWith("|")) {
        rows.push(splitRow(lines[i] ?? "").map((cell) => parseInline(cell)));
        i += 1;
      }
      blocks.push({ type: "table", header, rows });
      continue;
    }

    if (/^\s*[-*]\s+/.test(line) || /^\s*\d+\.\s+/.test(line)) {
      const ordered = /^\s*\d+\.\s+/.test(line);
      const items: Inline[][] = [];
      const marker = ordered ? /^\s*\d+\.\s+/ : /^\s*[-*]\s+/;
      while (i < lines.length && marker.test(lines[i] ?? "")) {
        let text = (lines[i] ?? "").replace(marker, "").trim();
        i += 1;
        // Continuation lines (indented, not a new marker, not blank) belong to
        // the same item; wrapped bullets are common in prose.
        while (i < lines.length) {
          const cont = lines[i] ?? "";
          if (cont.trim() === "") break;
          if (marker.test(cont)) break;
          if (!/^\s{2,}\S/.test(cont)) break;
          text += " " + cont.trim();
          i += 1;
        }
        items.push(parseInline(text));
      }
      blocks.push({ type: "list", ordered, items });
      continue;
    }

    // Paragraph: consecutive plain lines.
    const paragraph: string[] = [];
    while (i < lines.length) {
      const current = lines[i] ?? "";
      if (
        current.trim() === "" ||
        current.startsWith("```") ||
        /^(#{1,4})\s+/.test(current) ||
        current.startsWith(">") ||
        current.trimStart().startsWith("|") ||
        /^\s*[-*]\s+/.test(current) ||
        /^\s*\d+\.\s+/.test(current) ||
        /^(-{3,}|\*{3,})$/.test(current.trim()) ||
        current.trimStart().startsWith("<!--")
      ) {
        break;
      }
      paragraph.push(current.trim());
      i += 1;
    }
    if (paragraph.length > 0) {
      blocks.push({ type: "paragraph", children: parseInline(paragraph.join(" ")) });
    }
  }

  return blocks;
}

export interface TocEntry {
  level: 2 | 3;
  text: string;
  id: string;
}

/** Table of contents from the level-2 and level-3 headings. */
export function buildToc(blocks: readonly Block[]): TocEntry[] {
  const entries: TocEntry[] = [];
  for (const block of blocks) {
    if (block.type !== "heading") continue;
    if (block.level === 2 || block.level === 3) {
      entries.push({ level: block.level, text: block.text, id: block.id });
    }
  }
  return entries;
}
