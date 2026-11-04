import threatSource from "../../../docs/THREAT_MODEL.md?raw";
import specSource from "../../../docs/SPEC.md?raw";
import { buildToc, parseMarkdown, type Block, type TocEntry } from "./markdown";
import { renderBlocks } from "./render";

export type DocKey = "spec" | "threat-model";

interface DocDefinition {
  key: DocKey;
  title: string;
  subtitle: string;
  source: string;
}

export const DOCS: Record<DocKey, DocDefinition> = {
  spec: {
    key: "spec",
    title: "Protocol specification (v1)",
    subtitle: "docs/SPEC.md",
    source: specSource,
  },
  "threat-model": {
    key: "threat-model",
    title: "Threat model",
    subtitle: "docs/THREAT_MODEL.md",
    source: threatSource,
  },
};

export function isDocKey(value: string): value is DocKey {
  return value === "spec" || value === "threat-model";
}

const cache = new Map<DocKey, { blocks: Block[]; toc: TocEntry[] }>();

export function loadDoc(key: DocKey): { blocks: Block[]; toc: TocEntry[] } {
  const cached = cache.get(key);
  if (cached !== undefined) return cached;
  const blocks = parseMarkdown(DOCS[key].source);
  const parsed = { blocks, toc: buildToc(blocks) };
  cache.set(key, parsed);
  return parsed;
}

function el<K extends keyof HTMLElementTagNameMap>(
  doc: Document,
  tag: K,
  className?: string,
  text?: string
): HTMLElementTagNameMap[K] {
  const node = doc.createElement(tag);
  if (className !== undefined) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

export function buildDocView(key: DocKey, doc: Document): HTMLElement {
  const definition = DOCS[key];
  const { blocks, toc } = loadDoc(key);

  const layout = el(doc, "div", "doc-layout");

  // Table of contents. A <details> so it can fold away on narrow screens.
  const details = el(doc, "details", "toc");
  // On narrow screens the contents would push the document down two screens.
  details.open = !window.matchMedia("(max-width: 900px)").matches;
  const summary = el(doc, "summary", "toc-summary", "Contents");
  const nav = el(doc, "nav");
  nav.setAttribute("aria-label", `${definition.title} contents`);
  const list = el(doc, "ol", "toc-list");

  for (const entry of toc) {
    const item = el(doc, "li", `toc-item level-${entry.level}`);
    const button = el(doc, "button", "toc-link", entry.text);
    button.type = "button";
    button.addEventListener("click", () => {
      const target = doc.getElementById(entry.id);
      target?.scrollIntoView({ behavior: "smooth", block: "start" });
      target?.focus({ preventScroll: true });
    });
    item.append(button);
    list.append(item);
  }
  nav.append(list);
  details.append(summary, nav);
  layout.append(details);

  // Document body.
  const article = el(doc, "article", "doc-body");
  const head = el(doc, "header", "doc-head");
  head.append(el(doc, "h2", "doc-title", definition.title));
  head.append(el(doc, "p", "doc-subtitle", definition.subtitle));
  article.append(head);
  article.append(renderBlocks(blocks.filter((block) => !(block.type === "heading" && block.level === 1)), doc));
  layout.append(article);

  return layout;
}
