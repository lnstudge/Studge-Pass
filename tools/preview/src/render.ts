// DOM renderer for the Markdown AST. Every node is built with createElement and
// textContent; nothing here can turn document text into markup.
import type { Block, Inline } from "./markdown";

function renderInline(nodes: readonly Inline[], doc: Document): Node[] {
  const out: Node[] = [];
  for (const node of nodes) {
    switch (node.type) {
      case "text":
        out.push(doc.createTextNode(node.value));
        break;
      case "code": {
        const code = doc.createElement("code");
        code.textContent = node.value;
        out.push(code);
        break;
      }
      case "strong": {
        const strong = doc.createElement("strong");
        strong.append(...renderInline(node.children, doc));
        out.push(strong);
        break;
      }
      case "em": {
        const em = doc.createElement("em");
        em.append(...renderInline(node.children, doc));
        out.push(em);
        break;
      }
      case "link": {
        if (node.href === null) {
          out.push(...renderInline(node.children, doc));
          break;
        }
        const anchor = doc.createElement("a");
        anchor.href = node.href;
        anchor.rel = "noreferrer noopener";
        anchor.append(...renderInline(node.children, doc));
        out.push(anchor);
        break;
      }
      case "image": {
        if (node.src === null) {
          out.push(doc.createTextNode(`[image: ${node.alt}]`));
          break;
        }
        const img = doc.createElement("img");
        img.src = node.src;
        img.alt = node.alt;
        img.loading = "lazy";
        img.decoding = "async";
        out.push(img);
        break;
      }
    }
  }
  return out;
}

/** Markdown levels map one step down: the page already owns the h1. */
function headingTag(level: 1 | 2 | 3 | 4): "h2" | "h3" | "h4" | "h5" {
  if (level === 1) return "h2";
  if (level === 2) return "h3";
  if (level === 3) return "h4";
  return "h5";
}

export function renderBlocks(blocks: readonly Block[], doc: Document): DocumentFragment {
  const fragment = doc.createDocumentFragment();

  for (const block of blocks) {
    switch (block.type) {
      case "heading": {
        const heading = doc.createElement(headingTag(block.level));
        heading.id = block.id;
        heading.textContent = block.text;
        fragment.append(heading);
        break;
      }
      case "paragraph": {
        const p = doc.createElement("p");
        p.append(...renderInline(block.children, doc));
        fragment.append(p);
        break;
      }
      case "code": {
        const pre = doc.createElement("pre");
        const code = doc.createElement("code");
        if (block.lang !== "") code.className = `language-${block.lang}`;
        code.textContent = block.value;
        pre.append(code);
        fragment.append(pre);
        break;
      }
      case "list": {
        const list = doc.createElement(block.ordered ? "ol" : "ul");
        for (const item of block.items) {
          const li = doc.createElement("li");
          li.append(...renderInline(item, doc));
          list.append(li);
        }
        fragment.append(list);
        break;
      }
      case "table": {
        const table = doc.createElement("table");
        const thead = doc.createElement("thead");
        const headRow = doc.createElement("tr");
        for (const cell of block.header) {
          const th = doc.createElement("th");
          th.scope = "col";
          th.append(...renderInline(cell, doc));
          headRow.append(th);
        }
        thead.append(headRow);
        const tbody = doc.createElement("tbody");
        for (const row of block.rows) {
          const tr = doc.createElement("tr");
          for (const cell of row) {
            const td = doc.createElement("td");
            td.append(...renderInline(cell, doc));
            tr.append(td);
          }
          tbody.append(tr);
        }
        table.append(thead, tbody);
        const wrap = doc.createElement("div");
        wrap.className = "table-wrap";
        wrap.append(table);
        fragment.append(wrap);
        break;
      }
      case "quote": {
        const quote = doc.createElement("blockquote");
        quote.append(...renderInline(block.children, doc));
        fragment.append(quote);
        break;
      }
      case "hr":
        fragment.append(doc.createElement("hr"));
        break;
    }
  }

  return fragment;
}
