import statusJson from "../../../docs/preview/status.json";
import { buildDocView, isDocKey, type DocKey } from "./docs";
import "./styles.css";
import {
  checkLabel,
  checkTone,
  progressOf,
  screenshotUrl,
  shortSha,
  stepLabel,
  testsSummary,
  themeFrom,
  type Checks,
  type Risk,
  type Screenshot,
  type Status,
  type Step,
  type Theme,
} from "./lib";

const status = statusJson as unknown as Status;
const THEME_KEY = "studge-preview-theme";

/**
 * Creates an element. Text always goes through `textContent`, never
 * innerHTML, so nothing from status.json can become markup.
 */
function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className !== undefined) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function externalLink(href: string, text: string, className = "link"): HTMLAnchorElement {
  const anchor = el("a", className, text);
  anchor.href = href;
  anchor.rel = "noreferrer noopener";
  return anchor;
}

function section(title: string, count?: string): { root: HTMLElement; body: HTMLElement } {
  const root = el("section", "card section");
  const head = el("div", "section-head");
  head.append(el("h2", "section-title", title));
  if (count !== undefined) head.append(el("span", "chip idle", count));
  const body = el("div", "section-body");
  root.append(head, body);
  return { root, body };
}

function chip(text: string, tone: "ok" | "bad" | "idle" | "warn"): HTMLSpanElement {
  return el("span", `chip ${tone}`, text);
}

function buildHero(): HTMLElement {
  const hero = el("header", "hero");

  const top = el("div", "hero-top");
  top.append(el("p", "eyebrow", "Studge Pass · build preview"));

  const themeButton = el("button", "btn theme-toggle");
  themeButton.type = "button";
  const paintToggle = (): void => {
    const current = document.documentElement.dataset.theme === "dark" ? "dark" : "light";
    themeButton.textContent = current === "dark" ? "Light mode" : "Dark mode";
    themeButton.setAttribute(
      "aria-label",
      current === "dark" ? "Switch to light theme" : "Switch to dark theme"
    );
  };
  themeButton.addEventListener("click", () => {
    const current = document.documentElement.dataset.theme === "dark" ? "dark" : "light";
    const next: Theme = current === "dark" ? "light" : "dark";
    localStorage.setItem(THEME_KEY, next);
    document.documentElement.dataset.theme = next;
    paintToggle();
  });
  paintToggle();
  top.append(themeButton);

  hero.append(top);
  hero.append(el("h1", "hero-title", `Phase ${status.phase.id} — ${status.phase.name}`));

  const meta = el("div", "meta");
  const branch = el("span", "chip branch");
  branch.append(el("span", "dot-mini"), document.createTextNode(status.phase.branch));
  meta.append(branch);
  if (status.phase.pr_url !== null) {
    meta.append(externalLink(status.phase.pr_url, "Pull request", "chip link-chip"));
  }
  hero.append(meta);

  const progress = progressOf(status.steps);
  const barWrap = el("div", "progress-wrap");
  const barLabel = el(
    "p",
    "progress-label",
    `${progress.done} of ${progress.total} steps done`
  );
  const bar = el("div", "progress");
  bar.setAttribute("role", "progressbar");
  bar.setAttribute("aria-valuemin", "0");
  bar.setAttribute("aria-valuemax", "100");
  bar.setAttribute("aria-valuenow", String(progress.percent));
  bar.setAttribute("aria-label", "Phase progress");
  const fill = el("div", "progress-fill");
  fill.style.width = `${progress.percent}%`;
  bar.append(fill);
  barWrap.append(barLabel, bar);
  hero.append(barWrap);

  return hero;
}

function stepChip(step: Step): HTMLSpanElement {
  const tone = step.state === "done" ? "ok" : step.state === "doing" ? "warn" : "idle";
  return chip(stepLabel(step.state), tone);
}

function buildSteps(): HTMLElement {
  const done = status.steps.filter((step) => step.state === "done").length;
  const view = section("Steps", `${done}/${status.steps.length}`);
  const list = el("ol", "steps");

  for (const step of status.steps as Step[]) {
    const item = el("li", `step ${step.state}`);
    const marker = el("span", `marker ${step.state}`);
    marker.setAttribute("aria-hidden", "true");
    marker.textContent = step.state === "done" ? "✓" : step.state === "doing" ? "◐" : "○";

    const main = el("div", "step-main");
    const titleRow = el("div", "step-title-row");
    titleRow.append(el("h3", "step-title", `${step.n}. ${step.title}`));
    titleRow.append(stepChip(step));
    main.append(titleRow);
    if (step.summary !== "") main.append(el("p", "step-summary", step.summary));

    const side = el("div", "step-side");
    if (step.commit_sha !== null) {
      const sha = externalLink(
        `https://github.com/lnstudge/Studge-Pass/commit/${step.commit_sha}`,
        shortSha(step.commit_sha),
        "sha"
      );
      side.append(sha);
    }
    item.append(marker, main, side);
    list.append(item);
  }

  view.body.append(list);
  return view.root;
}

function checkCard(label: string, value: string, tone: "ok" | "bad" | "idle"): HTMLElement {
  const card = el("div", `check ${tone}`);
  card.append(el("p", "check-label", label));
  card.append(el("p", "check-value", value));
  return card;
}

function buildChecks(): HTMLElement {
  const checks: Checks = status.checks;
  const view = section("Checks");
  const grid = el("div", "checks-grid");
  grid.append(checkCard("Format (fmt)", checkLabel(checks.fmt), checkTone(checks.fmt)));
  grid.append(checkCard("Clippy", checkLabel(checks.clippy), checkTone(checks.clippy)));
  grid.append(
    checkCard(
      "Tests",
      testsSummary(checks.tests),
      checks.tests.failed !== null && checks.tests.failed > 0 ? "bad" : checks.tests.passed === null ? "idle" : "ok"
    )
  );
  grid.append(checkCard("cargo deny", checkLabel(checks.deny), checkTone(checks.deny)));
  view.body.append(grid);
  view.body.append(el("p", "muted small", `Last run: ${checks.updated_at}`));
  return view.root;
}

function buildCommits(): HTMLElement {
  const view = section("Commits", String(status.commits.length));
  if (status.commits.length === 0) {
    view.body.append(el("p", "empty", "No commits recorded yet for this phase."));
    return view.root;
  }
  const list = el("ol", "commits");
  for (const commit of status.commits) {
    const item = el("li", "commit");
    item.append(externalLink(commit.url, shortSha(commit.sha), "sha"));
    item.append(el("span", "commit-message", commit.message));
    list.append(item);
  }
  view.body.append(list);
  return view.root;
}

function buildScreenshots(lightbox: { open: (shot: Screenshot, trigger: HTMLElement) => void }): HTMLElement {
  const view = section("Screenshots", String(status.screenshots.length));
  if (status.screenshots.length === 0) {
    view.body.append(
      el("p", "empty", "No screenshots yet — this phase has not produced a visual step.")
    );
    return view.root;
  }
  const grid = el("div", "gallery");
  for (const shot of status.screenshots) {
    const url = screenshotUrl(shot.path);
    if (url === null) continue;
    const button = el("button", "shot");
    button.type = "button";
    const img = el("img", "shot-img");
    img.src = url;
    img.alt = shot.caption;
    img.loading = "lazy";
    button.append(img, el("span", "shot-caption", shot.caption));
    button.addEventListener("click", () => {
      lightbox.open(shot, button);
    });
    grid.append(button);
  }
  view.body.append(grid);
  return view.root;
}

async function copyText(text: string, button: HTMLButtonElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    button.textContent = "Copied";
    button.classList.add("copied");
    window.setTimeout(() => {
      button.textContent = "Copy";
      button.classList.remove("copied");
    }, 1400);
  } catch {
    button.textContent = "Press Ctrl+C";
  }
}

function buildTryIt(): HTMLElement {
  const view = section("Try it");
  const list = el("div", "tryit");
  for (const entry of status.try_it) {
    const row = el("div", "try");
    const text = el("div", "try-text");
    text.append(el("p", "try-label", entry.label));
    const code = el("code", "try-command", entry.command_or_url);
    text.append(code);
    const button = el("button", "btn copy", "Copy");
    button.type = "button";
    button.setAttribute("aria-label", `Copy: ${entry.label}`);
    button.addEventListener("click", () => {
      void copyText(entry.command_or_url, button);
    });
    row.append(text, button);
    list.append(row);
  }
  view.body.append(list);
  return view.root;
}

function buildRisks(): HTMLElement {
  const view = section("Open risks", String(status.risks.length));
  if (status.risks.length === 0) {
    view.body.append(el("p", "empty", "No risks recorded for this phase."));
    return view.root;
  }
  const table = el("table", "risks");
  const caption = el("caption", "sr-only", "Risks recorded for this phase");
  table.append(caption);
  const thead = el("thead");
  const headRow = el("tr");
  for (const label of ["Risk", "Severity", "Status"]) {
    const th = el("th", undefined, label);
    th.scope = "col";
    headRow.append(th);
  }
  thead.append(headRow);
  const tbody = el("tbody");
  for (const risk of status.risks as Risk[]) {
    const row = el("tr");
    row.append(el("td", "risk-title", risk.title));
    const severity = el("td");
    severity.append(chip(risk.severity, risk.severity === "critical" || risk.severity === "high" ? "bad" : risk.severity === "medium" ? "warn" : "idle"));
    row.append(severity);
    const state = el("td");
    state.append(chip(risk.status, risk.status === "open" ? "warn" : risk.status === "fixed" ? "ok" : "idle"));
    row.append(state);
    tbody.append(row);
  }
  table.append(thead, tbody);
  view.body.append(table);
  return view.root;
}

function buildLinks(): HTMLElement {
  const view = section("Links");
  const list = el("ul", "links");
  for (const link of status.links) {
    const item = el("li");
    const isExternal = /^https?:\/\//.test(link.url);
    item.append(
      isExternal
        ? externalLink(link.url, link.label)
        : externalLink(link.url, link.label, "link internal")
    );
    list.append(item);
  }
  view.body.append(list);
  return view.root;
}

function createLightbox(): { open: (shot: Screenshot, trigger: HTMLElement) => void } {
  const overlay = el("div", "lightbox");
  overlay.hidden = true;
  overlay.setAttribute("role", "dialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-label", "Screenshot");

  const close = el("button", "btn lightbox-close", "Close");
  close.type = "button";
  const figure = el("figure", "lightbox-figure");
  const img = el("img", "lightbox-img");
  img.alt = "";
  const caption = el("figcaption", "lightbox-caption");
  figure.append(img, caption);
  overlay.append(close, figure);
  document.body.append(overlay);

  let previousFocus: HTMLElement | null = null;

  const closeBox = (): void => {
    overlay.hidden = true;
    img.removeAttribute("src");
    previousFocus?.focus();
    previousFocus = null;
  };

  close.addEventListener("click", closeBox);
  overlay.addEventListener("click", (event) => {
    if (event.target === overlay) closeBox();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !overlay.hidden) closeBox();
  });

  return {
    open(shot: Screenshot, trigger: HTMLElement): void {
      const url = screenshotUrl(shot.path);
      if (url === null) return;
      img.src = url;
      img.alt = shot.caption;
      caption.textContent = shot.caption;
      previousFocus = trigger;
      overlay.hidden = false;
      close.focus();
    },
  };
}

type TabKey = "status" | "docs";

function buildTabs(onSelect: (tab: TabKey) => void): {
  root: HTMLElement;
  buttons: Record<TabKey, HTMLButtonElement>;
} {
  const root = el("div", "tabs");
  root.setAttribute("role", "tablist");
  root.setAttribute("aria-label", "Views");

  const create = (key: TabKey, label: string): HTMLButtonElement => {
    const button = el("button", "tab", label);
    button.type = "button";
    button.id = `tab-${key}`;
    button.setAttribute("role", "tab");
    button.setAttribute("aria-controls", `panel-${key}`);
    button.setAttribute("aria-selected", "false");
    button.tabIndex = -1;
    button.addEventListener("click", () => onSelect(key));
    return button;
  };

  const statusTab = create("status", "Status");
  const docsTab = create("docs", "Docs");
  root.append(statusTab, docsTab);

  root.addEventListener("keydown", (event) => {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    const next = document.activeElement === statusTab ? docsTab : statusTab;
    next.focus();
    event.preventDefault();
  });

  return { root, buttons: { status: statusTab, docs: docsTab } };
}

function buildDocsPanel(): { root: HTMLElement; select: (key: DocKey) => void } {
  const root = el("section", "panel docs-panel");
  root.id = "panel-docs";
  root.setAttribute("role", "tabpanel");
  root.setAttribute("aria-labelledby", "tab-docs");
  root.hidden = true;

  const switcher = el("div", "doc-switch");
  switcher.setAttribute("role", "group");
  switcher.setAttribute("aria-label", "Documents");

  const container = el("div", "doc-container");
  const buttons: HTMLButtonElement[] = [];
  let current: DocKey | null = null;

  const make = (key: DocKey, label: string): HTMLButtonElement => {
    const button = el("button", "btn doc-choice", label);
    button.type = "button";
    button.setAttribute("aria-pressed", "false");
    button.addEventListener("click", () => select(key));
    buttons.push(button);
    return button;
  };

  const specButton = make("spec", "Specification");
  const threatButton = make("threat-model", "Threat model");
  switcher.append(specButton, threatButton);

  const select = (key: DocKey): void => {
    if (current !== key) {
      current = key;
      container.replaceChildren(buildDocView(key, document));
    }
    for (const button of buttons) {
      const active = button === (key === "spec" ? specButton : threatButton);
      button.setAttribute("aria-pressed", active ? "true" : "false");
      button.classList.toggle("active", active);
    }
  };

  root.append(switcher, container);
  return { root, select };
}

function parseHash(hash: string): { tab: TabKey; doc: DocKey } {
  const value = hash.replace(/^#/, "");
  if (value === "docs") return { tab: "docs", doc: "spec" };
  if (value.startsWith("docs/")) {
    const key = value.slice("docs/".length);
    return { tab: "docs", doc: isDocKey(key) ? key : "spec" };
  }
  return { tab: "status", doc: "spec" };
}

function main(): void {
  const stored = localStorage.getItem(THEME_KEY);
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const initial = themeFrom(
    new URLSearchParams(window.location.search),
    stored,
    prefersDark
  );
  document.documentElement.dataset.theme = initial;

  const app = document.getElementById("app");
  if (app === null) return;
  app.replaceChildren();

  const main = el("main", "main");
  main.id = "main";
  const lightbox = createLightbox();

  const statusPanel = el("div", "panel");
  statusPanel.id = "panel-status";
  statusPanel.setAttribute("role", "tabpanel");
  statusPanel.setAttribute("aria-labelledby", "tab-status");
  statusPanel.append(
    buildSteps(),
    buildChecks(),
    buildCommits(),
    buildScreenshots(lightbox),
    buildTryIt(),
    buildRisks(),
    buildLinks()
  );

  const docsPanel = buildDocsPanel();

  let select: (tab: TabKey, doc?: DocKey) => void = () => undefined;
  const tabs = buildTabs((tab) => select(tab));

  select = (tab: TabKey, doc: DocKey = "spec"): void => {
    const isStatus = tab === "status";
    tabs.buttons.status.setAttribute("aria-selected", String(isStatus));
    tabs.buttons.docs.setAttribute("aria-selected", String(!isStatus));
    tabs.buttons.status.tabIndex = isStatus ? 0 : -1;
    tabs.buttons.docs.tabIndex = isStatus ? -1 : 0;
    statusPanel.hidden = !isStatus;
    docsPanel.root.hidden = isStatus;
    if (!isStatus) docsPanel.select(doc);
    const hash = isStatus
      ? ""
      : doc === "threat-model"
        ? "#docs/threat-model"
        : "#docs/spec";
    history.replaceState(null, "", `${location.pathname}${location.search}${hash}`);
  };

  const applyHash = (): void => {
    const parsed = parseHash(location.hash);
    select(parsed.tab, parsed.doc);
  };

  window.addEventListener("hashchange", applyHash);

  main.append(buildHero(), tabs.root, statusPanel, docsPanel.root);

  const footer = el("footer", "footer");
  footer.append(
    el(
      "p",
      "muted small",
      `Generated from docs/preview/status.json · documents from docs/SPEC.md and docs/THREAT_MODEL.md · checks last run ${status.checks.updated_at}`
    )
  );

  app.append(main, footer);
  applyHash();

  // ?scroll=<heading-id> deep-links into a document section (used by the
  // screenshot helper and handy when sharing a link).
  const scrollTarget = new URLSearchParams(location.search).get("scroll");
  if (scrollTarget !== null) {
    window.setTimeout(() => {
      document.getElementById(scrollTarget)?.scrollIntoView({ block: "start" });
    }, 80);
  }
}

main();
