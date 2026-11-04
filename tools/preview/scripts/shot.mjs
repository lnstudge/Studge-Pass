// Screenshot helper: captures the page in light and dark themes.
//
//   pnpm shot http://localhost:4400 docs/screenshots/phase-00/step-09-preview
//   -> docs/screenshots/phase-00/step-09-preview-light.png
//   -> docs/screenshots/phase-00/step-09-preview-dark.png
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const here = path.dirname(fileURLToPath(import.meta.url));
// pnpm runs scripts with cwd = the package directory, so relative paths are
// resolved against the repository root instead.
const repoRoot = path.resolve(here, "..", "..", "..");

const [url, outBase, widthArg, mode] = process.argv.slice(2);

if (!url || !outBase) {
  console.error("usage: pnpm shot <url> <out-basename> [viewport-width] [viewport|full]");
  process.exit(2);
}

const fullPage = mode !== "viewport";

const width = widthArg === undefined ? 1440 : Number(widthArg);
if (!Number.isFinite(width) || width < 320 || width > 5120) {
  console.error(`invalid viewport width: ${widthArg}`);
  process.exit(2);
}

const base = path.isAbsolute(outBase) ? outBase : path.resolve(repoRoot, outBase);
mkdirSync(path.dirname(base), { recursive: true });

for (const theme of ["light", "dark"]) {
  const target = new URL(url);
  target.searchParams.set("theme", theme);

  const browser = await chromium.launch();
  try {
    const page = await browser.newPage({
      viewport: { width, height: 1000 },
      colorScheme: theme,
      deviceScaleFactor: 2,
    });
    await page.goto(target.toString(), { waitUntil: "networkidle" });

    const scrollId = target.searchParams.get("scroll");
    if (scrollId !== null) {
      await page.evaluate((id) => {
        document.getElementById(id)?.scrollIntoView({ block: "start" });
      }, scrollId);
    }
    // Let lazy images and the smooth scroll settle before capturing.
    await page.waitForTimeout(300);

    const file = `${base}-${theme}.png`;
    await page.screenshot({ path: file, fullPage });
    console.log(`wrote ${file}`);
  } finally {
    await browser.close();
  }
}
