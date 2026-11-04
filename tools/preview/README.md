# Dev-preview dashboard

A single local page that shows where the build stands: the current phase's
checklist, the latest check results, the commits pushed in this phase, a
screenshot gallery, the commands to try, the open risks and the important links.

It reads one file — [`docs/preview/status.json`](../../docs/preview/status.json) —
validated against [`status.schema.json`](status.schema.json) at build time. It
makes **no network requests**: no fonts, no analytics, no third-party anything.

## Commands

| Command | What it does |
| --- | --- |
| `pnpm preview` | Serves the dashboard at <http://localhost:4400> and reloads when `status.json` or screenshots change (polling under WSL). |
| `pnpm preview:update` | Runs `cargo fmt`, `cargo clippy`, `cargo test --all`, `cargo deny check` and `git log`, then writes the results into `status.json`. Add `--skip-checks` or `--skip-git` to run only part of it. |
| `pnpm build` | Validates `status.json` against the schema, then builds the static page into `dist/`. |
| `pnpm shot <url> <out-base>` | Captures `<out-base>-light.png` and `<out-base>-dark.png` with Playwright. |
| `pnpm -r lint` / `pnpm -r test` | Type-check + ESLint, and the Vitest suite. |

From the maintainer's Windows machine, run them through the wrapper, e.g.
`.\x.ps1 "pnpm install && pnpm preview"`.

## Notes

- Playwright's Chromium is installed explicitly, because dependency install
  scripts are disabled (`.npmrc`): `pnpm exec playwright install chromium`.
- The page uses a system font stack (IBM Plex Sans if installed, otherwise the
  platform UI font) so it never fetches a font from the network.
- The strict CSP allows `style-src 'unsafe-inline'` only because Vite's dev
  server injects styles during hot reload; the page itself sets no inline
  styles in markup, and `script-src` stays `'self'` with no `unsafe-eval`.
