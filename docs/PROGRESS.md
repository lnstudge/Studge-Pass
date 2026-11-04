# Progress log

One entry per phase, newest last. The Notion Build Log mirrors this file.

## Phase 0 — Repository setup, rules and preview dashboard

- **Status:** In review
- **Branch:** `phase-00-setup` · **Issue:** #6 · **Milestone:** Phase 0
- **Dates:** 2026-11-04 → 2026-11-05

### What changed

- **Repository scaffold:** canonical GPL-3.0-or-later `LICENSE` (35,149 bytes)
  and AGPL-3.0-or-later `relay/LICENSE` (34,523 bytes); `SECURITY.md` (private
  advisories only); `CONTRIBUTING.md` (DCO, no CLA); extended `README.md`
  (pre-alpha warning, build steps); `.gitignore`, `.editorconfig`,
  `rust-toolchain.toml`, `rustfmt.toml`, `deny.toml` (licence allowlist, yanked
  deny, OpenSSL ban); docs skeletons; placeholder READMEs for
  `desktop/`, `extension/`, `android/`, `ios/`.
- **Cargo workspace:** `studge-core` (seven empty modules, `forbid(unsafe_code)`),
  `studge-core-wasm` (`version()` via wasm-bindgen), `studge-relay`
  (`GET /health` on `127.0.0.1:8787` returning `{status, version}`),
  `studge` CLI (`--version` via clap), `studge-test-harness`. `Cargo.lock`
  committed (73 packages).
- **CI:** `ci.yml` (fmt, clippy, test and the wasm build on ubuntu-latest and
  windows-latest; `cargo deny` on ubuntu), `security.yml` (gitleaks on every
  push/PR, weekly `cargo audit`, `pnpm audit --audit-level high`), `codeql.yml`
  (JS/TS and Rust, gated while the repository is private), `dependabot.yml`
  (cargo, npm, github-actions weekly). Every action pinned to a full commit SHA;
  every workflow starts from `permissions: contents: read`.
- **Preview dashboard:** `tools/preview` (Vite 8 + TypeScript, no framework, no
  runtime network), `status.schema.json` validated on build and after every
  update, light/dark themes designed separately, 28 unit/policy tests.
- **Notion Build Log:** page, "Start here" page and six databases under the
  private "Studge Pass" page; IDs in `docs/notion.json`; the founder's task
  message, the full `00-master-setup.md` (verified word for word by SHA-256) and
  the continuation message archived in Prompts; 17 phase rows; one execution-log
  row per step; decisions D-0001…D-0005; risks R-0001…R-0005; test-run rows.
- **GitHub:** labels (12), milestones (17, one per phase), tracking issues
  #6–#22, security findings #23–#25.

### How to try it

From the repository root, through the WSL wrapper:

```powershell
.\x.ps1 cargo build --all
.\x.ps1 cargo test --all
.\x.ps1 cargo run -p studge-relay          # then http://127.0.0.1:8787/health
.\x.ps1 cargo run -p studge -- --version   # prints: studge 0.1.0
.\x.ps1 "pnpm install"
.\x.ps1 "pnpm preview"                     # dashboard at http://localhost:4400
.\x.ps1 "pnpm preview:update"              # refresh checks + commits in status.json
.\x.ps1 "pnpm shot http://127.0.0.1:4400 docs/screenshots/phase-00/name"  # light+dark PNGs
```

Screenshots: `docs/screenshots/phase-00/step-09-preview-{light,dark}.png` and
`step-09-preview-narrow-{light,dark}.png`.

### Test results (2026-11-04, through `.\x.ps1`)

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --all-targets --all-features -- -D warnings` | pass |
| `cargo test --all` | 3 passed, 0 failed, 0 ignored (cli 1, relay 2) |
| `cargo deny check` | advisories ok, bans ok, licenses ok, sources ok |
| `cargo build -p studge-core-wasm --target wasm32-unknown-unknown` | pass |
| `pnpm -r lint` (tsc + eslint) | pass |
| `pnpm -r test` (Vitest) | 28 passed, 0 failed (16 lib, 3 static scan, 9 repo policy) |
| `pnpm build` | pass — 16.65 kB JS, 9.90 kB CSS |
| `pnpm audit` | 1 moderate, dev-only — R-0005 (accepted) |
| GitHub CI on `1d0f2db` | ubuntu-latest and windows-latest green; gitleaks green; CodeQL gated |

### Design self-critique (preview dashboard)

Against the AGENTS.md design bar, honestly:

- **Clarity:** one column, one job per section, one primary action per card
  (Copy). The eyebrow → title → progress → sections hierarchy reads in order.
- **Spacing:** every gap and padding comes from the 8-point scale in CSS custom
  properties; nothing is hard-coded per component.
- **Themes:** light and dark are separate palettes (warm paper with dark teal vs
  deep green-black with a brighter teal), not inversions.
- **Motion:** 180 ms ease-out on hover, progress and the lightbox; all of it is
  disabled under `prefers-reduced-motion: reduce`.
- **Contrast:** body ink on surface is roughly 15:1 in light and 12:1 in dark;
  chips use tinted backgrounds with darker text rather than bare colour.
- **Keyboard and screen readers:** skip link, visible focus rings, real
  `<button>`s, table headers with scope, lightbox closes on Escape and restores
  focus, 44 px minimum touch targets.
- **Weaknesses:** the step summaries are long, which makes the narrow view very
  tall (about 14,000 px at 390 px wide); a future pass could collapse each
  summary behind a disclosure. The gallery thumbnails show a screenshot of the
  dashboard inside the dashboard — an honest artefact of dogfooding. There is no
  dedicated error state if `status.json` ever ships broken, because the build
  validates it first.

### Known gaps and open questions

- **R-0001 / #23:** CodeQL code scanning needs a public repository or GitHub
  Advanced Security. Everything else in the security automation runs.
- `cargo-audit` is not installed locally; the binary runs weekly in CI.
- The preview dashboard's `status.json` is validated, but the screenshots in the
  gallery were captured before the latest commits; a final refresh runs before
  the PR.
- `typescript-eslint` requires TypeScript `< 6.1`, so the preview package pins
  TypeScript 6.0.3 (recorded here rather than in DECISIONS.md because it is a
  tooling compatibility constraint, not a product decision).
- The wrapper prints PowerShell "RemoteException" noise on successful `pnpm`
  commands that write to stderr; it does not affect exit codes.
- No Storybook, design tokens package or product UI yet — that is Phase 6b.

### Open questions for the founder

1. Should the repository be made public? It would enable CodeQL and GitHub
   secret scanning at no cost, and the project is meant to be open source.
2. Phase 1 (spec + threat model) writes `docs/SPEC.md` in full; the current
   headings are placeholders.

## Phase 1 — Protocol specification and threat model

- **Status:** In review
- **Branch:** `phase-01-spec` · **Issue:** #7 · **Milestone:** Phase 1
- **Dates:** 2026-11-05

### What changed

- **docs/SPEC.md** (new, ~8,600 words — roughly 17 printed pages) — eleven
  sections: purpose and goals, terminology, trust model, identities and key
  hierarchy, encryption format, operation log, relay API, health scoring,
  sharing, recovery, and the crypto inventory. Every detail the brief left open
  is written as **PROPOSED** and listed as D-0101…D-0117.
- **docs/THREAT_MODEL.md** — adversaries A1–A8 (assets, attacks, mitigations with
  SPEC links, residual risk), the ETH Zurich 2026 malicious-server classes, the
  DEF CON 33 DOM clickjacking mapping, a risk register (R-0001…R-0115) and the
  Phase 1 design self-attack table.
- **docs/DECISIONS.md** — D-0101…D-0117; D-0115 (a Shamir crate) needs a decision
  before Phase 12.
- **docs/diagrams/** — `key-hierarchy.svg` and `relay-trust-boundary.svg`,
  embedded in SPEC §3.2 and §4.11.
- **tools/preview** — a Docs tab: strict Markdown parser plus DOM renderer (no
  `innerHTML`), table of contents, Status/Docs tabs with hash routing,
  `?scroll=` deep links, 15 new tests (43 total).
- **Notion / GitHub** — both Phase 1 prompts archived word for word
  (SHA-verified), one execution row per step, 16 decisions mirrored, findings
  filed as issues #32–#34.

### How to try it

```powershell
.\x.ps1 "pnpm install && pnpm preview"
# then http://localhost:4400/#docs/spec and http://localhost:4400/#docs/threat-model
```

Or read `docs/SPEC.md` and `docs/THREAT_MODEL.md` directly; the diagrams render
in both files and in the preview.

### Test results (2026-11-04, through `.\x.ps1`)

| Check | Result |
| --- | --- |
| `cargo fmt` / `clippy` / `test --all` / `deny check` | pass; 3 tests; advisories, bans, licenses, sources ok |
| `pnpm -r lint` | pass |
| `pnpm -r test` | 43 passed (16 lib, 15 markdown, 3 static scan, 9 repo policy) |
| Renderer security | `javascript:`, `data:`, `file:` and `mailto:` links rejected; remote images rejected; no HTML sinks (static scan) |

No product code changed in this phase.

### Known gaps and open questions

- Open risks: R-0113 read-only membership (D-0117), R-0114 look-alike field
  names, R-0115 enrolment intent, R-0110 transparency split view, R-0111
  recovery window. Each has an issue or a decision reference.
- 17 decisions need the founder's review; the ten most important are in the PR.
- Shamir crate approval blocks Phase 12 (D-0115).
- The preview server caches its static file list at startup: after adding files
  under `docs/` (screenshots, diagrams), restart `pnpm preview`.
- SPEC is ~17 printed pages against the 8–15 target; the tables and normative
  lists account for the difference. Happy to trim if you prefer.

### Open questions for the founder

1. Approve or change the ten decisions listed in the PR — especially D-0101
   (Secret Key length) and D-0115 (Shamir crate).
2. Should v1 ship sharing as write-or-nothing (D-0117), or wait for signed
   capabilities in Phase 11?

### Follow-ups (outside this phase's scope)

- **CI does not run the preview's TypeScript checks yet.** `ci.yml` covers Rust
  only, so `pnpm -r lint` and `pnpm -r test` ran locally. Add a `preview` job
  (`pnpm install --frozen-lockfile`, lint, test) at the start of Phase 2.
- `tools/preview` still needs a restart after files are added under `docs/`
  (the static file list is cached at startup).
- A Storybook and the design-token package arrive in Phase 6b, per the plan.
