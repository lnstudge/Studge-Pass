# Studge Pass — Bob rules

These rules apply to every Bob session in this repository.
They mirror the most important constraints from `AGENTS.md`; read that file
for the full spec before starting any phase.

## Build commands — always through `.\x.ps1`

Smart App Control on Windows blocks unsigned Rust/Node executables.
Every `cargo`, `pnpm`, `npm`, `npx` and `playwright` command **must** run via:

```
.\x.ps1 cargo build --all
.\x.ps1 cargo test -p studge-relay
.\x.ps1 "pnpm install && pnpm preview"
```

`git` and `gh` run on Windows directly (already signed).
Never run `sudo`; never `apt-get` without providing the exact `wsl -u root` command.

## Security rules (non-negotiable)

1. Never invent cryptography. Only use crates on the AGENTS.md approved list.
   Stop and ask before adding any new crypto crate.
2. Every ciphertext has AEAD + AAD binding suite version, account/vault/item id,
   record type and field name. Decryption failures are hard errors — never silent.
3. Secrets live in `Zeroizing`/`SecretBox`. Never log, print, `Debug`-format,
   serialise into errors, or send secrets or plaintext.
4. `#![forbid(unsafe_code)]` in core, relay and cli.
5. The relay must never receive master password, Secret Key, MUK, auth secret,
   vault keys, item keys, or plaintext URLs.
6. No `unwrap()`, `expect()`, or `panic!` on network/file/user input — tests only.
7. Browser extension: never render fill/save prompts inside page-controlled DOM;
   always take origin from browser's sender, never from page data.

## Git workflow

1. Start each phase: `git switch main`, `git pull`, `git switch -c phase-NN-name`.
2. After every logical step: run fast checks, `git add <specific files>`,
   inspect `git diff --cached` for secrets, `git commit -s -m "type(scope): msg"`.
3. Never push to main. Never force-push. Never rewrite pushed history.
4. Open PR with `gh pr create`; stop and wait for founder review — do not merge.

## Before every commit

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all`
- `cargo deny check`
- If TypeScript changed: `pnpm -r lint` and `pnpm -r test`
- Scan `git diff --cached` for secrets and private data.

## Scope rules

- Do only the phase/task asked for. Anything outside scope → `docs/PROGRESS.md`
  "Follow-ups" section.
- Helper scripts → `.work/` only (gitignored). Use `docs/` for temp docs.
- Stop and ask on any security ambiguity, unapproved crate, or unclear decision.
- Self-attack review required at end of every phase: list ≥ 10 concrete attacks,
  prove each is blocked by a test, or record it in `docs/THREAT_MODEL.md`.

## Key files

| File | Purpose |
|---|---|
| `AGENTS.md` | Full rules — read at the start of every phase |
| `docs/SPEC.md` | Protocol specification |
| `docs/THREAT_MODEL.md` | Risks and mitigations |
| `docs/PROGRESS.md` | Phase-by-phase progress log |
| `docs/DECISIONS.md` | Architectural decisions (D-xxxx) |
| `docs/preview/status.json` | Live dashboard data |
| `.\x.ps1` | WSL command wrapper — use this for all builds |
