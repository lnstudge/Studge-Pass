# Studge Pass

A free, fully open-source password and passkey manager. Every feature is free
forever: no paid tiers, no subscriptions, no feature counts.

> **Status: pre-alpha. Do not store real passwords in it yet.**
> The code is being built in public, phase by phase. Nothing here is ready for
> real secrets.

## Why Studge Pass

1. **Free forever, by charter.** The code cannot be relicensed: contributions
   are under the DCO, with no CLA.
2. **Built so a compromised sync server cannot read or silently change your
   data.** The sync server ("relay") is treated as an attacker: it stores only
   ciphertext, every ciphertext is AEAD-authenticated, vault history is a signed
   hash chain, and there is exactly one cipher suite ("v1") with no legacy or
   downgrade paths. Phase 5 ships an "evil relay" test harness that attacks all
   of this; the claims are only as good as those tests.
3. **A passkey-aware security dashboard** with a phishing-resistance score and a
   "blast radius" view of the accounts that can reset other accounts.
4. **Recovery without the vendor:** 2-of-3 guardians plus emergency access.
5. **Bring-your-own storage:** a hosted relay, a self-hosted relay, or a synced
   folder.

First market: India — low-end Android, Indian languages, and item templates for
Aadhaar, PAN, UPI and netbanking.

## Licence

- Clients and core: **GPL-3.0-or-later** — see [LICENSE](LICENSE).
- The sync server (`relay/`): **AGPL-3.0-or-later** — see [relay/LICENSE](relay/LICENSE).

## Repository layout

| Path | What it is |
| --- | --- |
| `core/` | `studge-core` Rust library: crypto, vault model, op log, sync engine, import/export, health scoring. No direct I/O; I/O arrives through injected traits. |
| `core-wasm/` | WebAssembly bindings of core for the browser extension. |
| `relay/` | `studge-relay` sync server (axum, tokio, sqlx; SQLite by default). |
| `cli/` | `studge` command-line client. |
| `test-harness/` | The evil relay and adversarial integration tests. |
| `desktop/` | Tauri 2 + React + TypeScript desktop app (Phase 7). |
| `extension/` | Manifest V3 browser extension (Phase 8). |
| `android/`, `ios/` | Native apps (Phases 13–14). |
| `docs/` | [SPEC](docs/SPEC.md), [threat model](docs/THREAT_MODEL.md), [progress](docs/PROGRESS.md), [decisions](docs/DECISIONS.md). |
| `tools/preview/` | The local dev-preview dashboard (see below). |

## Building

You need Rust stable (with the `wasm32-unknown-unknown` target for the extension
core) and pnpm.

```sh
cargo build --all
cargo test --all
cargo run -p studge-relay          # then GET http://127.0.0.1:8787/health
cargo run -p studge -- --version
cargo build -p studge-core-wasm --target wasm32-unknown-unknown
```

The JavaScript side is a pnpm workspace:

```sh
pnpm install
pnpm preview        # dev-preview dashboard at http://localhost:4400
```

**Windows note for the maintainer machine:** builds run inside WSL through the
wrapper, e.g. `.\x.ps1 cargo build --all` (see AGENTS.md). Contributors on Linux
and macOS run the commands above directly.

## Contributing

Sign-off is required (`git commit -s`, DCO) and there is no CLA. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Reporting a vulnerability

Please use GitHub private security advisories — see [SECURITY.md](SECURITY.md).
