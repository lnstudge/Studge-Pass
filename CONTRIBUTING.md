# Contributing to Studge Pass

Thanks for helping. A few rules keep the project safe and reviewable.

## Licence and sign-off

- Clients and core are **GPL-3.0-or-later**; the relay is **AGPL-3.0-or-later**.
- **DCO sign-off is required and there is no CLA.** Every commit must carry a
  `Signed-off-by:` line — commit with `git commit -s`. By signing off you certify
  the Developer Certificate of Origin (https://developercertificate.org/).

## Workflow

- One branch per phase: `phase-NN-short-name`. Never push to `main`; open a pull
  request and let the maintainer merge it.
- Conventional Commits: `type(scope): summary` (for example
  `feat(core): add hkdf label constants`).
- Keep pull requests small and reviewable. Run the checks below before pushing.

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo deny check
pnpm -r lint && pnpm -r test     # if TypeScript packages changed
```

## Security rules

The rules in [AGENTS.md](AGENTS.md) apply to every contribution: approved crypto
crates only, AEAD everywhere with bound AAD, secrets in zeroizing types, no
`unwrap()`/`expect()`/`panic!` on network, file or user input, no legacy crypto
paths, least-privilege CI. If a change needs a new cryptographic primitive or a
new dependency, ask first in the pull request.

Never commit secrets, `.env` files or real vault data.
